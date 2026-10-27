/* ====================================================================
 *  injspoof — AF_XDP / XDP fastpath
 *
 *  Implementation strategy
 *  -----------------------
 *  - One UMEM region per process (large contiguous mmap'd buffer).
 *  - One AF_XDP socket per RX queue on the capture interface.
 *  - Each xsk binds with XDP_USE_NEED_WAKEUP + XDP_ZEROCOPY when
 *    supported, else copy-mode.
 *  - A worker thread per queue polls its RX ring; for each descriptor
 *    it computes the frame address inside umem, invokes the
 *    user-supplied on_rx callback, then returns the frame to the
 *    FILL ring.
 *  - The XDP program is loaded via libbpf (the .bpf.o blob is
 *    embedded via objcopy / xxd at build time).
 *  - Hot reload re-populates the BPF maps in place; no socket
 *    teardown.
 *
 *  Build deps
 *  ----------
 *  Link with: -lbpf -lxdp -lelf -lz
 *  Headers:   <bpf/libbpf.h>, <xdp/xsk.h>
 *
 *  Graceful degradation
 *  --------------------
 *  When libbpf is not available (build without BUILD_FASTPATH=1), or
 *  when the runtime kernel/NIC doesn't support AF_XDP, the module
 *  reports FASTPATH_AF_PACKET via fastpath_mode() and acts as a
 *  pure pass-through stub. The rest of the codebase keeps working
 *  with the legacy AF_PACKET path.
 * ==================================================================== */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fastpath.h"
#include "logger.h"
#include "metrics.h"
#include "raw_socket.h"
#include "rcu.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <signal.h>

/* ====================================================================
 *  Build-time gate
 *
 *  When BUILD_FASTPATH is not defined, this file compiles to a thin
 *  stub that always reports AF_PACKET mode. This lets us ship a
 *  single Makefile target that works on systems without libbpf.
 * ==================================================================== */
#ifndef BUILD_FASTPATH

struct fastpath_ctx {
    fastpath_mode_t mode;
};

int fastpath_init(fastpath_ctx_t **out, const interface_t *capture_iface,
                  const source_pool_t *filter, int proto_match,
                  const fastpath_settings_t *fpset,
                  fastpath_rx_fn on_rx, void *rx_ctx)
{
    (void)capture_iface; (void)filter; (void)proto_match; (void)fpset;
    (void)on_rx; (void)rx_ctx;
    fastpath_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->mode = FASTPATH_AF_PACKET;
    LOG_INFO("fastpath: AF_XDP unavailable in this build (rebuild with BUILD_FASTPATH=1), using AF_PACKET");
    *out = c;
    return 0;
}

int  fastpath_reconfigure(fastpath_ctx_t *fp, const source_pool_t *filter, int proto_match)
{ (void)fp; (void)filter; (void)proto_match; return 0; }
fastpath_mode_t fastpath_mode(const fastpath_ctx_t *fp) { return fp ? fp->mode : FASTPATH_AF_PACKET; }
int  fastpath_start(fastpath_ctx_t *fp) { (void)fp; return 0; }
void fastpath_stop(fastpath_ctx_t *fp)  { (void)fp; }
void fastpath_destroy(fastpath_ctx_t *fp) { free(fp); }
int  fastpath_tx(fastpath_ctx_t *fp, uint32_t q, const uint8_t *f, uint32_t l)
{ (void)fp; (void)q; (void)f; (void)l; return -1; }
int  fastpath_tx_batch(fastpath_ctx_t *fp, uint32_t q,
                       const uint8_t *const *frames, const uint32_t *lens, int n)
{ (void)fp; (void)q; (void)frames; (void)lens; (void)n; return -1; }
void fastpath_stats(const fastpath_ctx_t *fp, fastpath_stats_t *out)
{ (void)fp; memset(out, 0, sizeof(*out)); }

#else  /* BUILD_FASTPATH */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <dirent.h>

/* Match the BPF program layout */
#define INJ_MAX_CIDR_BLOCKS  4096
#define INJ_MAX_PORTS        64
#define INJ_MAX_XSK_QUEUES   64

struct inj_bpf_config {
    uint32_t cidr_count;
    uint32_t port_count;
    uint8_t  proto_filter;
    uint8_t  redirect_to_xsk;
    uint16_t _pad;
};

struct inj_cidr_block { uint32_t first_ip; uint32_t last_ip; };

/* UMEM layout */
#define FRAME_SIZE   2048
#define NUM_FRAMES   (4 * 1024)      /* 8 MiB per ring */
#define UMEM_SIZE    ((uint64_t)FRAME_SIZE * NUM_FRAMES)

/* Per-queue worker state */
typedef struct {
    fastpath_ctx_t *fp;             /* back-pointer */
    uint32_t        queue;
    int             fd;             /* xsk socket fd */
    struct xsk_socket   *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    void           *umem_area;
    struct xsk_umem    *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    uint32_t        free_frames[NUM_FRAMES];
    int             free_count;
    pthread_t       tid;
} xsk_queue_t;

struct fastpath_ctx {
    fastpath_mode_t mode;
    fastpath_rx_fn  on_rx;
    void           *rx_ctx;

    int             if_index;
    char            if_name[32];

    struct bpf_object *bpf_obj;
    struct bpf_program *prog;
    int             prog_fd;
    uint32_t        xdp_flags;      /* attach flags actually used (for detach) */
    int             xsks_map_fd;
    int             cidr_map_fd;
    int             ports_map_fd;
    int             config_map_fd;
    int             stats_map_fd;

    int             num_queues;
    xsk_queue_t     queues[INJ_MAX_XSK_QUEUES];

    _Atomic int     running;
};

/* Embedded BPF object - the Makefile turns injspoof.bpf.o into a
 * symbol via `ld -r -b binary` so we can mmap it without a separate
 * file at runtime. The four symbols below come from objcopy. */
extern const unsigned char _binary_injspoof_bpf_o_start[];
extern const unsigned char _binary_injspoof_bpf_o_end[];

static size_t bpf_blob_size(void)
{
    return (size_t)(_binary_injspoof_bpf_o_end - _binary_injspoof_bpf_o_start);
}

/* ====================================================================
 *  CPU affinity helper
 * ==================================================================== */
static void pin_thread_to_cpu(pthread_t tid, int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(tid, sizeof(set), &set);
}

/* ====================================================================
 *  RX-queue detection
 *
 *  Every modern NIC has multiple RX queues and RSS hashes incoming
 *  flows across them. If we only bind an AF_XDP socket on queue 0,
 *  any packet that RSS steers to queue 1..N will be processed by the
 *  XDP program but `bpf_redirect_map(&xsks_map, rx_queue_index, ...)`
 *  has no entry for that queue id, the redirect fails, and the frame
 *  goes up the kernel stack instead of into our umem ring. Userspace
 *  then sees nothing.
 *
 *  We count queues via /sys/class/net/<iface>/queues/rx-* which works
 *  on every distro without dragging in ethtool ioctls. The user can
 *  override via `tuning.fastpath.queues`.
 * ==================================================================== */
static int detect_num_rx_queues(const char *iface)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", iface);
    DIR *d = opendir(path);
    if (!d) return -1;

    int count = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "rx-", 3) == 0) count++;
    }
    closedir(d);
    return count > 0 ? count : -1;
}

/* ====================================================================
 *  AF_XDP suitability probe
 *
 *  AF_XDP looks attractive on paper but breaks badly on a number of
 *  common NIC drivers - in particular VMware vmxnet3 (typical ens160),
 *  virtio-net under most kernels, hyperv-netvsc, and some Intel ixgbe
 *  firmware revisions.  On those drivers the program loads cleanly,
 *  the xsk binds in copy mode, but RX descriptors never actually
 *  appear in the umem ring (kernel-side wakeup/fill semantics are
 *  buggy or the driver doesn't redirect to AF_XDP at all in copy mode).
 *  The user-visible symptom is "everything looks fine in the log but
 *  tcpdump sees frames and injspoof doesn't" - exactly what we hit on
 *  this codebase.
 *
 *  Rather than letting `mode: "auto"` silently land users in that
 *  broken state, peek at the driver name in
 *      /sys/class/net/<iface>/device/driver
 *  and refuse to use AF_XDP on the known-bad set unless the user
 *  explicitly asked for `mode: "af_xdp"`.
 * ==================================================================== */
static int read_iface_driver(const char *iface, char *out, size_t outsz)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", iface);
    ssize_t n = readlink(path, out, outsz - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
    /* readlink result is "../../../bus/.../drivers/<name>" - keep tail */
    char *slash = strrchr(out, '/');
    if (slash) memmove(out, slash + 1, strlen(slash + 1) + 1);
    return 0;
}

static int driver_supports_afxdp_well(const char *driver)
{
    /* Drivers with reliable AF_XDP support (zero-copy where available,
     * copy mode that actually delivers frames otherwise). Anything not
     * in this list is treated as "unknown/probably broken" under
     * `mode: "auto"` and silently degraded to AF_PACKET. The user can
     * still force AF_XDP via `mode: "af_xdp"` if they really want to. */
    static const char *const known_good[] = {
        "i40e", "ice", "ixgbe", "mlx5_core", "mlx4_en",
        "nfp", "bnxt_en", "sfc", "veth",
        NULL,
    };
    for (int i = 0; known_good[i]; i++)
        if (strcmp(driver, known_good[i]) == 0) return 1;
    return 0;
}

/* ====================================================================
 *  BPF maps population
 * ==================================================================== */

static int populate_maps(fastpath_ctx_t *fp, const source_pool_t *flt, int proto_match)
{
    /* CIDR map */
    uint32_t n = (uint32_t)flt->count;
    if (n > INJ_MAX_CIDR_BLOCKS) n = INJ_MAX_CIDR_BLOCKS;
    for (uint32_t i = 0; i < INJ_MAX_CIDR_BLOCKS; i++) {
        struct inj_cidr_block b = { 0 };
        if (i < n) { b.first_ip = flt->subnets[i].first_ip; b.last_ip = flt->subnets[i].last_ip; }
        if (bpf_map_update_elem(fp->cidr_map_fd, &i, &b, BPF_ANY) < 0) {
            LOG_PERROR("fastpath: bpf_map_update_elem(cidr)");
            return -1;
        }
    }

    /* Ports map */
    uint32_t np = (uint32_t)flt->port_count;
    if (np > INJ_MAX_PORTS) np = INJ_MAX_PORTS;
    for (uint32_t i = 0; i < INJ_MAX_PORTS; i++) {
        uint16_t p = (i < np) ? flt->ports[i] : 0;
        if (bpf_map_update_elem(fp->ports_map_fd, &i, &p, BPF_ANY) < 0) {
            LOG_PERROR("fastpath: bpf_map_update_elem(ports)");
            return -1;
        }
    }

    /* Single-entry config */
    struct inj_bpf_config bc = {
        .cidr_count    = n,
        .port_count    = np,
        .proto_filter  = (uint8_t)proto_match,
        .redirect_to_xsk = (uint8_t)(fp->mode == FASTPATH_AF_XDP ? 1 : 0),
    };
    uint32_t k0 = 0;
    if (bpf_map_update_elem(fp->config_map_fd, &k0, &bc, BPF_ANY) < 0) {
        LOG_PERROR("fastpath: bpf_map_update_elem(config)");
        return -1;
    }
    return 0;
}

/* ====================================================================
 *  BPF program load
 * ==================================================================== */

static int load_bpf_program(fastpath_ctx_t *fp)
{
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    fp->bpf_obj = bpf_object__open_mem(_binary_injspoof_bpf_o_start,
                                       bpf_blob_size(), &opts);
    if (!fp->bpf_obj) {
        LOG_ERROR("fastpath: bpf_object__open_mem failed");
        return -1;
    }
    if (bpf_object__load(fp->bpf_obj) < 0) {
        LOG_ERROR("fastpath: bpf_object__load failed");
        bpf_object__close(fp->bpf_obj); fp->bpf_obj = NULL;
        return -1;
    }

    fp->prog = bpf_object__find_program_by_name(fp->bpf_obj, "xdp_inj_filter");
    if (!fp->prog) {
        LOG_ERROR("fastpath: prog xdp_inj_filter not found");
        return -1;
    }
    fp->prog_fd       = bpf_program__fd(fp->prog);
    fp->xsks_map_fd   = bpf_object__find_map_fd_by_name(fp->bpf_obj, "xsks_map");
    fp->cidr_map_fd   = bpf_object__find_map_fd_by_name(fp->bpf_obj, "cidr_blocks_map");
    fp->ports_map_fd  = bpf_object__find_map_fd_by_name(fp->bpf_obj, "ports_map");
    fp->config_map_fd = bpf_object__find_map_fd_by_name(fp->bpf_obj, "config_map");
    fp->stats_map_fd  = bpf_object__find_map_fd_by_name(fp->bpf_obj, "stats_map");

    if (fp->xsks_map_fd < 0 || fp->cidr_map_fd < 0 ||
        fp->ports_map_fd < 0 || fp->config_map_fd < 0 || fp->stats_map_fd < 0) {
        LOG_ERROR("fastpath: BPF map fd lookup failed");
        return -1;
    }

    /* Attach XDP - native mode preferred, fall back to SKB (generic). */
    uint32_t flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (bpf_xdp_attach(fp->if_index, fp->prog_fd, flags, NULL) < 0) {
        LOG_WARN("fastpath: native XDP attach failed (%s); trying generic mode", strerror(errno));
        flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
        if (bpf_xdp_attach(fp->if_index, fp->prog_fd, flags, NULL) < 0) {
            LOG_PERROR("fastpath: XDP attach (generic)");
            return -1;
        }
        LOG_INFO("fastpath: XDP attached in generic (SKB) mode - reduced performance");
    } else {
        LOG_INFO("fastpath: XDP attached in native (driver) mode");
    }
    /* Remember the mode we attached with so detach uses matching flags. */
    fp->xdp_flags = flags & (XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE);
    return 0;
}

/* ====================================================================
 *  AF_XDP socket setup (per RX queue)
 * ==================================================================== */

static int setup_xsk_queue(fastpath_ctx_t *fp, uint32_t qid)
{
    xsk_queue_t *q = &fp->queues[qid];
    q->fp    = fp;
    q->queue = qid;

    /* UMEM region (one per queue for cache locality). */
    q->umem_area = mmap(NULL, UMEM_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (q->umem_area == MAP_FAILED) {
        /* Fallback without HUGETLB */
        q->umem_area = mmap(NULL, UMEM_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (q->umem_area == MAP_FAILED) {
            LOG_PERROR("fastpath: mmap umem");
            return -1;
        }
    }

    struct xsk_umem_config umem_cfg = {
        .fill_size      = NUM_FRAMES,
        .comp_size      = NUM_FRAMES,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,
    };
    if (xsk_umem__create(&q->umem, q->umem_area, UMEM_SIZE,
                         &q->fq, &q->cq, &umem_cfg) != 0) {
        LOG_PERROR("fastpath: xsk_umem__create");
        munmap(q->umem_area, UMEM_SIZE);
        return -1;
    }

    struct xsk_socket_config xsk_cfg = {
        .rx_size      = NUM_FRAMES,
        .tx_size      = NUM_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = 0,
        .bind_flags   = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
    };
    if (xsk_socket__create(&q->xsk, fp->if_name, qid, q->umem,
                           &q->rx, &q->tx, &xsk_cfg) != 0) {
        LOG_WARN("fastpath: zero-copy xsk_socket__create failed on queue %u, trying copy mode", qid);
        xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;
        if (xsk_socket__create(&q->xsk, fp->if_name, qid, q->umem,
                               &q->rx, &q->tx, &xsk_cfg) != 0) {
            LOG_PERROR("fastpath: xsk_socket__create (copy mode)");
            xsk_umem__delete(q->umem);
            munmap(q->umem_area, UMEM_SIZE);
            return -1;
        }
    }
    q->fd = xsk_socket__fd(q->xsk);

    /* Populate fill ring with all frames. */
    uint32_t idx_fq = 0;
    if (xsk_ring_prod__reserve(&q->fq, NUM_FRAMES / 2, &idx_fq) != NUM_FRAMES / 2) {
        LOG_ERROR("fastpath: failed to reserve fill ring");
        return -1;
    }
    for (uint32_t i = 0; i < NUM_FRAMES / 2; i++)
        *xsk_ring_prod__fill_addr(&q->fq, idx_fq + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&q->fq, NUM_FRAMES / 2);

    /* Remaining frames stored on the "free" stack for TX. */
    q->free_count = 0;
    for (uint32_t i = NUM_FRAMES / 2; i < NUM_FRAMES; i++)
        q->free_frames[q->free_count++] = i * FRAME_SIZE;

    /* Register this xsk in the BPF SOCKMAP under its RX queue id. */
    int fd = q->fd;
    if (bpf_map_update_elem(fp->xsks_map_fd, &qid, &fd, BPF_ANY) < 0) {
        LOG_PERROR("fastpath: bpf_map_update_elem(xsks_map)");
        return -1;
    }

    /* Copy-mode AF_XDP chicken-and-egg: the kernel only sets
     * needs_wakeup() on the fill ring AFTER it has consumed at least
     * one descriptor.  Until then, frames received by the driver get
     * stuck waiting for somewhere to land.  Poke the socket once at
     * startup so the kernel knows our fill ring has work for it. */
    (void)!recvfrom(q->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    return 0;
}

/* ====================================================================
 *  Worker thread
 * ==================================================================== */

#define RX_BATCH 64

static void *worker_main(void *arg)
{
    xsk_queue_t   *q  = arg;
    fastpath_ctx_t *fp = q->fp;

    char tname[16];
    snprintf(tname, sizeof(tname), "xsk-q%u", q->queue);
    pthread_setname_np(pthread_self(), tname);
    pin_thread_to_cpu(pthread_self(), (int)q->queue);

    struct pollfd pfd = { .fd = q->fd, .events = POLLIN };
    int rcu_id = rcu_register();

    while (atomic_load_explicit(&fp->running, memory_order_acquire)) {
        rcu_quiescent(rcu_id);
        uint32_t idx_rx = 0;
        unsigned rcvd = xsk_ring_cons__peek(&q->rx, RX_BATCH, &idx_rx);
        if (!rcvd) {
            /* Wake the kernel.  In zero-copy mode the kernel sets
             * needs_wakeup() only after it has drained the fill ring
             * once; in copy mode the bit is sometimes never set at
             * all (driver/kernel dependent), and skipping the wakeup
             * causes the RX ring to stay perpetually empty.  Cheap
             * to call unconditionally — it's a syscall with len=0. */
            (void)!recvfrom(q->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            poll(&pfd, 1, 200);
            continue;
        }
        METRIC_INC(&g_metrics.recvmmsg_calls);

        uint32_t idx_fq = 0;
        unsigned ret = xsk_ring_prod__reserve(&q->fq, rcvd, &idx_fq);
        unsigned fq_spins = 0;
        while (ret != rcvd) {
            if (xsk_ring_prod__needs_wakeup(&q->fq))
                (void)!recvfrom(q->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            /* F10: after a few quick retries, yield (poll) rather than
             * busy-spinning so a transiently-full FILL ring cannot pin the
             * CPU at 100%. */
            if (++fq_spins >= 16) {
                struct pollfd p = { .fd = q->fd, .events = POLLIN };
                poll(&p, 1, 1);
                if (!atomic_load_explicit(&fp->running, memory_order_acquire))
                    return NULL;
            }
            ret = xsk_ring_prod__reserve(&q->fq, rcvd, &idx_fq);
        }

        for (unsigned i = 0; i < rcvd; i++) {
            const struct xdp_desc *d =
                xsk_ring_cons__rx_desc(&q->rx, idx_rx + i);
            uint64_t addr = d->addr;
            uint32_t len  = d->len;
            const uint8_t *frame = xsk_umem__get_data(q->umem_area, addr);

            METRIC_INC(&g_metrics.pkts_in);
            METRIC_ADD(&g_metrics.bytes_in, (uint64_t)len);

            if (fp->on_rx) fp->on_rx(frame, len, q->queue, fp->rx_ctx);

            /* Recycle the frame back to fill ring. */
            *xsk_ring_prod__fill_addr(&q->fq, idx_fq + i) = addr;
        }
        xsk_ring_prod__submit(&q->fq, rcvd);
        xsk_ring_cons__release(&q->rx, rcvd);
    }
    return NULL;
}

/* ====================================================================
 *  TX
 * ==================================================================== */

int fastpath_tx(fastpath_ctx_t *fp, uint32_t qid,
                const uint8_t *frame, uint32_t len)
{
    if (fp->mode != FASTPATH_AF_XDP) return -1;
    if (qid >= (uint32_t)fp->num_queues) qid = 0;
    xsk_queue_t *q = &fp->queues[qid];

    if (q->free_count == 0) {
        /* Drain completion ring to refill free list. */
        uint32_t idx_cq = 0;
        unsigned freed = xsk_ring_cons__peek(&q->cq, NUM_FRAMES, &idx_cq);
        for (unsigned i = 0; i < freed && q->free_count < NUM_FRAMES; i++) {
            q->free_frames[q->free_count++] =
                *xsk_ring_cons__comp_addr(&q->cq, idx_cq + i);
        }
        xsk_ring_cons__release(&q->cq, freed);
        if (q->free_count == 0) return -1;
    }

    uint64_t addr = q->free_frames[--q->free_count];
    memcpy(xsk_umem__get_data(q->umem_area, addr), frame, len);

    uint32_t idx_tx = 0;
    if (xsk_ring_prod__reserve(&q->tx, 1, &idx_tx) != 1) {
        q->free_frames[q->free_count++] = addr;
        return -1;
    }
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&q->tx, idx_tx);
    d->addr = addr;
    d->len  = len;
    xsk_ring_prod__submit(&q->tx, 1);
    if (xsk_ring_prod__needs_wakeup(&q->tx))
        sendto(q->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    METRIC_INC(&g_metrics.pkts_out);
    METRIC_ADD(&g_metrics.bytes_out, (uint64_t)len);
    return (int)len;
}

int fastpath_tx_batch(fastpath_ctx_t *fp, uint32_t qid,
                      const uint8_t *const *frames, const uint32_t *lens, int n)
{
    if (fp->mode != FASTPATH_AF_XDP) return -1;
    if (qid >= (uint32_t)fp->num_queues) qid = 0;
    xsk_queue_t *q = &fp->queues[qid];

    /* Drain completion ring */
    uint32_t idx_cq = 0;
    unsigned freed = xsk_ring_cons__peek(&q->cq, NUM_FRAMES, &idx_cq);
    for (unsigned i = 0; i < freed && q->free_count < NUM_FRAMES; i++) {
        q->free_frames[q->free_count++] =
            *xsk_ring_cons__comp_addr(&q->cq, idx_cq + i);
    }
    xsk_ring_cons__release(&q->cq, freed);

    if (q->free_count < n) return -1;

    uint32_t idx_tx = 0;
    if ((int)xsk_ring_prod__reserve(&q->tx, (unsigned)n, &idx_tx) != (int)n) return -1;

    for (int i = 0; i < n; i++) {
        uint64_t addr = q->free_frames[--q->free_count];
        memcpy(xsk_umem__get_data(q->umem_area, addr), frames[i], lens[i]);
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&q->tx, idx_tx + i);
        d->addr = addr;
        d->len  = lens[i];
        METRIC_ADD(&g_metrics.bytes_out, (uint64_t)lens[i]);
    }
    xsk_ring_prod__submit(&q->tx, (unsigned)n);
    METRIC_ADD(&g_metrics.pkts_out, (uint64_t)n);
    METRIC_INC(&g_metrics.sendmmsg_calls);

    if (xsk_ring_prod__needs_wakeup(&q->tx))
        sendto(q->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    return n;
}

/* ====================================================================
 *  Lifecycle
 * ==================================================================== */

int fastpath_init(fastpath_ctx_t **out, const interface_t *capture_iface,
                  const source_pool_t *filter, int proto_match,
                  const fastpath_settings_t *fpset,
                  fastpath_rx_fn on_rx, void *rx_ctx)
{
    fastpath_ctx_t *fp = calloc(1, sizeof(*fp));
    if (!fp) return -1;
    fp->on_rx   = on_rx;
    fp->rx_ctx  = rx_ctx;
    fp->mode    = FASTPATH_AF_XDP;
    fp->if_index = capture_iface->incoming_index;
    snprintf(fp->if_name, sizeof(fp->if_name), "%s", capture_iface->incoming_name);

    /* Mode decision.
     *
     *   "af_packet" -> user explicitly opted out; never load XDP.
     *   "af_xdp"    -> user explicitly opted in; try, fail loudly.
     *   "auto"      -> probe the driver. Use AF_XDP only on a curated
     *                  allow-list of drivers known to handle it well;
     *                  on virtio-net / vmxnet3 / hyperv-netvsc the
     *                  program loads but RX silently doesn't deliver,
     *                  so we degrade to AF_PACKET instead of leaving
     *                  the user in a "looks fine in logs, no traffic
     *                  in metrics" broken state.
     */
    int want_xdp = 1;
    if (!strcasecmp(fpset->mode, "af_packet")) {
        want_xdp = 0;
        LOG_INFO("fastpath: mode=af_packet (user override), skipping AF_XDP");
    } else if (!strcasecmp(fpset->mode, "af_xdp")) {
        want_xdp = 1;
        LOG_INFO("fastpath: mode=af_xdp (user override), forcing AF_XDP");
    } else {
        /* auto */
        char drv[64] = { 0 };
        if (read_iface_driver(fp->if_name, drv, sizeof(drv)) == 0) {
            if (driver_supports_afxdp_well(drv)) {
                LOG_INFO("fastpath: mode=auto, driver=%s -> AF_XDP", drv);
                want_xdp = 1;
            } else {
                LOG_INFO("fastpath: mode=auto, driver=%s has poor AF_XDP support, using AF_PACKET "
                         "(set tuning.fastpath.mode=\"af_xdp\" to override)", drv);
                want_xdp = 0;
            }
        } else {
            LOG_WARN("fastpath: mode=auto, could not read driver for %s, defaulting to AF_PACKET",
                     fp->if_name);
            want_xdp = 0;
        }
    }

    if (!want_xdp) {
        fp->mode = FASTPATH_AF_PACKET;
        *out = fp;
        return 0;
    }

    if (load_bpf_program(fp) < 0) {
        LOG_WARN("fastpath: falling back to AF_PACKET");
        free(fp);
        fp = calloc(1, sizeof(*fp));
        if (!fp) return -1;
        fp->mode = FASTPATH_AF_PACKET;
        *out = fp;
        return 0;
    }

    /* Decide how many RX queues to bind. Honour the user override
     * (tuning.fastpath.queues) if set, otherwise probe sysfs. The
     * single biggest "no packets in AF_XDP mode" footgun is binding
     * only queue 0 while the NIC RSS-hashes flows across all queues,
     * which makes most inbound traffic miss our xsks_map entry. */
    int detected = detect_num_rx_queues(fp->if_name);
    if (fpset->queues > 0) {
        fp->num_queues = fpset->queues;
        if (detected > 0 && fp->num_queues > detected) {
            LOG_WARN("fastpath: configured queues=%d exceeds detected %d on %s, clamping",
                     fp->num_queues, detected, fp->if_name);
            fp->num_queues = detected;
        }
    } else if (detected > 0) {
        fp->num_queues = detected;
    } else {
        LOG_WARN("fastpath: could not detect RX queue count for %s, defaulting to 1 "
                 "(if traffic does not reach AF_XDP, set tuning.fastpath.queues "
                 "to the NIC's actual queue count, e.g. `ethtool -l %s`)",
                 fp->if_name, fp->if_name);
        fp->num_queues = 1;
    }
    if (fp->num_queues > INJ_MAX_XSK_QUEUES) {
        LOG_WARN("fastpath: %d queues > INJ_MAX_XSK_QUEUES, clamping", fp->num_queues);
        fp->num_queues = INJ_MAX_XSK_QUEUES;
    }
    LOG_INFO("fastpath: binding %d AF_XDP socket(s) (one per RX queue on %s)",
             fp->num_queues, fp->if_name);

    for (int q = 0; q < fp->num_queues; q++) {
        if (setup_xsk_queue(fp, (uint32_t)q) < 0) {
            LOG_ERROR("fastpath: queue %d setup failed", q);
            /* Clean up partially constructed queues */
            for (int j = 0; j < q; j++) {
                xsk_socket__delete(fp->queues[j].xsk);
                xsk_umem__delete(fp->queues[j].umem);
                munmap(fp->queues[j].umem_area, UMEM_SIZE);
            }
            bpf_xdp_detach(fp->if_index, fp->xdp_flags, NULL);
            bpf_object__close(fp->bpf_obj);
            free(fp);
            return -1;
        }
    }

    if (populate_maps(fp, filter, proto_match) < 0) {
        LOG_ERROR("fastpath: failed to populate BPF maps");
        fastpath_destroy(fp);
        return -1;
    }

    LOG_INFO("fastpath: AF_XDP initialised, %d queue(s) on %s", fp->num_queues, fp->if_name);
    *out = fp;
    return 0;
}

int fastpath_reconfigure(fastpath_ctx_t *fp,
                         const source_pool_t *filter, int proto_match)
{
    if (!fp || fp->mode != FASTPATH_AF_XDP) return 0;
    return populate_maps(fp, filter, proto_match);
}

fastpath_mode_t fastpath_mode(const fastpath_ctx_t *fp)
{
    return fp ? fp->mode : FASTPATH_AF_PACKET;
}

int fastpath_start(fastpath_ctx_t *fp)
{
    if (!fp || fp->mode != FASTPATH_AF_XDP) return 0;
    atomic_store(&fp->running, 1);
    for (int q = 0; q < fp->num_queues; q++) {
        if (pthread_create(&fp->queues[q].tid, NULL,
                           worker_main, &fp->queues[q]) != 0) {
            LOG_PERROR("fastpath: pthread_create");
            fastpath_stop(fp);
            return -1;
        }
    }
    LOG_INFO("fastpath: %d worker(s) running", fp->num_queues);
    return 0;
}

void fastpath_stop(fastpath_ctx_t *fp)
{
    if (!fp || fp->mode != FASTPATH_AF_XDP) return;
    if (!atomic_exchange(&fp->running, 0)) return;
    for (int q = 0; q < fp->num_queues; q++)
        if (fp->queues[q].tid) pthread_join(fp->queues[q].tid, NULL);
}

void fastpath_destroy(fastpath_ctx_t *fp)
{
    if (!fp) return;
    if (fp->mode == FASTPATH_AF_XDP) {
        for (int q = 0; q < fp->num_queues; q++) {
            if (fp->queues[q].xsk)       xsk_socket__delete(fp->queues[q].xsk);
            if (fp->queues[q].umem)      xsk_umem__delete(fp->queues[q].umem);
            if (fp->queues[q].umem_area) munmap(fp->queues[q].umem_area, UMEM_SIZE);
        }
        if (fp->prog_fd > 0)
            bpf_xdp_detach(fp->if_index, fp->xdp_flags, NULL);
        if (fp->bpf_obj) bpf_object__close(fp->bpf_obj);
    }
    free(fp);
}

void fastpath_stats(const fastpath_ctx_t *fp, fastpath_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!fp || fp->mode != FASTPATH_AF_XDP || fp->stats_map_fd < 0) return;

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = 1;
    uint64_t *vals = calloc((size_t)ncpus, sizeof(uint64_t));
    if (!vals) return;
    static const uint32_t keys[] = { 0, 1, 2, 3 };
    uint64_t *target[4] = { &out->rx_pass, &out->rx_drop,
                            &out->rx_redirect, &out->rx_malformed };
    for (int k = 0; k < 4; k++) {
        if (bpf_map_lookup_elem(fp->stats_map_fd, &keys[k], vals) == 0) {
            uint64_t sum = 0;
            for (int c = 0; c < ncpus; c++) sum += vals[c];
            *target[k] = sum;
        }
    }
    free(vals);
}

#endif /* BUILD_FASTPATH */
