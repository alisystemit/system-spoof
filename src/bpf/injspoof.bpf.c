/* ====================================================================
 *  injspoof — XDP ingress filter
 *
 *  Runs at the NIC driver level, before any skbuff allocation.
 *
 *  Layout
 *  ------
 *      [parse Ethernet]
 *      [parse IPv4]
 *      [optional protocol gate]
 *      [CIDR-bounds check across the source IP map]
 *      [port check across the source port map]
 *      ACCEPT -> XDP_REDIRECT into the AF_XDP socket map (zero-copy
 *                into the userspace umem ring), or XDP_PASS if no
 *                xsk is bound.
 *      REJECT -> XDP_PASS   (hand the frame back to the kernel so
 *                the host's normal networking — SSH, ARP, IPv6,
 *                everything not in our capture filter — keeps working).
 *                A per-cpu "filtered" counter is still bumped for stats.
 *
 *  Rule of thumb: this is a *capture* filter, not a firewall. We never
 *  drop user traffic; we only steal copies of the frames we care about.
 *  The only XDP_DROP path is reserved for truly malformed frames where
 *  we cannot even compute a length.
 *
 *  Maps
 *  ----
 *      xsks_map         : SOCKMAP indexed by RX queue  -> AF_XDP socket
 *      cidr_blocks_map  : ARRAY of (first_ip, last_ip) host-order bounds
 *      ports_map        : ARRAY of allowed src ports (uint16)
 *      config_map       : ARRAY (1 entry) with packed runtime params
 *      stats_map        : PERCPU_ARRAY with drop/pass/redirect counters
 *
 *  Compile with:
 *      clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *            -I/usr/include -c injspoof.bpf.c -o injspoof.bpf.o
 *
 *  The userspace loader (src/fastpath.c) populates the maps from the
 *  parsed config_t at startup, and again on hot-reload.
 * ==================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Hard caps mirror what the userspace loader enforces. */
#define INJ_MAX_CIDR_BLOCKS  4096
#define INJ_MAX_PORTS        64
#define INJ_MAX_XSK_QUEUES   64

/* ============================================================
 *  Maps
 * ============================================================ */

struct cidr_block {
    __u32 first_ip;   /* host byte order */
    __u32 last_ip;
};

/* AF_XDP socket map: one socket per RX queue index */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, INJ_MAX_XSK_QUEUES);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* CIDR allow-list (sorted; first invalid entry has first_ip == 0). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, INJ_MAX_CIDR_BLOCKS);
    __type(key, __u32);
    __type(value, struct cidr_block);
} cidr_blocks_map SEC(".maps");

/* Source port allow-list (first 0 entry ends the list). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, INJ_MAX_PORTS);
    __type(key, __u32);
    __type(value, __u16);
} ports_map SEC(".maps");

/* Single-entry runtime parameters */
struct inj_config {
    __u32 cidr_count;
    __u32 port_count;
    __u8  proto_filter;       /* 0 = any, 6 = TCP, 17 = UDP */
    __u8  redirect_to_xsk;    /* 1 = use AF_XDP, 0 = XDP_PASS on accept */
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct inj_config);
} config_map SEC(".maps");

/* Per-CPU stats - copied by userspace into the metrics module.
 *
 *  RX_PASS       - frame did not match the capture filter; handed back
 *                  to the kernel stack untouched.
 *  RX_FILTERED   - frame matched but xsk redirect was disabled
 *                  (or alias for "captured but passed up"). Kept as
 *                  INJ_STAT_RX_DROP for ABI compatibility with the
 *                  userspace metrics reader, but it no longer means
 *                  the frame was dropped.
 *  RX_REDIRECT   - frame matched and was redirected into AF_XDP.
 *  RX_MALFORMED  - frame too short to parse; the ONLY XDP_DROP path.
 */
enum {
    INJ_STAT_RX_PASS = 0,
    INJ_STAT_RX_DROP,         /* now means "matched but not redirected" */
    INJ_STAT_RX_REDIRECT,
    INJ_STAT_RX_MALFORMED,
    INJ_STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, INJ_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats_map, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

/* ============================================================
 *  Scan callbacks
 *
 *  The two array scans (CIDR allow-list, port allow-list) used to
 *  be open-coded `for` loops. On older verifier kernels — and on
 *  kernels where the loop counter gets spilled to the stack across
 *  the bpf_map_lookup_elem() call — the verifier loses the bound
 *  on `i` and rejects the program with
 *
 *      infinite loop detected at insn N
 *      ... fp-16=????scalar(smin=0,smax=umax=0xffffffff, ...) ...
 *
 *  bpf_loop() (kernel ≥ 5.17) bounds termination structurally:
 *  it verifies the callback exactly once and the runtime enforces
 *  the `nr_loops` cap, so the verifier never has to prove anything
 *  about loop progress.
 * ============================================================ */

struct cidr_scan_ctx {
    __u32 src;          /* source IP in host order */
    __u32 max;          /* clamped cidr_count      */
    int   matched;
};

static long cidr_match_cb(__u32 i, struct cidr_scan_ctx *c)
{
    if (i >= c->max) return 1;                          /* stop */
    struct cidr_block *b = bpf_map_lookup_elem(&cidr_blocks_map, &i);
    if (!b) return 1;
    if (b->first_ip == 0 && b->last_ip == 0) return 1;  /* sentinel */
    /* Blocks are sorted ascending by first_ip (userspace guarantees this),
     * so once src is below the current block's start no later block can
     * match -- stop early instead of scanning the whole array. */
    if (c->src < b->first_ip) return 1;                 /* stop (sorted) */
    if (c->src <= b->last_ip) {
        c->matched = 1;
        return 1;                                       /* stop (match) */
    }
    return 0;                                           /* continue */
}

struct port_scan_ctx {
    __u16 sport;
    __u32 max;          /* clamped port_count */
    int   ok;
};

static long port_match_cb(__u32 i, struct port_scan_ctx *c)
{
    if (i >= c->max) return 1;
    __u16 *p = bpf_map_lookup_elem(&ports_map, &i);
    if (!p) return 1;
    if (*p == c->sport) { c->ok = 1; return 1; }
    return 0;
}

/* ============================================================
 *  Entry point
 * ============================================================ */

SEC("xdp")
int xdp_inj_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { bump(INJ_STAT_RX_MALFORMED); return XDP_DROP; }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bump(INJ_STAT_RX_PASS);
        return XDP_PASS;
    }

    /* IPv4 */
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) { bump(INJ_STAT_RX_MALFORMED); return XDP_DROP; }
    if (iph->version != 4 || iph->ihl < 5) { bump(INJ_STAT_RX_MALFORMED); return XDP_DROP; }

    __u32 key0 = 0;
    struct inj_config *cfg = bpf_map_lookup_elem(&config_map, &key0);
    if (!cfg) return XDP_PASS;

    /* Protocol gate. Non-matching protocols are NOT ours — hand them
     * back to the host kernel so SSH/ARP/etc. continue to work. */
    if (cfg->proto_filter && iph->protocol != cfg->proto_filter) {
        bump(INJ_STAT_RX_PASS);
        return XDP_PASS;
    }

    /* Source IP in host order */
    __u32 src = bpf_ntohl(iph->saddr);

    /* CIDR membership */
    int matched = 0;
    if (cfg->cidr_count == 0) {
        matched = 1; /* no rules = accept all */
    } else {
        __u32 max = cfg->cidr_count;
        if (max > INJ_MAX_CIDR_BLOCKS) max = INJ_MAX_CIDR_BLOCKS;

        struct cidr_scan_ctx sc = { .src = src, .max = max, .matched = 0 };
        bpf_loop(INJ_MAX_CIDR_BLOCKS, cidr_match_cb, &sc, 0);
        matched = sc.matched;
    }
    /* Not part of our capture set -> let the kernel have it. */
    if (!matched) { bump(INJ_STAT_RX_PASS); return XDP_PASS; }

    /* Source port (parse transport header).
     *
     * F14: a non-first IP fragment carries no transport header, so its
     * "port" bytes would be payload garbage.  Match such fragments on the
     * IP allow-list alone (the first fragment already enforced the port). */
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    int is_noninitial_frag = (frag_off & 0x1FFF) != 0;
    if (cfg->port_count > 0 && !is_noninitial_frag) {
        void *l4 = (void *)iph + (iph->ihl * 4);
        __u16 sport;
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = l4;
            if ((void *)(th + 1) > data_end) { bump(INJ_STAT_RX_MALFORMED); return XDP_DROP; }
            sport = bpf_ntohs(th->source);
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *uh = l4;
            if ((void *)(uh + 1) > data_end) { bump(INJ_STAT_RX_MALFORMED); return XDP_DROP; }
            sport = bpf_ntohs(uh->source);
        } else {
            /* Not TCP/UDP and ports were configured -> not ours. */
            bump(INJ_STAT_RX_PASS);
            return XDP_PASS;
        }
        __u32 max = cfg->port_count;
        if (max > INJ_MAX_PORTS) max = INJ_MAX_PORTS;

        struct port_scan_ctx pc = { .sport = sport, .max = max, .ok = 0 };
        bpf_loop(INJ_MAX_PORTS, port_match_cb, &pc, 0);
        if (!pc.ok) { bump(INJ_STAT_RX_PASS); return XDP_PASS; }
    }

    /* Accept path: either redirect to the AF_XDP socket for this RX
     * queue, or pass up to the kernel for AF_PACKET fallback. */
    if (cfg->redirect_to_xsk) {
        /* bpf_redirect_map will look up the rx_queue_index and steer
         * the frame to the bound AF_XDP socket if any. */
        bump(INJ_STAT_RX_REDIRECT);
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    }
    bump(INJ_STAT_RX_PASS);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
