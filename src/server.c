/* ====================================================================
 *  injspoof -- server mode (new core)
 *
 *  Multi-client by 5-byte HID; forwarding destination comes from the
 *  per-packet header chosen by the client:
 *      [ hid : 5 ][ redirect_ip : 4 (BE) ][ redirect_port : 2 (BE) ]
 * ==================================================================== */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "server.h"
#include "config.h"
#include "packet.h"
#include "raw_socket.h"
#include "pool.h"
#include "logger.h"
#include "metrics.h"
#include "api.h"
#include "fastpath.h"
#include "rcu.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS       64
#define EPOLL_TIMEOUT_MS 1
#define RECV_BATCH_SIZE  32
#define UDP_RECV_BATCH   32
#define TX_BATCH_FRAMES  128
#define UDP_RX_SLOT      65536
#define TX_FRAME_BUF     (MAX_PACKET_SIZE * PKT_MAX_FRAGS)
#define TX_SCRATCH_BUF   65536
#define MAX_DRAIN_PER_FD 256

extern volatile sig_atomic_t g_shutdown;
extern char **g_argv_saved;

static _Atomic(config_t *) g_active_cfg;
static pool_t              g_pool;

typedef struct {
    int                peer_index;
    int                udp_fwd_fd;
    struct sockaddr_in addr;
    _Atomic uint64_t   last_redirect;  /* (ip_be << 16) | port_be */
    /* Per-client telemetry */
    _Atomic uint64_t   rx_bytes, tx_bytes, rx_pkts, tx_pkts;
    _Atomic uint64_t   first_seen_ns, last_active_ns;
    _Atomic int        conn_state;     /* 0 never, 1 active, 2 idle */
    /* Reporter snapshot (main thread only) */
    uint64_t           rep_rx_bytes, rep_tx_bytes, rep_ns;
} peer_state_t;

static peer_state_t g_peer_states[MAX_PEERS];
static int          g_peer_state_count = 0;

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int create_backend_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { LOG_PERROR("server: udp socket"); return -1; }
    /* Modest per-peer buffers: there can be thousands of these sockets,
     * so keep each small to bound total kernel memory (F17 / scale). */
    int rcvbuf = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int busy_poll = 50;
    setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
    return fd;
}

static inline int filter_match(const source_pool_t *flt,
                               uint32_t src_ip_be, uint16_t src_port_host)
{
    int ip_ok = (flt->count == 0);
    if (!ip_ok) {
        uint32_t h = ntohl(src_ip_be);
        for (int i = 0; i < flt->count; i++) {
            if (h < flt->subnets[i].first_ip) break;   /* sorted: stop early */
            if (h <= flt->subnets[i].last_ip) { ip_ok = 1; break; }
        }
    }
    if (!ip_ok) return 0;
    int port_ok = (flt->port_count == 0);
    if (!port_ok)
        for (int i = 0; i < flt->port_count; i++)
            if (src_port_host == flt->ports[i]) { port_ok = 1; break; }
    return port_ok;
}

static inline int parse_rx(const uint8_t *buf, size_t len,
                           uint32_t *src_ip_out, uint16_t *src_port_out,
                           const uint8_t **payload_out, int *pl_len_out)
{
    if (__builtin_expect(len < (size_t)(ETH_HLEN_CONST + IP_HLEN), 0)) {
        METRIC_INC(&g_metrics.drop_parse); return 0;
    }
    const struct iphdr *iph = (const void *)(buf + ETH_HLEN_CONST);
    int ip_hlen = iph->ihl * 4;
    if (__builtin_expect(len < (size_t)(ETH_HLEN_CONST + ip_hlen), 0)) {
        METRIC_INC(&g_metrics.drop_parse); return 0;
    }
    uint8_t  proto    = iph->protocol;
    int      to       = ETH_HLEN_CONST + ip_hlen;
    const uint8_t *payload = NULL;
    int      pl_len   = 0;
    uint16_t src_port = 0;

    if (proto == IPPROTO_TCP) {
        if (len < (size_t)(to + TCP_HLEN)) { METRIC_INC(&g_metrics.drop_parse); return 0; }
        const struct tcphdr *th = (const void *)(buf + to);
        src_port = ntohs(th->source);
        int thlen = th->doff * 4;
        payload = buf + to + thlen; pl_len = (int)len - to - thlen;
    } else if (proto == IPPROTO_UDP) {
        if (len < (size_t)(to + UDP_HLEN)) { METRIC_INC(&g_metrics.drop_parse); return 0; }
        const struct udphdr *uh = (const void *)(buf + to);
        src_port = ntohs(uh->source);
        payload = buf + to + UDP_HLEN; pl_len = (int)len - to - UDP_HLEN;
    } else if (proto == IPPROTO_ICMP) {
        if (len < (size_t)(to + ICMP_HLEN)) { METRIC_INC(&g_metrics.drop_parse); return 0; }
        payload = buf + to + ICMP_HLEN; pl_len = (int)len - to - ICMP_HLEN;
    } else {
        METRIC_INC(&g_metrics.drop_parse); return 0;
    }
    if (pl_len <= 0) { METRIC_INC(&g_metrics.drop_parse); return 0; }
    *src_ip_out = iph->saddr; *src_port_out = src_port;
    *payload_out = payload;   *pl_len_out = pl_len;
    return 1;
}

static void handle_client_frame(const config_t *cfg, const uint8_t *buf, size_t len)
{
    uint32_t src_ip; uint16_t src_port;
    const uint8_t *payload; int pl_len;
    if (!parse_rx(buf, len, &src_ip, &src_port, &payload, &pl_len)) return;
    if (pl_len <= HID_HLEN) { METRIC_INC(&g_metrics.drop_parse); return; }

    int pi = config_find_peer_by_hid(cfg, (const char *)payload);
    if (pi < 0) { METRIC_INC(&g_metrics.drop_filter); return; }

    const peer_endpoint_t *ep = &cfg->peers[pi].primary;
    const firewall_rule_t *rule = &cfg->firewall[ep->rule_index];
    if (!filter_match(&rule->incoming_pool, src_ip, src_port)) {
        METRIC_INC(&g_metrics.drop_filter); return;
    }

    uint32_t rip; uint16_t rport;
    memcpy(&rip,   payload + HID_LEN,     4);
    memcpy(&rport, payload + HID_LEN + 4, 2);
    atomic_store_explicit(&g_peer_states[pi].last_redirect,
                          ((uint64_t)rip << 16) | (uint64_t)rport,
                          memory_order_relaxed);

    /* Per-client accounting + connect/reconnect state change. */
    uint64_t nowns = metrics_now_ns();
    int prev = atomic_exchange_explicit(&g_peer_states[pi].conn_state, 1, memory_order_relaxed);
    if (prev != 1) {
        char ipbuf[INET_ADDRSTRLEN];
        struct in_addr ia; ia.s_addr = src_ip;
        inet_ntop(AF_INET, &ia, ipbuf, sizeof(ipbuf));
        if (prev == 0) {
            atomic_store_explicit(&g_peer_states[pi].first_seen_ns, nowns, memory_order_relaxed);
            LOG_INFO("peer connected    hid=%-5s  src=%s", cfg->peers[pi].hid, ipbuf);
        } else {
            LOG_INFO("peer reconnected  hid=%-5s  src=%s", cfg->peers[pi].hid, ipbuf);
        }
    }
    atomic_store_explicit(&g_peer_states[pi].last_active_ns, nowns, memory_order_relaxed);

    const uint8_t *data = payload + HID_HLEN;
    int dlen = pl_len - HID_HLEN;
    if (g_peer_states[pi].udp_fwd_fd < 0) return;
    atomic_fetch_add_explicit(&g_peer_states[pi].rx_bytes, (uint64_t)dlen, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_peer_states[pi].rx_pkts, 1, memory_order_relaxed);

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = rip;
    to.sin_port = rport;
    ssize_t s = sendto(g_peer_states[pi].udp_fwd_fd, data, (size_t)dlen,
                       MSG_DONTWAIT, (struct sockaddr *)&to, sizeof(to));
    if (s > 0) {
        METRIC_INC(&g_metrics.pkts_out_local);
        METRIC_ADD(&g_metrics.pkts_out, 1);
    }
}

static void fp_on_rx(const uint8_t *frame, uint32_t len, uint32_t queue, void *ctx)
{
    (void)queue; (void)ctx;
    config_t *cfg = atomic_load_explicit(&g_active_cfg, memory_order_acquire);
    handle_client_frame(cfg, frame, (size_t)len);
}

typedef struct { config_t **slot; fastpath_ctx_t *fp; } reload_ctx_t;

static int on_hot_reload(const config_t *new_cfg_const, void *ctx)
{
    reload_ctx_t *rc = ctx;
    config_t *new_cfg = (config_t *)new_cfg_const;
    config_t *old = atomic_exchange(&g_active_cfg, new_cfg);

    logger_config_t lcfg; config_build_logger_cfg(new_cfg, &lcfg);
    logger_reconfigure(&lcfg);
    config_apply_tcp_policy(new_cfg);

    if (rc && rc->fp && new_cfg->peer_count > 0) {
        const peer_endpoint_t *ep = &new_cfg->peers[0].primary;
        const firewall_rule_t *rule = &new_cfg->firewall[ep->rule_index];
        protocol_filter_t pf; config_protocol_filter(&rule->incoming_protocol, &pf);
        fastpath_reconfigure(rc->fp, &rule->incoming_pool,
                             new_cfg->peer_count == 1 ? pf.proto : 0);
    }
    if (rc && rc->slot) *rc->slot = new_cfg;
    /* F5: wait until packet thread + XDP workers pass a quiescent state
     * (no longer hold the old pointer), then it is safe to reclaim. */
    if (old) { rcu_synchronize(); config_free(old); free(old); }
    return 0;
}

static int on_hard_reload(void *ctx)
{
    (void)ctx;
    LOG_INFO("server: execve self for hard reload");
    logger_shutdown();
    if (g_argv_saved) execv(g_argv_saved[0], g_argv_saved);
    _exit(2);
    return 0;
}

/* Periodic per-client status: one readable line per active peer, plus
 * connect/idle state changes. Rate-limited to once every 5 s. */
static uint64_t g_peer_report_last = 0;
static void report_peers(const config_t *cfg)
{
    uint64_t now = metrics_now_ns();
    if (now - g_peer_report_last < 5000000000ull) return;
    g_peer_report_last = now;

    int dbg = (logger_get_level() <= LVL_DEBUG);
    uint64_t trx = 0, ttx = 0;
    int active = 0;

    for (int i = 0; i < g_peer_state_count; i++) {
        peer_state_t *ps = &g_peer_states[i];
        int st = atomic_load_explicit(&ps->conn_state, memory_order_relaxed);
        if (st == 0) continue;                       /* never connected */

        uint64_t last  = atomic_load_explicit(&ps->last_active_ns, memory_order_relaxed);
        uint64_t first = atomic_load_explicit(&ps->first_seen_ns,  memory_order_relaxed);
        uint64_t rxb   = atomic_load_explicit(&ps->rx_bytes, memory_order_relaxed);
        uint64_t txb   = atomic_load_explicit(&ps->tx_bytes, memory_order_relaxed);
        uint64_t idle  = now > last ? now - last : 0;

        if (st == 1 && idle > 30000000000ull) {       /* 30 s -> idle (state change) */
            atomic_store_explicit(&ps->conn_state, 2, memory_order_relaxed);
            char ago[32]; metrics_fmt_duration_ns(idle, ago, sizeof(ago));
            LOG_WARN("peer idle         hid=%-5s  no traffic for %s", cfg->peers[i].hid, ago);
            continue;
        }
        if (st != 1) continue;

        trx += rxb; ttx += txb; active++;

        /* Per-peer detail only when DEBUG is enabled, so logging stays
         * cheap (one aggregate INFO line) with thousands of peers. */
        if (dbg) {
            double dt = ps->rep_ns ? (double)(now - ps->rep_ns) / 1e9 : 0.0;
            double rin  = dt > 0 ? (double)(rxb - ps->rep_rx_bytes) / dt : 0.0;
            double rout = dt > 0 ? (double)(txb - ps->rep_tx_bytes) / dt : 0.0;
            ps->rep_ns = now; ps->rep_rx_bytes = rxb; ps->rep_tx_bytes = txb;
            char up[32], srx[24], stx[24], rrx[24], rtx[24];
            metrics_fmt_duration_ns(now > first ? now - first : 0, up, sizeof(up));
            metrics_fmt_bytes(rxb, srx, sizeof(srx));
            metrics_fmt_bytes(txb, stx, sizeof(stx));
            metrics_fmt_rate(rin,  rrx, sizeof(rrx));
            metrics_fmt_rate(rout, rtx, sizeof(rtx));
            LOG_DEBUG("peer hid=%-5s  up %-9s  rx %9s (%10s)  tx %9s (%10s)",
                      cfg->peers[i].hid, up, srx, rrx, stx, rtx);
        }
    }

    char brx[24], btx[24];
    metrics_fmt_bytes(trx, brx, sizeof(brx));
    metrics_fmt_bytes(ttx, btx, sizeof(btx));
    LOG_INFO("clients: %d total, %d active | total rx %9s  tx %9s",
             g_peer_state_count, active, brx, btx);
}

int server_run(config_t *cfg_in)
{
    int ret = -1;
    int rcu_id = rcu_register();
    config_t *cfg = cfg_in;
    atomic_store(&g_active_cfg, cfg);

    if (cfg->peer_count <= 0) { LOG_ERROR("server: no peers configured"); return -1; }

    const peer_endpoint_t *ep0 = &cfg->peers[0].primary;
    const interface_t *iface0  = &cfg->interfaces[ep0->interface_index];

    for (int i = 1; i < cfg->peer_count; i++)
        if (cfg->peers[i].primary.interface_index != ep0->interface_index)
            LOG_WARN("server: peers span multiple interfaces; Phase A uses "
                     "'%s' for all raw I/O (see REVIEW.md F12)", iface0->tag);

    LOG_INFO("server: %d peers, frag=%u fastpath=%s iface=%s",
             cfg->peer_count, iface0->fragment_size, cfg->fastpath.mode, iface0->tag);

    g_peer_state_count = cfg->peer_count;
    for (int i = 0; i < cfg->peer_count; i++) {
        memset(&g_peer_states[i], 0, sizeof(g_peer_states[i]));
        g_peer_states[i].peer_index = i;
        g_peer_states[i].addr.sin_family = AF_INET;
        g_peer_states[i].addr.sin_addr.s_addr = cfg->peers[i].primary.addr_be;
        g_peer_states[i].udp_fwd_fd = create_backend_socket();
        if (g_peer_states[i].udp_fwd_fd < 0) return -1;
    }

    if (pool_init(&g_pool, POOL_DEFAULT_COUNT, POOL_DEFAULT_BUFSIZE) < 0) {
        LOG_ERROR("server: pool init failed");
        return -1;
    }

    uint8_t *tx_frame   = aligned_alloc(4096, TX_FRAME_BUF);
    uint8_t *tx_scratch = aligned_alloc(4096, TX_SCRATCH_BUF);
    uint8_t *udp_rx_block = aligned_alloc(4096, (size_t)UDP_RECV_BATCH * UDP_RX_SLOT);
    uint8_t *hdr_block  = malloc(UDP_RX_SLOT + HID_HLEN);  /* no page alignment needed */
    int epoll_fd = -1, raw_send_fd = -1, raw_recv_fd = -1;
    fastpath_ctx_t *fp = NULL;
    uint8_t *rx_bufs[RECV_BATCH_SIZE];
    int      rx_alloc = 0;
    if (!tx_frame || !tx_scratch || !udp_rx_block || !hdr_block) {
        LOG_ERROR("server: tx alloc failed"); goto cleanup;
    }

    raw_send_fd = raw_send_init(iface0);
    if (raw_send_fd < 0) goto cleanup;

    {
        const firewall_rule_t *rule0 = &cfg->firewall[ep0->rule_index];
        protocol_filter_t pf; config_protocol_filter(&rule0->incoming_protocol, &pf);
        int proto_match = (cfg->peer_count == 1) ? pf.proto : 0;
        static const source_pool_t empty_pool;
        const source_pool_t *bpf_filter = (cfg->peer_count == 1)
                                        ? &rule0->incoming_pool : &empty_pool;

        int want_fastpath = !strcasecmp(cfg->fastpath.mode, "af_xdp") ||
                            !strcasecmp(cfg->fastpath.mode, "auto");
        if (want_fastpath) {
            if (fastpath_init(&fp, iface0, bpf_filter, proto_match,
                              &cfg->fastpath, fp_on_rx, NULL) == 0 &&
                fastpath_mode(fp) == FASTPATH_AF_XDP) {
                if (fastpath_start(fp) < 0) {
                    LOG_WARN("server: fastpath_start failed, falling back to AF_PACKET");
                    fastpath_destroy(fp); fp = NULL;
                }
            }
        }
        if (!fp || fastpath_mode(fp) != FASTPATH_AF_XDP) {
            raw_recv_fd = raw_recv_init(iface0, bpf_filter, proto_match);
            if (raw_recv_fd < 0) goto cleanup;
            set_nonblock(raw_recv_fd);
        } else {
            LOG_INFO("server: using AF_XDP fastpath for RX");
        }
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) { LOG_PERROR("server: epoll_create1"); goto cleanup; }

    /* Encode the dispatch target in the epoll token for O(1) routing:
     * data.u64 = (fd << 32) | tag, where tag 0 = raw RX and tag i+1 = peer i. */
    struct epoll_event ev;
    for (int i = 0; i < g_peer_state_count; i++) {
        ev.events = EPOLLIN;
        ev.data.u64 = ((uint64_t)g_peer_states[i].udp_fwd_fd << 32) | (uint32_t)(i + 1);
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_peer_states[i].udp_fwd_fd, &ev);
    }
    if (raw_recv_fd >= 0) {
        ev.events = EPOLLIN;
        ev.data.u64 = ((uint64_t)raw_recv_fd << 32);
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
    }

    reload_ctx_t rctx = { .slot = &cfg, .fp = fp };
    api_ctx_t actx = {
        .cfg = cfg, .on_hot_reload = on_hot_reload,
        .on_hard_reload = on_hard_reload, .reload_ctx = &rctx, .pool = &g_pool,
    };
    api_start(&actx);

    if (raw_recv_fd >= 0) {
        for (int j = 0; j < RECV_BATCH_SIZE; j++) {
            rx_bufs[j] = pool_alloc(&g_pool);
            if (!rx_bufs[j]) { LOG_ERROR("server: pool exhausted at startup"); goto cleanup; }
            rx_alloc++;
        }
    }
    struct iovec   rx_iovs[RECV_BATCH_SIZE];
    struct mmsghdr rx_msgs[RECV_BATCH_SIZE];
    memset(rx_msgs, 0, sizeof(rx_msgs));
    for (int j = 0; j < RECV_BATCH_SIZE; j++) {
        rx_iovs[j].iov_base = rx_alloc ? rx_bufs[j] : NULL;
        rx_iovs[j].iov_len  = POOL_DEFAULT_BUFSIZE;
        rx_msgs[j].msg_hdr.msg_iov    = &rx_iovs[j];
        rx_msgs[j].msg_hdr.msg_iovlen = 1;
    }

    struct iovec   udp_iovs[UDP_RECV_BATCH];
    struct mmsghdr udp_msgs[UDP_RECV_BATCH];
    memset(udp_msgs, 0, sizeof(udp_msgs));
    for (int j = 0; j < UDP_RECV_BATCH; j++) {
        udp_iovs[j].iov_base = udp_rx_block + (size_t)j * UDP_RX_SLOT;
        udp_iovs[j].iov_len  = UDP_RX_SLOT;
        udp_msgs[j].msg_hdr.msg_iov    = &udp_iovs[j];
        udp_msgs[j].msg_hdr.msg_iovlen = 1;
    }

    struct iovec   tx_iovs[TX_BATCH_FRAMES];
    struct mmsghdr tx_msgs[TX_BATCH_FRAMES];
    memset(tx_msgs, 0, sizeof(tx_msgs));
    for (int j = 0; j < TX_BATCH_FRAMES; j++) {
        tx_msgs[j].msg_hdr.msg_iov    = &tx_iovs[j];
        tx_msgs[j].msg_hdr.msg_iovlen = 1;
    }

    struct epoll_event events[MAX_EVENTS];
    metrics_reporter_t reporter;
    metrics_reporter_init(&reporter);
    LOG_INFO("server: event loop running");

    static int adaptive_drain_limit = MAX_DRAIN_PER_FD;

    while (!g_shutdown) {
        rcu_quiescent(rcu_id);
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            LOG_PERROR("server: epoll_wait"); break;
        }
        cfg = atomic_load_explicit(&g_active_cfg, memory_order_acquire);
        metrics_reporter_tick(&reporter, "server", &g_pool, 0);
        report_peers(cfg);

        const interface_t *iface = &cfg->interfaces[ep0->interface_index];
        const uint8_t *o_mac = iface->outgoing_mac;
        const uint8_t *g_mac = iface->outgoing_gateway_mac;
        const uint16_t frag_s = iface->fragment_size;

        for (int i = 0; i < nfds; i++) {
            uint64_t tok = events[i].data.u64;
            int fd  = (int)(tok >> 32);
            int tag = (int)(uint32_t)tok;

            if (tag == 0) {
                int drained = 0;
                while (drained < adaptive_drain_limit) {
                    int got = recvmmsg(raw_recv_fd, rx_msgs, RECV_BATCH_SIZE, MSG_DONTWAIT, NULL);
                    METRIC_INC(&g_metrics.recvmmsg_calls);
                    if (got <= 0) break;
                    for (int j = 0; j < got; j++) {
                        unsigned ml = rx_msgs[j].msg_len;
                        METRIC_INC(&g_metrics.pkts_in_wire);
                        METRIC_INC(&g_metrics.pkts_in);
                        METRIC_ADD(&g_metrics.bytes_in, (uint64_t)ml);
                        handle_client_frame(cfg, rx_bufs[j], ml);
                    }
                    drained += got;
                    if (got < RECV_BATCH_SIZE) break;
                }
                continue;
            }

            int pi = tag - 1;
            if (pi < 0 || pi >= g_peer_state_count) continue;

            const peer_endpoint_t *ep = &cfg->peers[pi].primary;
            const firewall_rule_t *rule = &cfg->firewall[ep->rule_index];
            source_pool_t *opool = (source_pool_t *)&rule->outgoing_pool;
            int use_tcp  = !strcmp(rule->outgoing_protocol.mode, "tcp");
            int use_icmp = !strcmp(rule->outgoing_protocol.mode, "icmp");
            uint8_t tcp_flags = use_tcp ? pkt_parse_tcp_flags(rule->outgoing_protocol.flags) : 0;
            uint16_t dst_port = opool->dst_port_count > 0 ? opool->dst_ports[0] : 443;
            uint32_t peer_dst_be = ep->addr_be;

            uint64_t rdr = atomic_load_explicit(&g_peer_states[pi].last_redirect,
                                                memory_order_relaxed);
            uint32_t rip   = (uint32_t)(rdr >> 16);
            uint16_t rport = (uint16_t)(rdr & 0xFFFF);

            int total = 0;
            while (total < adaptive_drain_limit) {
                int got = recvmmsg(fd, udp_msgs, UDP_RECV_BATCH, MSG_DONTWAIT, NULL);
                METRIC_INC(&g_metrics.recvmmsg_calls);
                if (got <= 0) break;
                total += got;

                int used = 0, frame_count = 0;
                for (int p = 0; p < got; p++) {
                    unsigned n = udp_msgs[p].msg_len;
                    if (__builtin_expect(n == 0, 0)) continue;
                    if (__builtin_expect(n > UDP_RX_SLOT - HID_HLEN, 0)) {
                        METRIC_INC(&g_metrics.drop_oversize); continue;
                    }
                    METRIC_INC(&g_metrics.pkts_in_local);
                    METRIC_INC(&g_metrics.pkts_in);
                    METRIC_ADD(&g_metrics.bytes_in, (uint64_t)n);
                    atomic_fetch_add_explicit(&g_peer_states[pi].tx_bytes, (uint64_t)n, memory_order_relaxed);
                    atomic_fetch_add_explicit(&g_peer_states[pi].tx_pkts, 1, memory_order_relaxed);
                    atomic_store_explicit(&g_peer_states[pi].last_active_ns, metrics_now_ns(), memory_order_relaxed);

                    memcpy(hdr_block, cfg->peers[pi].hid, HID_LEN);
                    memcpy(hdr_block + HID_LEN,     &rip,   4);
                    memcpy(hdr_block + HID_LEN + 4, &rport, 2);
                    memcpy(hdr_block + HID_HLEN, udp_iovs[p].iov_base, n);
                    uint16_t total_pl = (uint16_t)(n + HID_HLEN);

                    uint32_t src_ip   = config_pool_next_source_ip(opool);
                    uint16_t src_port = config_pool_next_source_port(opool);
                    if (__builtin_expect(src_ip == 0, 0)) continue;

                    int worst_frames = (int)(total_pl / frag_s) + 2;
                    int worst_bytes  = (int)total_pl + worst_frames *
                                       (ETH_HLEN_CONST + IP_HLEN + 64);
                    if (used + worst_bytes > TX_FRAME_BUF ||
                        frame_count + worst_frames > TX_BATCH_FRAMES) {
                        if (frame_count > 0) {
                            int sent = raw_send_batch(raw_send_fd, tx_msgs, frame_count);
                            METRIC_ADD(&g_metrics.frags_sent, (uint64_t)frame_count);
                            if (sent >= 0 && sent < frame_count) {
                                adaptive_drain_limit /= 2;
                                if (adaptive_drain_limit < 16) adaptive_drain_limit = 16;
                                METRIC_INC(&g_metrics.congestion_events);
                            } else if (adaptive_drain_limit < MAX_DRAIN_PER_FD) {
                                adaptive_drain_limit += 16;
                            }
                            used = 0; frame_count = 0;
                        }
                    }

                    pkt_frame_view_t fr[PKT_MAX_FRAGS];
                    int fc = 0, rc;
                    if (use_tcp) {
                        rc = pkt_build_tcp_fragments(tx_frame + used, TX_FRAME_BUF - used,
                                tx_scratch, TX_SCRATCH_BUF, o_mac, g_mac, src_ip, peer_dst_be,
                                src_port, dst_port, tcp_flags, hdr_block, total_pl, frag_s, fr, &fc);
                    } else if (use_icmp) {
                        rc = pkt_build_icmp_fragments(tx_frame + used, TX_FRAME_BUF - used,
                                tx_scratch, TX_SCRATCH_BUF, o_mac, g_mac, src_ip, peer_dst_be,
                                rule->outgoing_protocol.icmp_type,
                                rule->outgoing_protocol.icmp_code,
                                hdr_block, total_pl, frag_s, fr, &fc);
                    } else {
                        rc = pkt_build_udp_fragments(tx_frame + used, TX_FRAME_BUF - used,
                                tx_scratch, TX_SCRATCH_BUF, o_mac, g_mac, src_ip, peer_dst_be,
                                src_port, dst_port, hdr_block, total_pl, frag_s, fr, &fc);
                    }
                    if (rc < 0 || fc == 0) continue;
                    for (int kk = 0; kk < fc; kk++) {
                        tx_iovs[frame_count].iov_base = (void *)fr[kk].frame;
                        tx_iovs[frame_count].iov_len  = (size_t)fr[kk].len;
                        frame_count++; used += fr[kk].len;
                    }
                }

                if (frame_count > 0) {
                    int sent = raw_send_batch(raw_send_fd, tx_msgs, frame_count);
                    METRIC_ADD(&g_metrics.frags_sent, (uint64_t)frame_count);
                    if (sent >= 0 && sent < frame_count) {
                        adaptive_drain_limit /= 2;
                        if (adaptive_drain_limit < 16) adaptive_drain_limit = 16;
                        METRIC_INC(&g_metrics.congestion_events);
                        METRIC_ADD(&g_metrics.drop_recv_backpressure,
                                   (uint64_t)(frame_count - sent));
                        break;
                    } else if (adaptive_drain_limit < MAX_DRAIN_PER_FD) {
                        adaptive_drain_limit += 16;
                    }
                }
                if (got < UDP_RECV_BATCH) break;
            }
        }
    }

    LOG_INFO("server: shutting down");
    ret = 0;

cleanup:
    api_stop();
    if (fp) { fastpath_stop(fp); fastpath_destroy(fp); }
    if (epoll_fd >= 0) close(epoll_fd);
    for (int i = 0; i < g_peer_state_count; i++)
        if (g_peer_states[i].udp_fwd_fd >= 0) close(g_peer_states[i].udp_fwd_fd);
    if (raw_send_fd >= 0) close(raw_send_fd);
    if (raw_recv_fd >= 0) close(raw_recv_fd);
    for (int j = 0; j < rx_alloc; j++) pool_free(&g_pool, rx_bufs[j]);
    free(tx_frame); free(tx_scratch); free(udp_rx_block); free(hdr_block);
    pool_destroy(&g_pool);
    return ret;
}
