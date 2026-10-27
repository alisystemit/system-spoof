/* ====================================================================
 *  injspoof — packet builder
 *
 *  Performance notes
 *  -----------------
 *  - g_ip_id is now an atomic uint16 so multiple producer threads
 *    (api thread vs. packet loop) cannot collide on the IPv4 ID.
 *  - Builders take pre-allocated scratch buffers from the caller -
 *    no heap traffic on the hot path.
 *  - Batched fragmentation (`pkt_build_*_fragments`) lays every
 *    fragment out contiguously in a caller-supplied buffer so they
 *    can be emitted with a single sendmmsg() call.
 *  - All checksum loops use a folded 32-bit accumulator
 *    (single-pass, no memcpy, branch-free fold).
 * ==================================================================== */

#include "packet.h"
#include "logger.h"

#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

/* ---- Packed wire structures (no padding) ---- */

struct __attribute__((packed)) eth_header {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

struct __attribute__((packed)) ip_header {
    uint8_t  ihl_ver;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct __attribute__((packed)) tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct __attribute__((packed)) udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t check;
};

struct __attribute__((packed)) icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};


/* Atomic global IP-ID (thread-safe across packet loop + api). */
static _Atomic uint16_t g_ip_id = 0;
static _Atomic uint16_t g_icmp_seq = 0;

static inline uint16_t next_ip_id(void)
{
    return atomic_fetch_add_explicit(&g_ip_id, 1, memory_order_relaxed);
}

/* TCP seq/ack policy (configurable via JSON `protocol.options`).
 *
 * Defaults match v1 behaviour: seq=0x12345678, ack=0x87654321 fixed.
 * The runtime installs the user-selected policy with
 * pkt_set_tcp_policy() at startup and again on hot-reload.
 */
static _Atomic int      g_tcp_policy  = TCP_POL_FIXED;
static _Atomic uint32_t g_tcp_seq_base = 0x12345678u;
static _Atomic uint32_t g_tcp_ack_base = 0x87654321u;
static _Atomic uint32_t g_tcp_seq_walk = 0x12345678u;
static __thread uint64_t s_pkt_xorshift = 0;

void pkt_set_tcp_policy(pkt_tcp_policy_t mode, uint32_t base_seq, uint32_t base_ack)
{
    atomic_store_explicit(&g_tcp_policy,  (int)mode,  memory_order_relaxed);
    atomic_store_explicit(&g_tcp_seq_base, base_seq, memory_order_relaxed);
    atomic_store_explicit(&g_tcp_ack_base, base_ack, memory_order_relaxed);
    atomic_store_explicit(&g_tcp_seq_walk, base_seq, memory_order_relaxed);
}

static inline uint32_t pkt_fast_rand32(void)
{
    uint64_t x = s_pkt_xorshift;
    if (__builtin_expect(x == 0, 0)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        x = ((uint64_t)ts.tv_nsec * 1000000007ull)
          ^ ((uint64_t)ts.tv_sec  * 0x9E3779B97F4A7C15ull)
          ^ ((uint64_t)getpid()   * 0xBF58476D1CE4E5B9ull)
          ^ (uint64_t)(uintptr_t)&x;
        if (x == 0) x = 0xDEADBEEFCAFEBABEull;
    }
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    s_pkt_xorshift = x;
    return (uint32_t)(x * 0x2545F4914F6CDD1Dull);
}

static inline uint32_t next_tcp_seq(uint16_t advance)
{
    int mode = atomic_load_explicit(&g_tcp_policy, memory_order_relaxed);
    if (mode == TCP_POL_RANDOM)
        return pkt_fast_rand32();
    if (mode == TCP_POL_SEQUENTIAL) {
        if (advance == 0) advance = 1;
        return atomic_fetch_add_explicit(&g_tcp_seq_walk,
                                         (uint32_t)advance,
                                         memory_order_relaxed);
    }
    /* TCP_POL_FIXED (default) */
    return atomic_load_explicit(&g_tcp_seq_base, memory_order_relaxed);
}

static inline uint32_t next_tcp_ack(uint16_t ip_id)
{
    int mode = atomic_load_explicit(&g_tcp_policy, memory_order_relaxed);
    if (mode == TCP_POL_RANDOM)
        return pkt_fast_rand32();
    (void)ip_id;
    return atomic_load_explicit(&g_tcp_ack_base, memory_order_relaxed);
}

/* ====================================================================
 *  Checksums
 * ==================================================================== */

uint16_t pkt_checksum(const void *data, size_t len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)p;
        sum += last;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint16_t transport_checksum(uint32_t saddr, uint32_t daddr,
                                          uint8_t protocol,
                                          const void *transport_hdr,
                                          uint16_t transport_len)
{
    uint32_t sum = 0;
    /* Pseudo-header words */
    uint16_t pw[6];
    pw[0] = (uint16_t)(saddr & 0xFFFF);   pw[1] = (uint16_t)(saddr >> 16);
    pw[2] = (uint16_t)(daddr & 0xFFFF);   pw[3] = (uint16_t)(daddr >> 16);
    pw[4] = htons((uint16_t)protocol);
    pw[5] = htons(transport_len);
    for (int i = 0; i < 6; i++) sum += pw[i];

    const uint16_t *p = transport_hdr;
    size_t len = transport_len;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)p;
        sum += last;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ====================================================================
 *  Builders
 * ==================================================================== */

static inline void build_eth(uint8_t *buf, const uint8_t src[6], const uint8_t dst[6])
{
    struct eth_header *eth = (void *)buf;
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, src, 6);
    eth->ethertype = htons(ETH_P_IP_CONST);
}

static inline void build_ip(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                            uint16_t total_ip_len, uint8_t protocol,
                            uint16_t ip_id, uint16_t frag_off_flags)
{
    struct ip_header *ip = (void *)buf;
    ip->ihl_ver  = 0x45;
    ip->tos      = 0x00;
    ip->tot_len  = htons(total_ip_len);
    ip->id       = htons(ip_id);
    ip->frag_off = htons(frag_off_flags);
    ip->ttl      = 64;
    ip->protocol = protocol;
    ip->check    = 0;
    ip->saddr    = saddr;
    ip->daddr    = daddr;
    ip->check    = pkt_checksum(ip, IP_HLEN);
}

int pkt_build_tcp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint8_t tcp_flags,
                  const uint8_t *payload, uint16_t payload_len)
{
    uint16_t transport_len = TCP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;
    if ((int)ETH_HLEN_CONST + total_ip_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: tcp payload too large (%u)", payload_len);
        return -1;
    }
    build_eth(buf, src_mac, dst_mac);
    uint16_t ip_id = next_ip_id();
    build_ip(buf + ETH_HLEN_CONST, src_ip, dst_ip, total_ip_len,
             6, ip_id, 0x4000);

    struct tcp_header *tcp = (void *)(buf + ETH_HLEN_CONST + IP_HLEN);
    memset(tcp, 0, TCP_HLEN);
    tcp->src_port      = htons(src_port);
    tcp->dst_port      = htons(dst_port);
    tcp->seq           = htonl(next_tcp_seq(payload_len));
    tcp->ack_seq       = htonl(next_tcp_ack(ip_id));
    tcp->doff_reserved = (TCP_HLEN / 4) << 4;
    tcp->flags         = tcp_flags;
    tcp->window        = htons(65535);

    if (payload && payload_len > 0)
        memcpy(buf + ETH_HLEN_CONST + IP_HLEN + TCP_HLEN, payload, payload_len);

    tcp->check = transport_checksum(src_ip, dst_ip, 6, tcp, transport_len);
    return ETH_HLEN_CONST + IP_HLEN + transport_len;
}

int pkt_build_udp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  const uint8_t *payload, uint16_t payload_len)
{
    uint16_t transport_len = UDP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;
    if ((int)ETH_HLEN_CONST + total_ip_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: udp payload too large (%u)", payload_len);
        return -1;
    }
    build_eth(buf, src_mac, dst_mac);
    build_ip(buf + ETH_HLEN_CONST, src_ip, dst_ip, total_ip_len,
             17, next_ip_id(), 0x4000);

    struct udp_header *udp = (void *)(buf + ETH_HLEN_CONST + IP_HLEN);
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len      = htons(transport_len);
    udp->check    = 0;

    if (payload && payload_len > 0)
        memcpy(buf + ETH_HLEN_CONST + IP_HLEN + UDP_HLEN, payload, payload_len);

    udp->check = transport_checksum(src_ip, dst_ip, 17, udp, transport_len);
    if (udp->check == 0) udp->check = 0xFFFF;
    return ETH_HLEN_CONST + IP_HLEN + transport_len;
}

/* ====================================================================
 *  Fragmentation
 * ==================================================================== */

/* Build all fragments contiguously into `buf`, recording each in `frames`. */
static int emit_fragments_into(uint8_t *buf, int buf_cap,
                               const uint8_t src_mac[6], const uint8_t dst_mac[6],
                               uint32_t src_ip, uint32_t dst_ip,
                               uint8_t protocol,
                               const uint8_t *transport_data, uint16_t transport_len,
                               uint16_t fragment_size,
                               pkt_frame_view_t *frames, int *frame_count)
{
    uint16_t max_frag_payload = (uint16_t)((fragment_size - IP_HLEN) & ~7u);
    if (max_frag_payload < 8) {
        LOG_ERROR("packet: fragment_size %u too small", fragment_size);
        return -1;
    }
    uint16_t ip_id = next_ip_id();
    uint16_t offset = 0;
    int      n = 0;
    int      used = 0;

    while (offset < transport_len) {
        if (n >= PKT_MAX_FRAGS) {
            LOG_ERROR("packet: too many fragments (>%d)", PKT_MAX_FRAGS);
            return -1;
        }
        uint16_t remaining = transport_len - offset;
        uint16_t frag_payload = remaining > max_frag_payload ? max_frag_payload : remaining;
        int more_frags = (offset + frag_payload < transport_len);
        if (more_frags && (frag_payload & 7)) frag_payload &= ~(uint16_t)7;
        if (frag_payload == 0) {
            LOG_ERROR("packet: zero-length fragment");
            return -1;
        }

        int frame_len = ETH_HLEN_CONST + IP_HLEN + frag_payload;
        if (used + frame_len > buf_cap) {
            LOG_ERROR("packet: fragment buffer cap exceeded");
            return -1;
        }
        uint8_t *frame = buf + used;
        build_eth(frame, src_mac, dst_mac);

        uint16_t frag_off_flags = (uint16_t)(offset / 8);
        if (more_frags) frag_off_flags |= 0x2000;

        build_ip(frame + ETH_HLEN_CONST, src_ip, dst_ip,
                 (uint16_t)(IP_HLEN + frag_payload), protocol,
                 ip_id, frag_off_flags);
        memcpy(frame + ETH_HLEN_CONST + IP_HLEN,
               transport_data + offset, frag_payload);

        frames[n].frame = frame;
        frames[n].len   = frame_len;
        n++;
        used   += frame_len;
        offset += frag_payload;
    }
    *frame_count = n;
    return 0;
}

int pkt_build_tcp_fragments(uint8_t *buf, int buf_cap,
                            uint8_t *scratch, int scratch_cap,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t tcp_flags,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_frame_view_t *frames, int *frame_count)
{
    uint16_t transport_len = TCP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    /* Single-frame fast path */
    if (total_ip_len <= fragment_size) {
        int n = pkt_build_tcp(buf, src_mac, dst_mac, src_ip, dst_ip,
                              src_port, dst_port, tcp_flags,
                              payload, payload_len);
        if (n < 0) return -1;
        frames[0].frame = buf; frames[0].len = n;
        *frame_count = 1;
        return 0;
    }

    if (transport_len > scratch_cap) {
        LOG_ERROR("packet: tcp transport > scratch cap (%u)", transport_len);
        return -1;
    }

    struct tcp_header *tcp = (void *)scratch;
    memset(tcp, 0, TCP_HLEN);
    tcp->src_port      = htons(src_port);
    tcp->dst_port      = htons(dst_port);
    tcp->seq           = htonl(next_tcp_seq(payload_len));
    /* Use IP-ID 0 just for ack mixing here - the real per-fragment IDs
     * are assigned inside emit_fragments_into(). */
    tcp->ack_seq       = htonl(next_tcp_ack(0));
    tcp->doff_reserved = (TCP_HLEN / 4) << 4;
    tcp->flags         = tcp_flags;
    tcp->window        = htons(65535);
    if (payload && payload_len > 0)
        memcpy(scratch + TCP_HLEN, payload, payload_len);
    tcp->check = transport_checksum(src_ip, dst_ip, 6, tcp, transport_len);

    return emit_fragments_into(buf, buf_cap, src_mac, dst_mac,
                               src_ip, dst_ip, 6,
                               scratch, transport_len, fragment_size,
                               frames, frame_count);
}

int pkt_build_udp_fragments(uint8_t *buf, int buf_cap,
                            uint8_t *scratch, int scratch_cap,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_frame_view_t *frames, int *frame_count)
{
    uint16_t transport_len = UDP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    if (total_ip_len <= fragment_size) {
        int n = pkt_build_udp(buf, src_mac, dst_mac, src_ip, dst_ip,
                              src_port, dst_port, payload, payload_len);
        if (n < 0) return -1;
        frames[0].frame = buf; frames[0].len = n;
        *frame_count = 1;
        return 0;
    }

    if (transport_len > scratch_cap) {
        LOG_ERROR("packet: udp transport > scratch cap (%u)", transport_len);
        return -1;
    }

    struct udp_header *udp = (void *)scratch;
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len      = htons(transport_len);
    udp->check    = 0;
    if (payload && payload_len > 0)
        memcpy(scratch + UDP_HLEN, payload, payload_len);
    udp->check = transport_checksum(src_ip, dst_ip, 17, udp, transport_len);
    if (udp->check == 0) udp->check = 0xFFFF;

    return emit_fragments_into(buf, buf_cap, src_mac, dst_mac,
                               src_ip, dst_ip, 17,
                               scratch, transport_len, fragment_size,
                               frames, frame_count);
}

int pkt_build_icmp(uint8_t *buf,
                   const uint8_t src_mac[6], const uint8_t dst_mac[6],
                   uint32_t src_ip, uint32_t dst_ip,
                   uint8_t icmp_type, uint8_t icmp_code,
                   const uint8_t *payload, uint16_t payload_len)
{
    uint16_t transport_len = ICMP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;
    if ((int)ETH_HLEN_CONST + total_ip_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: icmp payload too large (%u)", payload_len);
        return -1;
    }
    build_eth(buf, src_mac, dst_mac);
    build_ip(buf + ETH_HLEN_CONST, src_ip, dst_ip, total_ip_len,
             1, next_ip_id(), 0x4000);

    struct icmp_header *icmp = (void *)(buf + ETH_HLEN_CONST + IP_HLEN);
    icmp->type     = icmp_type;
    icmp->code     = icmp_code;
    icmp->checksum = 0;
    icmp->id       = htons(next_ip_id());
    icmp->seq      = htons(
        atomic_fetch_add_explicit(&g_icmp_seq, 1, memory_order_relaxed));

    if (payload && payload_len > 0)
        memcpy(buf + ETH_HLEN_CONST + IP_HLEN + ICMP_HLEN,
               payload, payload_len);

    /* ICMP checksum covers the entire ICMP message (header + payload),
     * NO pseudo-header unlike TCP/UDP. */
    icmp->checksum = pkt_checksum(icmp, transport_len);
    return ETH_HLEN_CONST + IP_HLEN + transport_len;
}

int pkt_build_icmp_fragments(uint8_t *buf, int buf_cap,
                             uint8_t *scratch, int scratch_cap,
                             const uint8_t src_mac[6], const uint8_t dst_mac[6],
                             uint32_t src_ip, uint32_t dst_ip,
                             uint8_t icmp_type, uint8_t icmp_code,
                             const uint8_t *payload, uint16_t payload_len,
                             uint16_t fragment_size,
                             pkt_frame_view_t *frames, int *frame_count)
{
    uint16_t transport_len = ICMP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    /* Single-frame fast path */
    if (total_ip_len <= fragment_size) {
        int n = pkt_build_icmp(buf, src_mac, dst_mac, src_ip, dst_ip,
                               icmp_type, icmp_code,
                               payload, payload_len);
        if (n < 0) return -1;
        frames[0].frame = buf; frames[0].len = n;
        *frame_count = 1;
        return 0;
    }

    if (transport_len > scratch_cap) {
        LOG_ERROR("packet: icmp transport > scratch cap (%u)",
                  transport_len);
        return -1;
    }

    struct icmp_header *icmp = (void *)scratch;
    icmp->type     = icmp_type;
    icmp->code     = icmp_code;
    icmp->checksum = 0;
    icmp->id       = htons(next_ip_id());
    icmp->seq      = htons(
        atomic_fetch_add_explicit(&g_icmp_seq, 1, memory_order_relaxed));
    if (payload && payload_len > 0)
        memcpy(scratch + ICMP_HLEN, payload, payload_len);
    /* ICMP checksum: no pseudo-header, covers header + payload. */
    icmp->checksum = pkt_checksum(icmp, transport_len);

    return emit_fragments_into(buf, buf_cap, src_mac, dst_mac,
                               src_ip, dst_ip, 1,
                               scratch, transport_len, fragment_size,
                               frames, frame_count);
}

/* ====================================================================
 *  Legacy single-call fragmented API (calls the batch and re-emits).
 *  Kept for backwards compatibility; new code should use the batch APIs.
 * ==================================================================== */
static int send_fragments_legacy(uint8_t *buf, int buf_cap,
                                 const uint8_t src_mac[6], const uint8_t dst_mac[6],
                                 uint32_t src_ip, uint32_t dst_ip,
                                 uint8_t protocol,
                                 const uint8_t *transport_data, uint16_t transport_len,
                                 uint16_t fragment_size,
                                 pkt_send_fn send_fn, void *send_ctx)
{
    pkt_frame_view_t frames[PKT_MAX_FRAGS];
    int n = 0;
    if (emit_fragments_into(buf, buf_cap, src_mac, dst_mac, src_ip, dst_ip,
                            protocol, transport_data, transport_len,
                            fragment_size, frames, &n) < 0)
        return -1;
    for (int i = 0; i < n; i++)
        if (send_fn(frames[i].frame, frames[i].len, send_ctx) < 0)
            return -1;
    return (int)transport_len;
}

int pkt_send_tcp_fragmented(uint8_t *buf, uint8_t *scratch,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t tcp_flags,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx)
{
    uint16_t transport_len = TCP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    if (total_ip_len <= fragment_size) {
        int frame_len = pkt_build_tcp(buf, src_mac, dst_mac,
                                      src_ip, dst_ip, src_port, dst_port,
                                      tcp_flags, payload, payload_len);
        if (frame_len < 0) return -1;
        return send_fn(buf, frame_len, send_ctx);
    }
    if (transport_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: tcp transport too large (%u)", transport_len);
        return -1;
    }
    struct tcp_header *tcp = (void *)scratch;
    memset(tcp, 0, TCP_HLEN);
    tcp->src_port      = htons(src_port);
    tcp->dst_port      = htons(dst_port);
    tcp->seq           = htonl(next_tcp_seq(payload_len));
    tcp->ack_seq       = htonl(next_tcp_ack(0));
    tcp->doff_reserved = (TCP_HLEN / 4) << 4;
    tcp->flags         = tcp_flags;
    tcp->window        = htons(65535);
    if (payload && payload_len > 0)
        memcpy(scratch + TCP_HLEN, payload, payload_len);
    tcp->check = transport_checksum(src_ip, dst_ip, 6, tcp, transport_len);

    return send_fragments_legacy(buf, MAX_PACKET_SIZE * PKT_MAX_FRAGS,
                                 src_mac, dst_mac, src_ip, dst_ip, 6,
                                 scratch, transport_len, fragment_size,
                                 send_fn, send_ctx);
}

int pkt_send_udp_fragmented(uint8_t *buf, uint8_t *scratch,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx)
{
    uint16_t transport_len = UDP_HLEN + payload_len;
    uint16_t total_ip_len  = IP_HLEN + transport_len;

    if (total_ip_len <= fragment_size) {
        int frame_len = pkt_build_udp(buf, src_mac, dst_mac,
                                      src_ip, dst_ip, src_port, dst_port,
                                      payload, payload_len);
        if (frame_len < 0) return -1;
        return send_fn(buf, frame_len, send_ctx);
    }
    if (transport_len > MAX_PACKET_SIZE) {
        LOG_ERROR("packet: udp transport too large (%u)", transport_len);
        return -1;
    }
    struct udp_header *udp = (void *)scratch;
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len      = htons(transport_len);
    udp->check    = 0;
    if (payload && payload_len > 0)
        memcpy(scratch + UDP_HLEN, payload, payload_len);
    udp->check = transport_checksum(src_ip, dst_ip, 17, udp, transport_len);
    if (udp->check == 0) udp->check = 0xFFFF;

    return send_fragments_legacy(buf, MAX_PACKET_SIZE * PKT_MAX_FRAGS,
                                 src_mac, dst_mac, src_ip, dst_ip, 17,
                                 scratch, transport_len, fragment_size,
                                 send_fn, send_ctx);
}

/* ====================================================================
 *  TCP flag parser
 * ==================================================================== */

uint8_t pkt_parse_tcp_flags(const char *flag_str)
{
    if (!flag_str || !flag_str[0])
        return TCP_FLAG_PSH | TCP_FLAG_ACK;

    uint8_t flags = 0;
    char buf[64];
    strncpy(buf, flag_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "+", &saveptr);
    while (tok) {
        for (char *c = tok; *c; c++)
            if (*c >= 'A' && *c <= 'Z') *c += 32;

        if      (!strcmp(tok, "fin")) flags |= TCP_FLAG_FIN;
        else if (!strcmp(tok, "syn")) flags |= TCP_FLAG_SYN;
        else if (!strcmp(tok, "rst")) flags |= TCP_FLAG_RST;
        else if (!strcmp(tok, "psh")) flags |= TCP_FLAG_PSH;
        else if (!strcmp(tok, "ack")) flags |= TCP_FLAG_ACK;
        else if (!strcmp(tok, "urg")) flags |= TCP_FLAG_URG;
        else LOG_WARN("packet: unknown TCP flag '%s'", tok);

        tok = strtok_r(NULL, "+", &saveptr);
    }
    return flags ? flags : (TCP_FLAG_PSH | TCP_FLAG_ACK);
}

