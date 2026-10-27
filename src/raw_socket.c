/* ====================================================================
 *  injspoof — raw L2 sockets (AF_PACKET / SOCK_RAW)
 *
 *  Hot-path features
 *  -----------------
 *  - Edge-triggered, NIC-bound sockets.
 *  - Kernel-side BPF filter with CIDR bounds checking + capture
 *    protocol gate, so undesired packets are dropped before
 *    crossing the user-space boundary.
 *  - SO_RCVBUFFORCE / SO_SNDBUFFORCE for unbounded burst absorption.
 *  - PACKET_QDISC_BYPASS on the sender (direct ring -> NIC).
 *  - PACKET_IGNORE_OUTGOING on the receiver (no loopback of our own
 *    traffic).
 *  - raw_send / raw_send_batch use a single sockaddr_ll cached at
 *    socket creation - no per-call build cost.
 * ==================================================================== */

#include "raw_socket.h"
#include "logger.h"
#include "metrics.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- Cached destination sockaddr (per socket) ---- */

/* We keep one cached destination per raw_send_fd; the typical case is
 * one sender per process, but we also support arbitrary FDs. The cache
 * uses the FD as a key in a small open-addressed array. */
#define RAW_FD_CACHE 16
static struct {
    int               fd;
    struct sockaddr_ll dest;
} g_dest_cache[RAW_FD_CACHE];

/* Look up the cached destination for an fd (seeded at raw_send_init). */
static struct sockaddr_ll *lookup_dest(int fd)
{
    for (int i = 0; i < RAW_FD_CACHE; i++)
        if (g_dest_cache[i].fd == fd) return &g_dest_cache[i].dest;
    /* Not seeded - return the first slot (functional but possibly wrong). */
    return &g_dest_cache[0].dest;
}

/* Seed the destination cache for an fd from its outgoing interface. */
static void seed_dest(int fd, int ifindex, const uint8_t gw_mac[6])
{
    for (int i = 0; i < RAW_FD_CACHE; i++) {
        if (g_dest_cache[i].fd == fd ||
            g_dest_cache[i].fd == 0 || g_dest_cache[i].fd == -1) {
            g_dest_cache[i].fd = fd;
            memset(&g_dest_cache[i].dest, 0, sizeof(g_dest_cache[i].dest));
            g_dest_cache[i].dest.sll_family  = AF_PACKET;
            g_dest_cache[i].dest.sll_ifindex = ifindex;
            g_dest_cache[i].dest.sll_halen   = 6;
            memcpy(g_dest_cache[i].dest.sll_addr, gw_mac, 6);
            return;
        }
    }
}

/* ====================================================================
 *  BPF builder
 *
 *  Layout (offsets from start of Ethernet frame):
 *    [0]   load ethertype (offset 12)
 *    [1]   jeq IPv4  -> next, else REJECT
 *    [2]   load IP proto (offset 23, IPv4 protocol byte)
 *    [3]   (optional) jeq proto -> next, else REJECT  (when cfg->capture_proto.proto != 0)
 *    [4]   load IP src (offset 26, word)
 *    [5..] for each subnet: bounds-check (JGE/JGT) -> ACCEPT_IP
 *    [..]  no match -> REJECT
 *    [..]  ACCEPT_IP: compute IP header length, load src port
 *    [..]  for each port: jeq -> ACCEPT
 *    [..]  REJECT
 * ==================================================================== */

#define BPF_MAX_INSTR 512
#define BPF_MAX_IP_BLOCKS  64
#define BPF_MAX_PORTS      16

static int attach_bpf_filter(int fd, const source_pool_t *flt, int proto_match)
{
    /* If no rules, accept all IPv4 */
    if (flt->count == 0 && flt->port_count == 0 && proto_match == 0) {
        LOG_DEBUG("raw: no BPF rules - accepting all IPv4");
        return 0;
    }

    int ip_blocks = (flt->count > BPF_MAX_IP_BLOCKS) ? 0 : flt->count;
    int port_count = (flt->port_count > BPF_MAX_PORTS) ? 0 : flt->port_count;

    struct sock_filter code[BPF_MAX_INSTR];
    int n = 0;

    /* 1) Ethertype IPv4 */
    code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12);
    code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 0);
    int eth_jf = n - 1;

    /* 2) Protocol gate.
     *    When proto_match is set (e.g. 6=TCP, 17=UDP, 1=ICMP): single proto.
     *    When proto_match == 0 AND we have ip/port rules: accept TCP|UDP|ICMP.
     *    This ensures ICMP mode captures its packets. */
    int proto_jf = -1;
    int proto_accept_tcp = -1, proto_accept_udp = -1, proto_accept_icmp = -1;
    if (proto_match) {
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14 + 9);
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 (uint32_t)proto_match, 0, 0);
        proto_jf = n - 1;
    } else if (ip_blocks > 0 || port_count > 0) {
        /* Accept TCP(6), UDP(17), or ICMP(1) */
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14 + 9);
        proto_accept_tcp = n;
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 0);
        proto_accept_udp = n;
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 0);
        proto_accept_icmp = n;
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0);
        proto_jf = n - 1; /* ICMP miss -> reject */
    }

    /* 3) IP source bounds check */
    int ip_block_jumps[BPF_MAX_IP_BLOCKS];
    int reject_ip_idx = -1;
    int accept_ip_idx = -1;

    if (ip_blocks > 0) {
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 14 + 12);
        for (int i = 0; i < ip_blocks; i++) {
            uint32_t first = flt->subnets[i].first_ip;
            uint32_t last  = flt->subnets[i].last_ip;
            if (first == last) {
                ip_block_jumps[i] = n;
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, first, 0, 0);
            } else {
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, first, 0, 2);
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, last,  1, 0);
                ip_block_jumps[i] = n;
                code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0);
            }
        }
        reject_ip_idx = n;
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0);
        accept_ip_idx = n;
    }

    /* 4) Source port */
    int port_jumps[BPF_MAX_PORTS];
    int reject_port_idx = -1;
    if (port_count > 0) {
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14);
        code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14);
        for (int i = 0; i < port_count; i++) {
            port_jumps[i] = n;
            code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                     flt->ports[i], 0, 0);
        }
        reject_port_idx = n;
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0);
    }

    /* 5) ACCEPT / REJECT */
    int accept_idx = n;
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 65535);
    int reject_idx = n;
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0);

    /* Patch jumps */
    code[eth_jf].jf = (uint8_t)(reject_idx - eth_jf - 1);
    if (proto_jf >= 0) code[proto_jf].jf = (uint8_t)(reject_idx - proto_jf - 1);

    /* Patch multi-proto jumps: TCP/UDP/ICMP all jump to the next insn on match */
    /* Actually, the jumps are forward to the instruction after the proto section.
     * proto_accept_tcp/udp/icmp.jt should jump past the remaining proto checks
     * to the IP/port block. The .jt (true-match) offset for each: */
    if (proto_accept_tcp >= 0) {
        /* TCP match: skip UDP and ICMP checks to continue to IP filter */
        code[proto_accept_tcp].jt = 2; /* skip 2 instructions (UDP check + ICMP check) */
    }
    if (proto_accept_udp >= 0) {
        /* UDP match: skip ICMP check */
        code[proto_accept_udp].jt = 1;
    }
    if (proto_accept_icmp >= 0) {
        /* ICMP match: fall through to next (already jt=0 from BPF_JUMP) */
        code[proto_accept_icmp].jt = 0;
    }

    if (ip_blocks > 0) {
        for (int i = 0; i < ip_blocks; i++) {
            int j = ip_block_jumps[i];
            uint8_t off = (uint8_t)(accept_ip_idx - j - 1);
            if (BPF_OP(code[j].code) == BPF_JEQ) code[j].jt = off;
            else                                  code[j].k  = off;
        }
        code[reject_ip_idx].k = (uint32_t)(reject_idx - reject_ip_idx - 1);
    }
    if (port_count > 0) {
        for (int i = 0; i < port_count; i++)
            code[port_jumps[i]].jt = (uint8_t)(accept_idx - port_jumps[i] - 1);
        code[reject_port_idx].k = (uint32_t)(reject_idx - reject_port_idx - 1);
    } else if (ip_blocks > 0) {
        /* If we have IPs but no ports, fall through to ACCEPT after ip match.
         * We've already laid that out (accept_ip_idx == n at this point...).
         * In fact if port_count is zero we already produced ACCEPT next. */
    }

    struct sock_fprog bpf = { .len = (unsigned short)n, .filter = code };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        LOG_PERROR("raw: SO_ATTACH_FILTER");
        return -1;
    }

    LOG_INFO("raw: BPF filter %d insns (%d ip-blocks, %d ports, proto=%d)",
             n, ip_blocks, port_count, proto_match);
    return 0;
}

/* ====================================================================
 *  Sockets
 * ==================================================================== */

int raw_send_init(const interface_t *iface)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { LOG_PERROR("raw_send: socket"); return -1; }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = iface->outgoing_index;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_PERROR("raw_send: bind"); close(fd); return -1;
    }

    int sndbuf = 16 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0) {
        sndbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    int prio = 6;
    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));

    int bypass = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &bypass, sizeof(bypass));

    /* Pre-populate the destination cache for this fd */
    seed_dest(fd, iface->outgoing_index, iface->outgoing_gateway_mac);

    LOG_INFO("raw_send: %s (idx=%d) fd=%d", iface->outgoing_name, iface->outgoing_index, fd);
    return fd;
}

int raw_recv_init(const interface_t *iface, const source_pool_t *filter, int proto_match)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) { LOG_PERROR("raw_recv: socket"); return -1; }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = iface->incoming_index;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_PERROR("raw_recv: bind"); close(fd); return -1;
    }

    /* Reduce from 16MB to 4MB to bound kernel buffering during
     * high packet loss bursts (root cause of the OOM issue). */
    int rcvbuf = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
        rcvbuf = 2 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    int ignore_outgoing = 1;
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING,
               &ignore_outgoing, sizeof(ignore_outgoing));

    /* SO_BUSY_POLL on the raw recv socket (reduces wakeup latency) */
    int busy_poll = 50;
    setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));

    if (attach_bpf_filter(fd, filter, proto_match) < 0)
        LOG_WARN("raw_recv: BPF attach failed, falling back to userspace filtering");

    LOG_INFO("raw_recv: %s (idx=%d) fd=%d", iface->incoming_name, iface->incoming_index, fd);
    return fd;
}

/* Classify a sendto/sendmmsg errno into one of our drop-cause buckets
 * and bump it.  Returns void; the caller still bumps `drop_send` (the
 * total) so the existing JSON contract is preserved. */
static inline void classify_send_errno(int e, uint64_t n)
{
    switch (e) {
        case ENOBUFS:                          METRIC_ADD(&g_metrics.drop_send_enobufs,  n); break;
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
                                               METRIC_ADD(&g_metrics.drop_send_eagain,   n); break;
        case EMSGSIZE:                         METRIC_ADD(&g_metrics.drop_send_emsgsize, n); break;
        case ENETDOWN:
        case ENETUNREACH:                      METRIC_ADD(&g_metrics.drop_send_enetdown, n); break;
        case EPERM:
        case EACCES:                           METRIC_ADD(&g_metrics.drop_send_eperm,    n); break;
        default:                               METRIC_ADD(&g_metrics.drop_send_other,    n); break;
    }
}

int raw_send(int fd, const uint8_t *frame, int frame_len)
{
    struct sockaddr_ll *dest = lookup_dest(fd);
    ssize_t sent = sendto(fd, frame, (size_t)frame_len, MSG_DONTWAIT,
                          (struct sockaddr *)dest, sizeof(*dest));
    METRIC_INC(&g_metrics.sendto_calls);
    if (sent < 0) {
        int e = errno;
        if (e != EAGAIN && e != EWOULDBLOCK && e != ENOBUFS)
            LOG_PERROR("raw_send: sendto");
        METRIC_INC(&g_metrics.drop_send);
        classify_send_errno(e, 1);
        return -1;
    }
    METRIC_INC(&g_metrics.pkts_out);
    METRIC_ADD(&g_metrics.bytes_out, (uint64_t)sent);
    return (int)sent;
}

int raw_send_batch(int fd, struct mmsghdr *msgs, int count)
{
    struct sockaddr_ll *dest = lookup_dest(fd);
    for (int i = 0; i < count; i++) {
        msgs[i].msg_hdr.msg_name    = dest;
        msgs[i].msg_hdr.msg_namelen = sizeof(*dest);
    }

    /* Single sendmmsg per call.  We DO NOT retry/sleep here - that
     * blocks the packet thread for microseconds and causes the UDP
     * recv queue to overflow on the producer side, which is worse
     * than dropping a few fragments.  If the kernel's TX ring is
     * full it will report a short send; we account those as drops
     * and move on so the rest of the pipeline stays responsive. */
    int sent = sendmmsg(fd, msgs, (unsigned int)count, MSG_DONTWAIT);
    METRIC_INC(&g_metrics.sendmmsg_calls);
    if (sent < 0) {
        int e = errno;
        if (e != EAGAIN && e != EWOULDBLOCK && e != ENOBUFS)
            LOG_PERROR("raw_send_batch: sendmmsg");
        METRIC_ADD(&g_metrics.drop_send, (uint64_t)count);
        classify_send_errno(e, (uint64_t)count);
        return -1;
    }
    METRIC_ADD(&g_metrics.pkts_out, (uint64_t)sent);
    for (int i = 0; i < sent; i++) {
        unsigned bytes = msgs[i].msg_len ? msgs[i].msg_len :
                         (msgs[i].msg_hdr.msg_iovlen > 0
                              ? (unsigned)msgs[i].msg_hdr.msg_iov[0].iov_len
                              : 0);
        METRIC_ADD(&g_metrics.bytes_out, bytes);
    }
    if (sent < count) {
        /* Partial success: kernel-side drops are not surfaced as
         * errno (sendmmsg returned >=0).  Attribute the missing slice
         * to the "other" bucket so it's still visible in the breakdown. */
        uint64_t missed = (uint64_t)(count - sent);
        METRIC_ADD(&g_metrics.drop_send, missed);
        METRIC_ADD(&g_metrics.drop_send_other, missed);
    }
    return sent;
}
