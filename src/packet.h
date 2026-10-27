#ifndef INJSPOOF_PACKET_H
#define INJSPOOF_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* Header / protocol sizes */
#define ETH_HLEN_CONST   14
#define ETH_P_IP_CONST   0x0800
#define IP_HLEN          20
#define TCP_HLEN         20
#define UDP_HLEN         8
#define ICMP_HLEN        8  /* type(1) + code(1) + checksum(2) + id(2) + seq(2) */
#define HID_HLEN         11 /* HID (5) + Redirect IP (4) + Redirect Port (2) */

/* Jumbo-safe maximum frame */
#define MAX_PACKET_SIZE  9216

/* TCP flag bits */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/* Max fragments per single packet (sane upper bound). */
#define PKT_MAX_FRAGS  64

typedef int (*pkt_send_fn)(const uint8_t *frame, int frame_len, void *ctx);

/* Batched variant - emit a whole iovec[] in one syscall.
 * Each entry is one independent Ethernet frame. */
typedef struct {
    const uint8_t *frame;
    int            len;
} pkt_frame_view_t;

typedef int (*pkt_send_batch_fn)(const pkt_frame_view_t *frames, int count,
                                 void *ctx);

/* Non-fragmented builders */
int pkt_build_tcp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint8_t tcp_flags,
                  const uint8_t *payload, uint16_t payload_len);

int pkt_build_udp(uint8_t *buf,
                  const uint8_t src_mac[6], const uint8_t dst_mac[6],
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  const uint8_t *payload, uint16_t payload_len);

/* Fragmented send (single-send-callback variant - kept for compatibility). */
int pkt_send_tcp_fragmented(uint8_t *buf, uint8_t *scratch,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t tcp_flags,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx);

int pkt_send_udp_fragmented(uint8_t *buf, uint8_t *scratch,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_send_fn send_fn, void *send_ctx);

/* Fragmented batched send - all fragments emitted in a single sendmmsg.
 * `buf` must be at least PKT_MAX_FRAGS * fragment_size bytes; on return,
 * frames[] points into `buf` at the correct fragment offsets.
 * Returns 0 on success, -1 on error. */
int pkt_build_tcp_fragments(uint8_t *buf, int buf_cap,
                            uint8_t *scratch, int scratch_cap,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t tcp_flags,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_frame_view_t *frames, int *frame_count);

int pkt_build_udp_fragments(uint8_t *buf, int buf_cap,
                            uint8_t *scratch, int scratch_cap,
                            const uint8_t src_mac[6], const uint8_t dst_mac[6],
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            const uint8_t *payload, uint16_t payload_len,
                            uint16_t fragment_size,
                            pkt_frame_view_t *frames, int *frame_count);

/* ICMP builders */
int pkt_build_icmp(uint8_t *buf,
                   const uint8_t src_mac[6], const uint8_t dst_mac[6],
                   uint32_t src_ip, uint32_t dst_ip,
                   uint8_t icmp_type, uint8_t icmp_code,
                   const uint8_t *payload, uint16_t payload_len);

int pkt_build_icmp_fragments(uint8_t *buf, int buf_cap,
                             uint8_t *scratch, int scratch_cap,
                             const uint8_t src_mac[6], const uint8_t dst_mac[6],
                             uint32_t src_ip, uint32_t dst_ip,
                             uint8_t icmp_type, uint8_t icmp_code,
                             const uint8_t *payload, uint16_t payload_len,
                             uint16_t fragment_size,
                             pkt_frame_view_t *frames, int *frame_count);

/* TCP seq/ack policy.  Mirror of the values in protocol_t (config.h).
 *
 *  TCP_POL_FIXED       seq=base_seq, ack=base_ack on every packet
 *  TCP_POL_RANDOM      per-packet random seq AND random ack
 *  TCP_POL_SEQUENTIAL  seq advances by payload_len per packet, ack fixed
 */
typedef enum {
    TCP_POL_FIXED      = 0,
    TCP_POL_RANDOM     = 1,
    TCP_POL_SEQUENTIAL = 2,
} pkt_tcp_policy_t;

/* Install the TCP seq/ack policy globally.  Cheap to call frequently
 * (a few atomic stores); intended to be invoked once at startup and
 * again on hot-reload. */
void pkt_set_tcp_policy(pkt_tcp_policy_t mode, uint32_t base_seq, uint32_t base_ack);

/* TCP flag string parser ("psh+ack" -> bitmask). */
uint8_t  pkt_parse_tcp_flags(const char *flag_str);

/* Internet checksum (RFC 1071). */
uint16_t pkt_checksum(const void *data, size_t len);

#endif /* INJSPOOF_PACKET_H */
