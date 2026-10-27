#ifndef INJSPOOF_RAW_SOCKET_H
#define INJSPOOF_RAW_SOCKET_H

#include "config.h"
#include <stdint.h>
#include <sys/socket.h>

/*
 * Initialize a raw sending socket (AF_PACKET, SOCK_RAW) bound to the
 * interface's outgoing index. Caches the destination (gateway MAC +
 * ifindex) for this fd. Returns fd on success, -1 on error.
 */
int raw_send_init(const interface_t *iface);

/*
 * Initialize a raw receiving socket (AF_PACKET, SOCK_RAW) on the
 * interface's incoming index, with a classic-BPF filter built from
 * `filter` (CIDR + src ports) and `proto_match` (IPPROTO_* or 0=any).
 * Returns fd on success, -1 on error.
 */
int raw_recv_init(const interface_t *iface, const source_pool_t *filter, int proto_match);

/*
 * Send a pre-built raw Ethernet frame on the fd's cached destination.
 * Returns bytes sent on success, -1 on error.
 */
int raw_send(int fd, const uint8_t *frame, int frame_len);

/*
 * Batch-send pre-built raw Ethernet frames via sendmmsg on the fd's
 * cached destination. Returns number of messages sent, -1 on error.
 */
int raw_send_batch(int fd, struct mmsghdr *msgs, int count);

#endif /* INJSPOOF_RAW_SOCKET_H */
