#ifndef INJSPOOF_FASTPATH_H
#define INJSPOOF_FASTPATH_H

#include "config.h"
#include <stdint.h>
#include <stdatomic.h>

/* ====================================================================
 *  AF_XDP / XDP fastpath
 *
 *  Drop-in alternative to the AF_PACKET RX path. When enabled in the
 *  config, the runtime:
 *
 *    1. Loads `injspoof.bpf.o` (embedded blob) onto the capture
 *       interface using libbpf.
 *    2. Allocates one AF_XDP socket per RX queue, each with its own
 *       umem ring (zero-copy when the driver supports it).
 *    3. Populates the BPF maps with the current filter (CIDR blocks,
 *       ports, protocol gate).
 *    4. Spawns one worker thread per queue, pinned to a CPU. Each
 *       worker drains its xsk RX ring directly into the rest of the
 *       pipeline (no skbuff allocation, no kernel copies).
 *
 *  The TX side optionally uses AF_XDP TX rings on the outgoing iface
 *  too — same zero-copy umem path, batched.
 *
 *  Build deps: libbpf, libxdp (or hand-rolled xsk ring code), clang
 *  for the .bpf.o object.
 *
 *  Trade-offs are documented in README.md - the user opts in via
 *  cfg.fastpath.mode.
 * ==================================================================== */

typedef enum {
    FASTPATH_AUTO     = 0,  /* try AF_XDP, fall back to AF_PACKET */
    FASTPATH_AF_PACKET= 1,  /* legacy raw-socket path */
    FASTPATH_AF_XDP   = 2,  /* AF_XDP zero-copy */
} fastpath_mode_t;

typedef struct fastpath_ctx fastpath_ctx_t;

/* Per-packet callback installed by the runtime (client.c / server.c).
 * Called from the AF_XDP worker threads with a pointer into the umem
 * region that remains valid only until the callback returns. */
typedef void (*fastpath_rx_fn)(const uint8_t *frame, uint32_t len,
                               uint32_t queue, void *ctx);

/* Initialise the fastpath against the capture interface in cfg.
 * Returns 0 on success, -1 on error.
 *
 * Falls back to AF_PACKET (returns 0 with mode=FASTPATH_AF_PACKET) if
 * the kernel/NIC can't support AF_XDP and cfg->fastpath.mode is "auto".
 */
int  fastpath_init(fastpath_ctx_t **out,
                   const interface_t *capture_iface,
                   const source_pool_t *filter, int proto_match,
                   const fastpath_settings_t *fpset,
                   fastpath_rx_fn on_rx, void *rx_ctx);

/* Reconfigure the BPF maps on hot-reload (filter changes only;
 * structural changes still require a restart). */
int  fastpath_reconfigure(fastpath_ctx_t *fp,
                          const source_pool_t *filter, int proto_match);

/* Effective mode actually in use (may differ from cfg.mode under
 * "auto" fallback). */
fastpath_mode_t fastpath_mode(const fastpath_ctx_t *fp);

/* Start the worker threads. */
int  fastpath_start(fastpath_ctx_t *fp);

/* Stop and join all workers. */
void fastpath_stop(fastpath_ctx_t *fp);

/* Tear down (after stop). */
void fastpath_destroy(fastpath_ctx_t *fp);

/* TX path - submit a single frame to the AF_XDP TX ring for the given
 * queue. Returns bytes sent or -1. When mode == AF_PACKET, this
 * forwards to raw_send() for compatibility. */
int  fastpath_tx(fastpath_ctx_t *fp, uint32_t queue,
                 const uint8_t *frame, uint32_t len);

/* TX batched - all frames go on a single AF_XDP ring submission. */
int  fastpath_tx_batch(fastpath_ctx_t *fp, uint32_t queue,
                       const uint8_t *const *frames,
                       const uint32_t *lens, int count);

/* Snapshot BPF-level counters into a struct for the metrics API. */
typedef struct {
    uint64_t rx_pass;
    uint64_t rx_drop;
    uint64_t rx_redirect;
    uint64_t rx_malformed;
} fastpath_stats_t;

void fastpath_stats(const fastpath_ctx_t *fp, fastpath_stats_t *out);

#endif /* INJSPOOF_FASTPATH_H */
