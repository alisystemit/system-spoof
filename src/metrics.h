#ifndef INJSPOOF_METRICS_H
#define INJSPOOF_METRICS_H

#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *  Atomic counters consumed by the Management API (/api/v1/stats)
 *  and any external Prometheus exporter.
 *
 *  All increments are relaxed atomics: thread-safe with minimal
 *  ordering overhead, ideal for hot-path packet accounting.
 * ============================================================ */

typedef struct {
    /* Packet I/O - directional, no double counting.
     *
     *   pkts_in_local  = UDP datagrams received from the local app
     *                    (client: from listen socket; server: from forwarder)
     *   pkts_in_wire   = raw frames captured from the NIC (tunnel side)
     *   pkts_out_wire  = raw frames sent on the NIC
     *   pkts_out_local = UDP datagrams forwarded to the local app
     */
    _Atomic uint64_t pkts_in_local;
    _Atomic uint64_t pkts_in_wire;
    _Atomic uint64_t pkts_out_wire;
    _Atomic uint64_t pkts_out_local;

    /* Aggregates (kept for compatibility - sum of the four above) */
    _Atomic uint64_t pkts_in;
    _Atomic uint64_t pkts_out;
    _Atomic uint64_t bytes_in;
    _Atomic uint64_t bytes_out;
    _Atomic uint64_t frags_sent;

    /* Drops */
    _Atomic uint64_t drop_filter;       /* dropped by BPF/userspace filter */
    _Atomic uint64_t drop_parse;        /* malformed/short packets */
    _Atomic uint64_t drop_pool;         /* memory pool exhausted */
    _Atomic uint64_t drop_send;         /* sendto / sendmmsg failure (total) */
    _Atomic uint64_t drop_oversize;     /* payload > 65535 */

    /* Per-errno send-failure breakdown.  drop_send is the sum of the
     * five buckets below plus drop_send_other (anything we don't have
     * a named bucket for).  These exist because "raw_send failed" in
     * the wild is almost always one of these, and knowing which one
     * dictates the fix:
     *
     *   ENOBUFS  -> kernel TX queue full -> grow qdisc / lower pps
     *   EAGAIN   -> nonblocking would-block -> usually transient burst
     *   EMSGSIZE -> frame > NIC MTU -> reduce outgoing.fragment_size
     *   ENETDOWN -> interface flapped / unplugged
     *   EPERM    -> capabilities dropped (cap_net_raw missing)
     */
    _Atomic uint64_t drop_send_enobufs;
    _Atomic uint64_t drop_send_eagain;
    _Atomic uint64_t drop_send_emsgsize;
    _Atomic uint64_t drop_send_enetdown;
    _Atomic uint64_t drop_send_eperm;
    _Atomic uint64_t drop_send_other;

    /* Backpressure / congestion */
    _Atomic uint64_t drop_recv_backpressure;  /* recv-side drops due to send congestion */
    _Atomic uint64_t congestion_events;       /* times adaptive drain kicked in */

    /* Syscalls */
    _Atomic uint64_t recvmmsg_calls;
    _Atomic uint64_t sendmmsg_calls;
    _Atomic uint64_t sendto_calls;

    /* Reloads */
    _Atomic uint64_t reloads_hot;
    _Atomic uint64_t reloads_hard;

    /* Process timing */
    uint64_t         uptime_start_ns;   /* set once at startup */
} metrics_t;

extern metrics_t g_metrics;

/* Initialise (zero counters, record start time). */
void metrics_init(void);

/* Snapshot helper - copies all atomic counters into a plain struct
 * (caller-supplied) so the API can serialise without inconsistency. */
typedef struct {
    uint64_t pkts_in_local, pkts_in_wire, pkts_out_wire, pkts_out_local;
    uint64_t pkts_in, pkts_out, bytes_in, bytes_out, frags_sent;
    uint64_t drop_filter, drop_parse, drop_pool, drop_send, drop_oversize;
    uint64_t drop_send_enobufs, drop_send_eagain, drop_send_emsgsize;
    uint64_t drop_send_enetdown, drop_send_eperm, drop_send_other;
    uint64_t drop_recv_backpressure, congestion_events;
    uint64_t recvmmsg_calls, sendmmsg_calls, sendto_calls;
    uint64_t reloads_hot, reloads_hard;
    uint64_t uptime_ns;
    uint64_t log_emitted, log_dropped;
} metrics_snapshot_t;

void metrics_snapshot(metrics_snapshot_t *out);

/* ============================================================
 *  Live status reporter (periodic INFO line).
 *
 *  Call once per outer loop iteration: it returns 1 and writes a
 *  one-line summary to the logger at INFO level if at least
 *  `interval_ns` has elapsed since the previous emission, otherwise
 *  it returns 0 immediately (cheap monotonic-clock check).
 *
 *  Each call site (client / server / ipfinder) keeps its own state
 *  in a caller-owned struct so multiple reporters can coexist with
 *  no shared locks.
 *
 *  Output format (single line, fits 80 cols on typical workloads):
 *
 *  injspoof <who>: in 12.3kpps (9.8 MB/s)  out 12.1kpps (9.5 MB/s)
 *      frags=18.1k drops f=0 p=0 pool=0 send=42(ENOBUFS=42 EAGAIN=0)
 *      pool=98% sys recv=410 send=405 hb=0
 * ============================================================ */

typedef struct {
    uint64_t            last_ns;        /* monotonic ns of last emit */
    metrics_snapshot_t  last_snap;      /* last counters snapshot */
    uint32_t            pool_avail_last;
} metrics_reporter_t;

/* Initialise (called once). */
void metrics_reporter_init(metrics_reporter_t *r);

/* Emit a periodic status line if enough time has elapsed.
 *
 *   who          - short label, e.g. "client", "server", "ipfinder"
 *   pool         - optional pool_t* (for pool utilisation %); NULL ok.
 *                  Typed as void* so this header stays free of pool.h.
 *   interval_ns  - minimum interval between emissions, 0 = use default 1s
 *
 * Returns 1 if an INFO line was emitted this call, 0 otherwise. */
int  metrics_reporter_tick(metrics_reporter_t *r,
                           const char *who,
                           const void *pool,
                           uint64_t interval_ns);

/* Human-readable formatting helpers (shared by client/server reporters). */
uint64_t metrics_now_ns(void);
void metrics_fmt_bytes(uint64_t bytes, char *buf, size_t cap);       /* "1.23 MB"  */
void metrics_fmt_rate(double bytes_per_sec, char *buf, size_t cap);  /* "3.4 KB/s" */
void metrics_fmt_duration_ns(uint64_t ns, char *buf, size_t cap);    /* "01:02:03" */



/* Fast inline increment helpers. */
static inline void METRIC_ADD(_Atomic uint64_t *m, uint64_t v) {
    atomic_fetch_add_explicit(m, v, memory_order_relaxed);
}
static inline void METRIC_INC(_Atomic uint64_t *m) {
    atomic_fetch_add_explicit(m, 1u, memory_order_relaxed);
}

#endif /* INJSPOOF_METRICS_H */
