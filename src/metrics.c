#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "metrics.h"
#include "logger.h"
#include "pool.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

metrics_t g_metrics = { 0 };

uint64_t metrics_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void metrics_init(void)
{
    memset((void *)&g_metrics, 0, sizeof(g_metrics));
    g_metrics.uptime_start_ns = metrics_now_ns();
}

void metrics_snapshot(metrics_snapshot_t *out)
{
    if (!out) return;
    out->pkts_in_local  = atomic_load_explicit(&g_metrics.pkts_in_local,  memory_order_relaxed);
    out->pkts_in_wire   = atomic_load_explicit(&g_metrics.pkts_in_wire,   memory_order_relaxed);
    out->pkts_out_wire  = atomic_load_explicit(&g_metrics.pkts_out_wire,  memory_order_relaxed);
    out->pkts_out_local = atomic_load_explicit(&g_metrics.pkts_out_local, memory_order_relaxed);
    out->pkts_in        = atomic_load_explicit(&g_metrics.pkts_in,        memory_order_relaxed);
    out->pkts_out       = atomic_load_explicit(&g_metrics.pkts_out,       memory_order_relaxed);
    out->bytes_in       = atomic_load_explicit(&g_metrics.bytes_in,       memory_order_relaxed);
    out->bytes_out      = atomic_load_explicit(&g_metrics.bytes_out,      memory_order_relaxed);
    out->frags_sent     = atomic_load_explicit(&g_metrics.frags_sent,     memory_order_relaxed);
    out->drop_filter    = atomic_load_explicit(&g_metrics.drop_filter,    memory_order_relaxed);
    out->drop_parse     = atomic_load_explicit(&g_metrics.drop_parse,     memory_order_relaxed);
    out->drop_pool      = atomic_load_explicit(&g_metrics.drop_pool,      memory_order_relaxed);
    out->drop_send      = atomic_load_explicit(&g_metrics.drop_send,      memory_order_relaxed);
    out->drop_oversize  = atomic_load_explicit(&g_metrics.drop_oversize,  memory_order_relaxed);
    out->drop_send_enobufs  = atomic_load_explicit(&g_metrics.drop_send_enobufs,  memory_order_relaxed);
    out->drop_send_eagain   = atomic_load_explicit(&g_metrics.drop_send_eagain,   memory_order_relaxed);
    out->drop_send_emsgsize = atomic_load_explicit(&g_metrics.drop_send_emsgsize, memory_order_relaxed);
    out->drop_send_enetdown = atomic_load_explicit(&g_metrics.drop_send_enetdown, memory_order_relaxed);
    out->drop_send_eperm    = atomic_load_explicit(&g_metrics.drop_send_eperm,    memory_order_relaxed);
    out->drop_send_other    = atomic_load_explicit(&g_metrics.drop_send_other,    memory_order_relaxed);
    out->recvmmsg_calls = atomic_load_explicit(&g_metrics.recvmmsg_calls, memory_order_relaxed);
    out->sendmmsg_calls = atomic_load_explicit(&g_metrics.sendmmsg_calls, memory_order_relaxed);
    out->sendto_calls   = atomic_load_explicit(&g_metrics.sendto_calls,   memory_order_relaxed);
    out->reloads_hot    = atomic_load_explicit(&g_metrics.reloads_hot,    memory_order_relaxed);
    out->reloads_hard   = atomic_load_explicit(&g_metrics.reloads_hard,   memory_order_relaxed);

    uint64_t now = metrics_now_ns();
    out->uptime_ns = (now > g_metrics.uptime_start_ns) ? (now - g_metrics.uptime_start_ns) : 0;

    out->log_emitted = atomic_load_explicit(&g_log_emitted, memory_order_relaxed);
    out->log_dropped = atomic_load_explicit(&g_log_dropped, memory_order_relaxed);
}

/* =====================================================================
 *  Periodic live status reporter
 *
 *  Designed to be called from the packet thread's outer loop.  It is
 *  cheap when not emitting (one monotonic clock + one comparison) and
 *  prints a single human-readable INFO line at most once per interval.
 *
 *  Rates are computed as delta(counter) / delta(time) since the last
 *  emission, so they reflect actual throughput, not lifetime averages.
 * ===================================================================== */

void metrics_reporter_init(metrics_reporter_t *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->last_ns = metrics_now_ns();
    metrics_snapshot(&r->last_snap);
}

/* Format a 64-bit count as "<= 4 digits + suffix" (3.5k, 1.2M, ...). */
static void fmt_count(uint64_t v, char *buf, size_t cap)
{
    if (v < 1000ull)                snprintf(buf, cap, "%llu",      (unsigned long long)v);
    else if (v < 1000000ull)        snprintf(buf, cap, "%.1fk",     (double)v / 1e3);
    else if (v < 1000000000ull)     snprintf(buf, cap, "%.2fM",     (double)v / 1e6);
    else                            snprintf(buf, cap, "%.2fG",     (double)v / 1e9);
}

/* Format a bytes-per-second rate as "<= 4 digits + B/s suffix". */
static void fmt_bps(double v, char *buf, size_t cap)
{
    if (v < 1024.0)              snprintf(buf, cap, "%.0f B/s",  v);
    else if (v < 1048576.0)      snprintf(buf, cap, "%.1f KB/s", v / 1024.0);
    else if (v < 1073741824.0)   snprintf(buf, cap, "%.2f MB/s", v / 1048576.0);
    else                         snprintf(buf, cap, "%.2f GB/s", v / 1073741824.0);
}

void metrics_fmt_rate(double v, char *buf, size_t cap) { fmt_bps(v, buf, cap); }

void metrics_fmt_bytes(uint64_t b, char *buf, size_t cap)
{
    double v = (double)b;
    if (b < 1024ull)             snprintf(buf, cap, "%llu B", (unsigned long long)b);
    else if (v < 1048576.0)      snprintf(buf, cap, "%.1f KB", v / 1024.0);
    else if (v < 1073741824.0)   snprintf(buf, cap, "%.2f MB", v / 1048576.0);
    else                         snprintf(buf, cap, "%.2f GB", v / 1073741824.0);
}

void metrics_fmt_duration_ns(uint64_t ns, char *buf, size_t cap)
{
    uint64_t sec = ns / 1000000000ull;
    uint64_t d = sec / 86400; sec %= 86400;
    uint64_t h = sec / 3600;  sec %= 3600;
    uint64_t m = sec / 60;    sec %= 60;
    if (d > 0) snprintf(buf, cap, "%llud %02llu:%02llu:%02llu",
                        (unsigned long long)d, (unsigned long long)h,
                        (unsigned long long)m, (unsigned long long)sec);
    else       snprintf(buf, cap, "%02llu:%02llu:%02llu",
                        (unsigned long long)h, (unsigned long long)m,
                        (unsigned long long)sec);
}

int metrics_reporter_tick(metrics_reporter_t *r,
                          const char *who,
                          const void *pool_void,
                          uint64_t interval_ns)
{
    if (!r) return 0;
    if (interval_ns == 0) interval_ns = 1000000000ull;  /* 1 s default */

    uint64_t now = metrics_now_ns();
    uint64_t elapsed = now - r->last_ns;
    if (elapsed < interval_ns) return 0;

    metrics_snapshot_t s;
    metrics_snapshot(&s);

    /* Compute per-second rates as deltas / elapsed-seconds.  Guard
     * against zero/very-small intervals (shouldn't happen in practice
     * but the math should still be defined). */
    double sec = (double)elapsed / 1e9;
    if (sec < 1e-6) sec = 1e-6;

    #define D(field)  ((s.field >= r->last_snap.field) \
                       ? (s.field - r->last_snap.field) : 0ull)

    uint64_t d_pkts_in       = D(pkts_in);
    uint64_t d_pkts_out      = D(pkts_out);
    uint64_t d_pkts_in_local = D(pkts_in_local);
    uint64_t d_pkts_in_wire  = D(pkts_in_wire);
    uint64_t d_pkts_out_loc  = D(pkts_out_local);
    uint64_t d_bytes_in      = D(bytes_in);
    uint64_t d_bytes_out     = D(bytes_out);
    uint64_t d_frags         = D(frags_sent);

    uint64_t d_dr_filter     = D(drop_filter);
    uint64_t d_dr_parse      = D(drop_parse);
    uint64_t d_dr_pool       = D(drop_pool);
    uint64_t d_dr_send       = D(drop_send);
    uint64_t d_dr_oversize   = D(drop_oversize);
    uint64_t d_dr_enobufs    = D(drop_send_enobufs);
    uint64_t d_dr_eagain     = D(drop_send_eagain);
    uint64_t d_dr_emsgsize   = D(drop_send_emsgsize);
    uint64_t d_dr_enetdown   = D(drop_send_enetdown);
    uint64_t d_dr_eperm      = D(drop_send_eperm);

    uint64_t d_recvmmsg      = D(recvmmsg_calls);
    uint64_t d_sendmmsg      = D(sendmmsg_calls);
    uint64_t d_sendto        = D(sendto_calls);

    uint64_t d_log_drop      = D(log_dropped);

    #undef D

    double rate_in  = (double)d_pkts_in  / sec;
    double rate_out = (double)d_pkts_out / sec;
    double bps_in   = (double)d_bytes_in  / sec;
    double bps_out  = (double)d_bytes_out / sec;

    char c_in[16], c_out[16], c_in_l[16], c_in_w[16], c_out_l[16];
    char c_frags[16];
    fmt_count((uint64_t)rate_in,  c_in,    sizeof(c_in));
    fmt_count((uint64_t)rate_out, c_out,   sizeof(c_out));
    fmt_count(d_pkts_in_local,    c_in_l,  sizeof(c_in_l));
    fmt_count(d_pkts_in_wire,     c_in_w,  sizeof(c_in_w));
    fmt_count(d_pkts_out_loc,     c_out_l, sizeof(c_out_l));
    fmt_count(d_frags,            c_frags, sizeof(c_frags));

    char r_in[24], r_out[24];
    fmt_bps(bps_in,  r_in,  sizeof(r_in));
    fmt_bps(bps_out, r_out, sizeof(r_out));

    /* Pool utilisation (if the caller provided one). */
    int pool_pct = -1;
    if (pool_void) {
        const pool_t *p = (const pool_t *)pool_void;
        uint32_t cap   = pool_capacity(p);
        uint32_t avail = pool_available(p);
        if (cap > 0) {
            uint32_t used = (avail > cap) ? 0 : (cap - avail);
            pool_pct = (int)((uint64_t)used * 100ull / cap);
        }
    }

    /* Headline line: always at INFO so the operator sees it without
     * cranking the level up.  Drop / pool / syscall detail lines emit
     * only when the corresponding interesting condition is present;
     * otherwise we keep the log compact. */
    char updur[32], tot_rx[24], tot_tx[24], poolbuf[24];
    metrics_fmt_duration_ns(s.uptime_ns, updur, sizeof(updur));
    metrics_fmt_bytes(s.bytes_in,  tot_rx, sizeof(tot_rx));
    metrics_fmt_bytes(s.bytes_out, tot_tx, sizeof(tot_tx));
    if (pool_pct >= 0) snprintf(poolbuf, sizeof(poolbuf), " | pool %d%%", pool_pct);
    else               poolbuf[0] = '\0';

    LOG_INFO("status %-6s up %-9s | rx %6s pps %10s | tx %6s pps %10s | total rx %9s tx %9s%s",
             who, updur, c_in, r_in, c_out, r_out, tot_rx, tot_tx, poolbuf);

    /* Only print the drops/syscalls line when something changed - keeps
     * the steady-state log noise low while still surfacing problems
     * the moment they appear. */
    if (d_dr_filter || d_dr_parse || d_dr_pool || d_dr_send ||
        d_dr_oversize || d_log_drop) {
        LOG_WARN("status[%s] drops/s: filter=%llu parse=%llu pool=%llu "
                 "send=%llu (ENOBUFS=%llu EAGAIN=%llu EMSGSIZE=%llu "
                 "ENETDOWN=%llu EPERM=%llu) oversize=%llu log_drop=%llu",
                 who,
                 (unsigned long long)d_dr_filter,
                 (unsigned long long)d_dr_parse,
                 (unsigned long long)d_dr_pool,
                 (unsigned long long)d_dr_send,
                 (unsigned long long)d_dr_enobufs,
                 (unsigned long long)d_dr_eagain,
                 (unsigned long long)d_dr_emsgsize,
                 (unsigned long long)d_dr_enetdown,
                 (unsigned long long)d_dr_eperm,
                 (unsigned long long)d_dr_oversize,
                 (unsigned long long)d_log_drop);
    }

    /* Syscall breakdown is interesting at DEBUG only - useful when
     * tracking down why the loop isn't batching as well as expected. */
    LOG_DEBUG("status[%s] syscalls/s: recvmmsg=%llu sendmmsg=%llu sendto=%llu",
              who,
              (unsigned long long)d_recvmmsg,
              (unsigned long long)d_sendmmsg,
              (unsigned long long)d_sendto);

    r->last_ns = now;
    r->last_snap = s;
    return 1;
}
