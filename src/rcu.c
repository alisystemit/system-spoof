#include "rcu.h"

#include <stdatomic.h>
#include <time.h>

static _Atomic unsigned long g_qs[RCU_MAX_READERS];
static _Atomic int           g_nreaders = 0;

int rcu_register(void)
{
    int id = atomic_fetch_add_explicit(&g_nreaders, 1, memory_order_acq_rel);
    if (id >= RCU_MAX_READERS) return -1;   /* over capacity: opt out */
    return id;
}

void rcu_quiescent(int id)
{
    if (id < 0) return;
    atomic_fetch_add_explicit(&g_qs[id], 1ul, memory_order_release);
}

void rcu_synchronize(void)
{
    int n = atomic_load_explicit(&g_nreaders, memory_order_acquire);
    if (n > RCU_MAX_READERS) n = RCU_MAX_READERS;

    unsigned long snap[RCU_MAX_READERS];
    for (int i = 0; i < n; i++)
        snap[i] = atomic_load_explicit(&g_qs[i], memory_order_acquire);

    for (int i = 0; i < n; i++) {
        unsigned spins = 0;
        /* Wait until reader i passes a quiescent state strictly after our
         * snapshot, i.e. it has finished any iteration that may have been
         * using the old pointer. */
        while (atomic_load_explicit(&g_qs[i], memory_order_acquire) <= snap[i]) {
            struct timespec ts = { 0, 200 * 1000 };   /* 200 us */
            nanosleep(&ts, NULL);
            if (++spins > 50000u) break;               /* ~10s safety cap */
        }
    }
}
