#ifndef INJSPOOF_RCU_H
#define INJSPOOF_RCU_H

/* ====================================================================
 *  Minimal quiescent-state-based reclamation (QSBR).
 *
 *  Used to safely free an old config_t after an atomic hot-reload swap
 *  while the packet thread and AF_XDP worker threads may still hold a
 *  pointer to it.  Each reader registers once and calls rcu_quiescent()
 *  at a point in its loop where it holds no protected pointer.  The
 *  writer calls rcu_synchronize() (cold path; may block briefly) after
 *  publishing the new pointer, then frees the old one.
 * ==================================================================== */

#define RCU_MAX_READERS 96   /* 1 packet thread + up to 64 xsk workers + margin */

/* Register the calling thread as a reader. Returns an id (>=0) or -1. */
int  rcu_register(void);

/* Announce a quiescent state for reader `id` (no protected ptr held). */
void rcu_quiescent(int id);

/* Block until every registered reader has passed a quiescent state
 * since this call began. Safe to free reclaimed memory afterwards. */
void rcu_synchronize(void);

#endif /* INJSPOOF_RCU_H */
