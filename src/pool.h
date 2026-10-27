#ifndef INJSPOOF_POOL_H
#define INJSPOOF_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/*
 * Lock-free fixed-size memory pool.
 *
 * Pre-allocates a contiguous, page-aligned block of buffers to avoid
 * malloc/free on the hot path. Uses atomic ops for thread safety.
 *
 * Buffer size raised to jumbo-frame ceiling (9216 B) so a single
 * buffer can hold any received raw packet plus minor headroom.
 */

#define POOL_DEFAULT_COUNT   1024
#define POOL_DEFAULT_BUFSIZE 9216   /* jumbo-safe (MTU 9000 + headers) */

typedef struct {
    uint8_t  *block;
    uint32_t *free_stack;
    _Atomic uint32_t top;
    uint32_t  count;
    uint32_t  buf_size;

    /* Statistics (relaxed atomics) */
    _Atomic uint64_t alloc_hits;
    _Atomic uint64_t alloc_misses;
} pool_t;

int  pool_init(pool_t *pool, uint32_t count, uint32_t buf_size);
void *pool_alloc(pool_t *pool);
void pool_free(pool_t *pool, void *ptr);
void pool_destroy(pool_t *pool);

/* Current available count (snapshot - may race; for stats only). */
uint32_t pool_available(const pool_t *pool);
uint32_t pool_capacity(const pool_t *pool);
uint64_t pool_alloc_hits(const pool_t *pool);
uint64_t pool_alloc_misses(const pool_t *pool);

#endif /* INJSPOOF_POOL_H */
