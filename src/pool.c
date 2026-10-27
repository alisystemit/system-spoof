#include "pool.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

int pool_init(pool_t *pool, uint32_t count, uint32_t buf_size)
{
    if (!pool || count == 0 || buf_size == 0) return -1;

    pool->count    = count;
    pool->buf_size = buf_size;
    atomic_store(&pool->alloc_hits, 0);
    atomic_store(&pool->alloc_misses, 0);

    /* Page-aligned for kernel-friendliness */
    size_t bytes = (size_t)count * buf_size;
    pool->block = aligned_alloc(4096, ((bytes + 4095) & ~(size_t)4095));
    if (!pool->block) {
        LOG_PERROR("pool: aligned_alloc block");
        return -1;
    }

    pool->free_stack = malloc((size_t)count * sizeof(uint32_t));
    if (!pool->free_stack) {
        free(pool->block);
        pool->block = NULL;
        LOG_PERROR("pool: malloc free_stack");
        return -1;
    }

    for (uint32_t i = 0; i < count; i++)
        pool->free_stack[i] = i;
    atomic_store(&pool->top, count);

    LOG_INFO("pool: %u buffers x %u B = %zu KiB",
             count, buf_size, bytes / 1024);
    return 0;
}

void *pool_alloc(pool_t *pool)
{
    uint32_t cur_top, new_top, idx;
    for (;;) {
        cur_top = atomic_load_explicit(&pool->top, memory_order_acquire);
        if (__builtin_expect(cur_top == 0, 0)) {
            atomic_fetch_add_explicit(&pool->alloc_misses, 1, memory_order_relaxed);
            return NULL;
        }
        new_top = cur_top - 1;
        if (atomic_compare_exchange_weak_explicit(
                &pool->top, &cur_top, new_top,
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
    idx = pool->free_stack[new_top];
    atomic_fetch_add_explicit(&pool->alloc_hits, 1, memory_order_relaxed);
    return pool->block + ((size_t)idx * pool->buf_size);
}

void pool_free(pool_t *pool, void *ptr)
{
    if (!ptr || !pool || !pool->block) return;
    uint8_t *p = ptr;
    if (__builtin_expect(p < pool->block ||
                         p >= pool->block + (size_t)pool->count * pool->buf_size, 0)) {
        LOG_ERROR("pool: free pointer outside pool range");
        return;
    }
    size_t offset = (size_t)(p - pool->block);
    if (offset % pool->buf_size != 0) {
        LOG_ERROR("pool: misaligned free");
        return;
    }
    uint32_t idx = (uint32_t)(offset / pool->buf_size);

    uint32_t cur_top, new_top;
    for (;;) {
        cur_top = atomic_load_explicit(&pool->top, memory_order_acquire);
        if (__builtin_expect(cur_top >= pool->count, 0)) {
            LOG_ERROR("pool: double free");
            return;
        }
        new_top = cur_top + 1;
        if (atomic_compare_exchange_weak_explicit(
                &pool->top, &cur_top, new_top,
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
    pool->free_stack[cur_top] = idx;
}

void pool_destroy(pool_t *pool)
{
    if (!pool) return;
    free(pool->block);
    free(pool->free_stack);
    memset(pool, 0, sizeof(*pool));
}

uint32_t pool_available(const pool_t *pool)
{
    return atomic_load_explicit(&((pool_t *)pool)->top, memory_order_relaxed);
}
uint32_t pool_capacity(const pool_t *pool)  { return pool->count; }
uint64_t pool_alloc_hits(const pool_t *pool)
{
    return atomic_load_explicit(&((pool_t *)pool)->alloc_hits, memory_order_relaxed);
}
uint64_t pool_alloc_misses(const pool_t *pool)
{
    return atomic_load_explicit(&((pool_t *)pool)->alloc_misses, memory_order_relaxed);
}
