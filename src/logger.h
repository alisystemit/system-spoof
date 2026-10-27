#ifndef INJSPOOF_LOGGER_H
#define INJSPOOF_LOGGER_H

#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

/* ====================================================================
 *  injspoof logger
 *
 *  Goals
 *  - Standards-compliant: levels TRACE/DEBUG/INFO/WARN/ERROR/FATAL
 *  - Non-blocking on the hot path: SPSC ring -> background writer thread
 *  - Drivers: console (stderr), file (size-rotation), syslog, composite
 *  - Format string: Python-style "%(asctime)s %(levelname)s %(message)s"
 *    parsed once at init into a precompiled segment list
 *  - Drop-on-full backpressure (counter exposed via metrics)
 *  - Thread-safe; hot-path uses only an atomic seq-claim + memcpy
 *
 *  Note: enum constants use the LVL_ prefix to avoid colliding with
 *  syslog.h's LOG_INFO/LOG_DEBUG/etc. object-like macros.
 * ==================================================================== */

typedef enum {
    LVL_TRACE = 0,
    LVL_DEBUG = 1,
    LVL_INFO  = 2,
    LVL_WARN  = 3,
    LVL_ERROR = 4,
    LVL_FATAL = 5,
} log_level_t;

typedef enum {
    LOG_DRV_CONSOLE = 0x1,
    LOG_DRV_FILE    = 0x2,
    LOG_DRV_SYSLOG  = 0x4,
} log_driver_mask_t;

typedef struct {
    log_level_t level;
    unsigned    drivers;          /* bitmask of log_driver_mask_t */
    const char *file_path;        /* used when LOG_DRV_FILE */
    const char *format;           /* Python-style placeholders */
    const char *name;             /* logger name (default: "injspoof") */
    const char *syslog_ident;     /* used when LOG_DRV_SYSLOG */
    uint64_t    file_rotate_size; /* rotate after N bytes (0 = no rotation) */
    int         file_rotate_keep; /* number of rotated files to keep */
    int         console_stderr;   /* 1: stderr, 0: stdout */
    int         async;            /* 1: spawn writer thread, 0: synchronous */
    size_t      ring_capacity;    /* bytes of ring buffer (default 1MB) */
} logger_config_t;

/* Initialize the global logger. Safe to call once at startup. */
int  logger_init(const logger_config_t *cfg);

/* Reconfigure on the fly (hot reload). */
int  logger_reconfigure(const logger_config_t *cfg);

/* Stop async writer (if any) and flush. */
void logger_shutdown(void);

/* Flush the async ring buffer (blocking). No-op if not async. */
void logger_flush(void);

/* Set/get the current minimum level (atomic, lock-free). */
void        logger_set_level(log_level_t lvl);
log_level_t logger_get_level(void);

/* Parse a level name. Returns the matching enum or LVL_INFO on unknown input. */
log_level_t logger_level_from_string(const char *s);
const char *logger_level_to_string(log_level_t lvl);

/* Hot-path log emission (use macros below). */
void logger_log(log_level_t lvl,
                const char *file,
                int line,
                const char *func,
                const char *fmt, ...) __attribute__((format(printf, 5, 6)));

void logger_vlog(log_level_t lvl,
                 const char *file,
                 int line,
                 const char *func,
                 const char *fmt, va_list ap);

/* Counters (atomic) - exposed for /api/v1/stats */
extern _Atomic uint64_t g_log_emitted;
extern _Atomic uint64_t g_log_dropped;

/* Strip path prefix, keep only filename - resolved at compile time. */
#ifndef LOG_FILE_SHORT
#  define LOG_FILE_SHORT \
    (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

/* Public emission macros. */
extern _Atomic int g_logger_level_cache;

#define LOGGER_ENABLED(lvl) \
    __builtin_expect((int)(lvl) >= atomic_load_explicit(&g_logger_level_cache, memory_order_relaxed), 0)

#define LOG_LOG(lvl, fmt, ...) do { \
        if (LOGGER_ENABLED(lvl)) \
            logger_log((lvl), LOG_FILE_SHORT, __LINE__, __func__, (fmt), ##__VA_ARGS__); \
    } while (0)

#define LOG_TRACE(fmt, ...) LOG_LOG(LVL_TRACE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG_LOG(LVL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG_LOG(LVL_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG_LOG(LVL_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG_LOG(LVL_ERROR, fmt, ##__VA_ARGS__)

/* LOG_FATAL: logs the message, flushes the ring, then exits. */
#define LOG_FATAL(fmt, ...) do { \
        logger_log(LVL_FATAL, LOG_FILE_SHORT, __LINE__, __func__, (fmt), ##__VA_ARGS__); \
        logger_flush(); \
        _exit(1); \
    } while (0)

/* Convenience for errno reporting (thread-safe strerror_r). */
#define LOG_PERROR(msg) do { \
        if (LOGGER_ENABLED(LVL_ERROR)) { \
            char _ebuf[128]; \
            const char *_estr = logger_strerror(errno, _ebuf, sizeof(_ebuf)); \
            logger_log(LVL_ERROR, LOG_FILE_SHORT, __LINE__, __func__, \
                       "%s: %s", (msg), _estr); \
        } \
    } while (0)

/* Rate-limited debug macro: emits at most once per `interval_ms` ms.
 * Uses a static local variable for the last emission timestamp.
 * Thread-safe via CAS on the timestamp. */
#define LOG_DEBUG_RATE(interval_ms, fmt, ...) do { \
        if (LOGGER_ENABLED(LVL_DEBUG)) { \
            static _Atomic uint64_t _last_ns = 0; \
            struct timespec _ts; \
            clock_gettime(CLOCK_MONOTONIC, &_ts); \
            uint64_t _now = (uint64_t)_ts.tv_sec * 1000000000ull + (uint64_t)_ts.tv_nsec; \
            uint64_t _prev = atomic_load_explicit(&_last_ns, memory_order_relaxed); \
            if (_now - _prev >= (uint64_t)(interval_ms) * 1000000ull) { \
                if (atomic_compare_exchange_weak_explicit(&_last_ns, &_prev, _now, \
                        memory_order_relaxed, memory_order_relaxed)) \
                    logger_log(LVL_DEBUG, LOG_FILE_SHORT, __LINE__, __func__, (fmt), ##__VA_ARGS__); \
            } \
        } \
    } while (0)

/* Thread-safe strerror wrapper. */
const char *logger_strerror(int errnum, char *buf, size_t buflen);

#endif /* INJSPOOF_LOGGER_H */
