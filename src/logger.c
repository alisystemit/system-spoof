/* ====================================================================
 *  injspoof — logger implementation
 *
 *  Architecture
 *  ------------
 *  Hot path (any thread that calls LOG_*):
 *      1. Cheap level check via relaxed atomic.
 *      2. Format the message into a stack buffer using vsnprintf.
 *      3. Claim a slot in a lock-free MPSC ring (one CAS).
 *      4. Copy the record into the ring; signal the writer via eventfd
 *         only if the ring transitioned from empty to non-empty
 *         (amortised - most claims do not signal).
 *
 *  Writer thread:
 *      1. epoll_wait on the eventfd.
 *      2. Drain the ring in batches, format each record using the
 *         pre-parsed format segments, writev() to all active drivers.
 *      3. Rotates the file when size threshold is crossed.
 *
 *  Drop-on-full: if the ring lacks space, the record is dropped and
 *  g_log_dropped is incremented. This guarantees the producer never
 *  blocks the packet loop, even if disk I/O stalls.
 * ==================================================================== */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* ---------- Public atomics ---------- */
_Atomic uint64_t g_log_emitted = 0;
_Atomic uint64_t g_log_dropped = 0;
_Atomic int      g_logger_level_cache = LVL_INFO;

/* ---------- Internal constants ---------- */
#define LOGGER_MAX_MSG       2048           /* per-record payload */
#define LOGGER_DEFAULT_RING  (1u << 20)     /* 1 MiB */
#define LOGGER_MAX_SEGMENTS  32
#define LOGGER_BATCH         128
#define LOGGER_DEFAULT_KEEP  5

/* ---------- Format segments ---------- */
typedef enum {
    SEG_LITERAL = 0,
    SEG_ASCTIME,    /* %(asctime)s   - YYYY-MM-DD HH:MM:SS.mmm */
    SEG_LEVELNAME,  /* %(levelname)s */
    SEG_LEVELNO,    /* %(levelno)d   */
    SEG_NAME,       /* %(name)s      */
    SEG_MESSAGE,    /* %(message)s   */
    SEG_PATHNAME,   /* %(pathname)s  */
    SEG_FILENAME,   /* %(filename)s  - alias for pathname (short) */
    SEG_LINENO,     /* %(lineno)d    */
    SEG_FUNCNAME,   /* %(funcName)s  */
    SEG_THREAD,     /* %(threadid)d  */
    SEG_PROCESS,    /* %(process)d   */
    SEG_NEWLINE,    /* literal '\n' inserted at end if not present */
} seg_kind_t;

typedef struct {
    seg_kind_t kind;
    const char *literal;  /* pointer into the strdup'd format string */
    uint16_t    literal_len;
} segment_t;

/* ---------- Record on the ring ---------- */
typedef struct __attribute__((aligned(64))) {
    /* Header */
    uint16_t    msg_len;            /* bytes of msg used */
    uint16_t    file_len;
    uint16_t    func_len;
    uint8_t     level;
    uint8_t     _pad0;
    int32_t     line;
    int32_t     tid;
    struct timespec ts;             /* CLOCK_REALTIME for asctime */
    /* Payload: msg followed by file string followed by func string */
    char        payload[LOGGER_MAX_MSG];
} log_record_t;

/* ---------- SPSC-friendly ring of fixed-size records (MPSC safe via CAS) ---------- */
typedef struct {
    log_record_t *records;
    uint32_t      capacity;          /* power of two */
    uint32_t      mask;
    _Atomic uint32_t head;           /* write index */
    _Atomic uint32_t tail;           /* read index (writer thread) */
} log_ring_t;

/* ---------- Global state ---------- */
typedef struct {
    /* Configuration */
    char        name[64];
    char        format[256];
    segment_t   segments[LOGGER_MAX_SEGMENTS];
    int         segment_count;
    int         has_newline;        /* format ends with newline? */

    unsigned    drivers;
    int         console_fd;
    int         console_is_tty;
    int         file_fd;
    char        file_path[256];
    uint64_t    file_rotate_size;
    int         file_rotate_keep;
    _Atomic uint64_t file_bytes;
    int         async;
    char        syslog_ident[64];

    /* Async machinery */
    log_ring_t  ring;
    int         efd;                /* eventfd to wake writer */
    pthread_t   writer_tid;
    _Atomic int writer_running;
    _Atomic int reconfig_pending;
    pthread_mutex_t reconfig_mtx;
} logger_state_t;

static logger_state_t g_log = { 0 };
static _Atomic int    g_log_initialized = 0;

/* ====================================================================
 *  Helpers
 * ==================================================================== */

const char *logger_strerror(int errnum, char *buf, size_t buflen)
{
    if (!buf || buflen == 0) return "";
#if defined(__GLIBC__) && (_GNU_SOURCE)
    /* GNU strerror_r returns char* (may not use buf) */
    return strerror_r(errnum, buf, buflen);
#else
    /* XSI strerror_r returns int */
    if (strerror_r(errnum, buf, buflen) != 0)
        snprintf(buf, buflen, "errno %d", errnum);
    return buf;
#endif
}

static inline int32_t fast_gettid(void)
{
#ifdef SYS_gettid
    return (int32_t)syscall(SYS_gettid);
#else
    return (int32_t)getpid();
#endif
}

static uint32_t next_pow2(uint32_t v)
{
    if (v < 2) return 2;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4;
    v |= v >> 8; v |= v >> 16;
    return v + 1;
}

log_level_t logger_level_from_string(const char *s)
{
    if (!s) return LVL_INFO;
    if      (!strcasecmp(s, "trace")) return LVL_TRACE;
    else if (!strcasecmp(s, "debug")) return LVL_DEBUG;
    else if (!strcasecmp(s, "info"))  return LVL_INFO;
    else if (!strcasecmp(s, "warn") || !strcasecmp(s, "warning")) return LVL_WARN;
    else if (!strcasecmp(s, "error") || !strcasecmp(s, "err")) return LVL_ERROR;
    else if (!strcasecmp(s, "fatal") || !strcasecmp(s, "crit") || !strcasecmp(s, "critical"))
        return LVL_FATAL;
    return LVL_INFO;
}

const char *logger_level_to_string(log_level_t lvl)
{
    switch (lvl) {
        case LVL_TRACE: return "TRACE";
        case LVL_DEBUG: return "DEBUG";
        case LVL_INFO:  return "INFO";
        case LVL_WARN:  return "WARN";
        case LVL_ERROR: return "ERROR";
        case LVL_FATAL: return "FATAL";
        default:        return "?";
    }
}

void logger_set_level(log_level_t lvl)
{
    atomic_store_explicit(&g_logger_level_cache, (int)lvl, memory_order_relaxed);
}

log_level_t logger_get_level(void)
{
    return (log_level_t)atomic_load_explicit(&g_logger_level_cache, memory_order_relaxed);
}

/* ====================================================================
 *  Format string parsing
 * ==================================================================== */

static seg_kind_t classify_placeholder(const char *name, size_t n)
{
    #define M(s, k) if (n == sizeof(s)-1 && !memcmp(name, s, n)) return k;
    M("asctime",   SEG_ASCTIME);
    M("levelname", SEG_LEVELNAME);
    M("levelno",   SEG_LEVELNO);
    M("name",      SEG_NAME);
    M("message",   SEG_MESSAGE);
    M("msg",       SEG_MESSAGE);
    M("pathname",  SEG_PATHNAME);
    M("filename",  SEG_FILENAME);
    M("lineno",    SEG_LINENO);
    M("funcName",  SEG_FUNCNAME);
    M("funcname",  SEG_FUNCNAME);
    M("threadid",  SEG_THREAD);
    M("thread",    SEG_THREAD);
    M("process",   SEG_PROCESS);
    M("pid",       SEG_PROCESS);
    #undef M
    return SEG_LITERAL; /* unknown: keep as literal */
}

/* Parse a Python-style format string into segments.
 * Caller owns the format string lifetime (must outlive the segments). */
static void parse_format(const char *fmt,
                         segment_t *out, int *out_count, int max,
                         int *has_newline)
{
    *out_count = 0;
    if (has_newline) *has_newline = 0;
    if (!fmt) return;

    const char *p = fmt;
    const char *lit_start = p;

    while (*p) {
        if (p[0] == '%' && p[1] == '(') {
            /* Flush literal */
            if (p > lit_start && *out_count < max) {
                out[*out_count].kind        = SEG_LITERAL;
                out[*out_count].literal     = lit_start;
                out[*out_count].literal_len = (uint16_t)(p - lit_start);
                (*out_count)++;
            }
            /* Find closing ')X' where X is type spec (s, d, ...) */
            const char *name = p + 2;
            const char *close = strchr(name, ')');
            if (!close || !close[1]) {
                /* malformed - treat as literal */
                lit_start = p; p++;
                continue;
            }
            seg_kind_t k = classify_placeholder(name, (size_t)(close - name));
            if (k == SEG_LITERAL) {
                /* unknown placeholder - keep literal */
                lit_start = p;
            } else {
                if (*out_count < max) {
                    out[*out_count].kind        = k;
                    out[*out_count].literal     = NULL;
                    out[*out_count].literal_len = 0;
                    (*out_count)++;
                }
                lit_start = close + 2;
            }
            p = close + 2;
            continue;
        }
        p++;
    }
    if (p > lit_start && *out_count < max) {
        out[*out_count].kind        = SEG_LITERAL;
        out[*out_count].literal     = lit_start;
        out[*out_count].literal_len = (uint16_t)(p - lit_start);
        (*out_count)++;
    }
    if (has_newline && p > fmt && p[-1] == '\n')
        *has_newline = 1;
}

/* ====================================================================
 *  Ring buffer
 * ==================================================================== */

static int ring_init(log_ring_t *r, size_t bytes)
{
    /* Each slot is a fixed-size record; bytes is the cap of raw memory. */
    uint32_t slots = (uint32_t)(bytes / sizeof(log_record_t));
    if (slots < 16) slots = 16;
    slots = next_pow2(slots);
    r->records = aligned_alloc(64, (size_t)slots * sizeof(log_record_t));
    if (!r->records) return -1;
    memset(r->records, 0, (size_t)slots * sizeof(log_record_t));
    r->capacity = slots;
    r->mask     = slots - 1;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
    return 0;
}

static void ring_free(log_ring_t *r)
{
    free(r->records);
    r->records = NULL;
}

/* MPSC enqueue with seq-based slot ownership.
 * Returns the claimed slot or NULL if the ring is full. */
static log_record_t *ring_claim(log_ring_t *r)
{
    uint32_t head, tail, next;
    for (;;) {
        head = atomic_load_explicit(&r->head, memory_order_relaxed);
        tail = atomic_load_explicit(&r->tail, memory_order_acquire);
        next = head + 1;
        if (next - tail > r->capacity)
            return NULL; /* full */
        if (atomic_compare_exchange_weak_explicit(
                &r->head, &head, next,
                memory_order_acq_rel, memory_order_relaxed))
            return &r->records[head & r->mask];
    }
}

/* Consumer side - called only from the writer thread. */
static int ring_drain(log_ring_t *r, log_record_t **out, int max)
{
    uint32_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&r->head, memory_order_acquire);
    int n = 0;
    while (tail != head && n < max) {
        out[n++] = &r->records[tail & r->mask];
        tail++;
    }
    /* Note: actual tail advance happens after caller has consumed. */
    return n;
}

static void ring_advance(log_ring_t *r, int n)
{
    if (n <= 0) return;
    uint32_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
    atomic_store_explicit(&r->tail, tail + (uint32_t)n, memory_order_release);
}

/* ====================================================================
 *  Output drivers
 * ==================================================================== */

static void file_rotate(void)
{
    if (g_log.file_fd < 0) return;
    close(g_log.file_fd);

    /* Rotate suffixes: .N-1 -> .N */
    char a[300], b[300];
    int keep = g_log.file_rotate_keep > 0 ? g_log.file_rotate_keep : LOGGER_DEFAULT_KEEP;
    for (int i = keep - 1; i >= 1; i--) {
        snprintf(a, sizeof(a), "%s.%d", g_log.file_path, i);
        snprintf(b, sizeof(b), "%s.%d", g_log.file_path, i + 1);
        rename(a, b); /* may not exist; ignore */
    }
    snprintf(a, sizeof(a), "%s.1", g_log.file_path);
    rename(g_log.file_path, a);

    g_log.file_fd = open(g_log.file_path,
                         O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    atomic_store_explicit(&g_log.file_bytes, 0, memory_order_relaxed);
}

static int syslog_priority(log_level_t lvl)
{
    switch (lvl) {
        case LVL_TRACE: case LVL_DEBUG: return LOG_DEBUG;
        case LVL_INFO:                  return LOG_INFO;
        case LVL_WARN:                  return LOG_WARNING;
        case LVL_ERROR:                 return LOG_ERR;
        case LVL_FATAL:                 return LOG_CRIT;
        default:                        return LOG_INFO;
    }
}

/* ---- ANSI colours (console TTY only) ----
 *
 * Each log line is painted in several colours so that its parts are visually
 * separated, following common logging conventions:
 *
 *   timestamp   -> white                (neutral, always the same)
 *   logger name -> dim grey             (low-salience context)
 *   level label -> bold, severity hue   (the at-a-glance signal)
 *   message     -> severity hue         (debug=blue, info=green,
 *                                         warn=yellow, error/fatal=red)
 *   separators  -> dim grey             (punctuation between fields)
 *   metadata    -> dim grey             (file:line, func, tid, pid)
 */
#define C_RESET   "\033[0m"
#define C_TIME    "\033[97m"   /* bright white */
#define C_NAME    "\033[90m"   /* dim grey     */
#define C_SEP     "\033[90m"   /* dim grey     */
#define C_META    "\033[90m"   /* dim grey     */

/* Bold severity colour for the level label. */
static const char *level_color(log_level_t lvl)
{
    switch (lvl) {
        case LVL_TRACE: return "\033[1;90m"; /* bold grey   */
        case LVL_DEBUG: return "\033[1;34m"; /* bold blue   */
        case LVL_INFO:  return "\033[1;32m"; /* bold green  */
        case LVL_WARN:  return "\033[1;33m"; /* bold yellow */
        case LVL_ERROR: return "\033[1;31m"; /* bold red    */
        case LVL_FATAL: return "\033[1;97;41m"; /* white on red */
        default:        return C_RESET;
    }
}

/* Non-bold severity colour for the message body. */
static const char *msg_color(log_level_t lvl)
{
    switch (lvl) {
        case LVL_TRACE: return "\033[90m";   /* grey   */
        case LVL_DEBUG: return "\033[34m";   /* blue   */
        case LVL_INFO:  return "\033[32m";   /* green  */
        case LVL_WARN:  return "\033[33m";   /* yellow */
        case LVL_ERROR: return "\033[31m";   /* red    */
        case LVL_FATAL: return "\033[1;31m"; /* bold red */
        default:        return C_RESET;
    }
}

/* Colour for a given segment, or NULL for "no colour". */
static const char *seg_color(seg_kind_t k, log_level_t lvl)
{
    switch (k) {
        case SEG_ASCTIME:   return C_TIME;
        case SEG_LEVELNAME:
        case SEG_LEVELNO:   return level_color(lvl);
        case SEG_NAME:      return C_NAME;
        case SEG_MESSAGE:   return msg_color(lvl);
        case SEG_PATHNAME:
        case SEG_FILENAME:
        case SEG_LINENO:
        case SEG_FUNCNAME:
        case SEG_THREAD:
        case SEG_PROCESS:   return C_META;
        case SEG_LITERAL:   return C_SEP;
        default:            return NULL;
    }
}

/* Fixed-width (5 char) level label for column alignment. */
static const char *level_padded(log_level_t lvl)
{
    switch (lvl) {
        case LVL_TRACE: return "TRACE";
        case LVL_DEBUG: return "DEBUG";
        case LVL_INFO:  return "INFO ";
        case LVL_WARN:  return "WARN ";
        case LVL_ERROR: return "ERROR";
        case LVL_FATAL: return "FATAL";
        default:        return "?    ";
    }
}

/* Render a record's segments into `line`.
 *
 * When `colorize` is non-zero, each segment is wrapped in its own ANSI colour
 * (and reset) so the parts of the line are visually distinct; this form is
 * used only for a TTY console. When zero, a plain line is produced for files,
 * syslog and non-TTY consoles. Returns the number of bytes written (a trailing
 * '\n' is appended unless the format already supplies one). */
static size_t render_line(char *line, size_t linesz,
                          const log_record_t *rec,
                          const char *asctime_buf,
                          const char *msg, const char *file, const char *func,
                          int colorize)
{
    size_t off = 0;
    const log_level_t lvl = (log_level_t)rec->level;

    #define APPEND(src, n) do { \
        size_t _n = (n); \
        if (_n > linesz - off - 1) _n = linesz - off - 1; \
        memcpy(line + off, (src), _n); off += _n; \
    } while (0)
    #define APPEND_STR(s) do { const char *_s = (s); APPEND(_s, strlen(_s)); } while (0)
    #define APPEND_INT(v) do { char _ib[16]; int _il = snprintf(_ib, sizeof(_ib), "%d", (int)(v)); APPEND(_ib, _il); } while (0)

    for (int i = 0; i < g_log.segment_count; i++) {
        const segment_t *s = &g_log.segments[i];
        const char *col = colorize ? seg_color(s->kind, lvl) : NULL;
        if (col) APPEND_STR(col);
        switch (s->kind) {
            case SEG_LITERAL:   APPEND(s->literal, s->literal_len); break;
            case SEG_ASCTIME:   APPEND_STR(asctime_buf); break;
            case SEG_LEVELNAME: APPEND_STR(level_padded(lvl)); break;
            case SEG_LEVELNO:   APPEND_INT(rec->level); break;
            case SEG_NAME:      APPEND_STR(g_log.name); break;
            case SEG_MESSAGE:   APPEND(msg, rec->msg_len); break;
            case SEG_PATHNAME:
            case SEG_FILENAME:  APPEND(file, rec->file_len); break;
            case SEG_LINENO:    APPEND_INT(rec->line); break;
            case SEG_FUNCNAME:  APPEND(func, rec->func_len); break;
            case SEG_THREAD:    APPEND_INT(rec->tid); break;
            case SEG_PROCESS:   APPEND_INT(getpid()); break;
            case SEG_NEWLINE:   break;
        }
        if (col) APPEND_STR(C_RESET);
    }
    if (!g_log.has_newline && off < linesz - 1)
        line[off++] = '\n';

    #undef APPEND
    #undef APPEND_STR
    #undef APPEND_INT
    return off;
}

/* Format and emit a single record to all configured drivers. */
static void emit_record(const log_record_t *rec)
{
    char asctime_buf[40] = "";

    const char *msg  = rec->payload;
    const char *file = rec->payload + rec->msg_len;
    const char *func = file + rec->file_len;

    /* Pre-format asctime once if requested */
    int need_asctime = 0;
    for (int i = 0; i < g_log.segment_count; i++)
        if (g_log.segments[i].kind == SEG_ASCTIME) { need_asctime = 1; break; }
    if (need_asctime) {
        struct tm tm;
        localtime_r(&rec->ts.tv_sec, &tm);
        int mmm = (int)(rec->ts.tv_nsec / 1000000);
        snprintf(asctime_buf, sizeof(asctime_buf),
                 "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, mmm);
    }

    const int console     = (g_log.drivers & LOG_DRV_CONSOLE) != 0;
    const int color        = console && g_log.console_is_tty;
    const int need_plain   = (g_log.drivers & (LOG_DRV_FILE | LOG_DRV_SYSLOG)) ||
                             (console && !g_log.console_is_tty);

    /* Plain line for file / syslog / non-TTY console. */
    char line[LOGGER_MAX_MSG + 512];
    size_t off = 0;
    if (need_plain)
        off = render_line(line, sizeof(line), rec, asctime_buf, msg, file, func, 0);

    /* Console */
    if (console) {
        if (color) {
            /* Colourised buffer needs extra room for the ANSI escapes. */
            char cline[LOGGER_MAX_MSG + 1024];
            size_t coff = render_line(cline, sizeof(cline), rec, asctime_buf,
                                      msg, file, func, 1);
            (void)!write(g_log.console_fd, cline, coff);
        } else {
            (void)!write(g_log.console_fd, line, off);
        }
    }
    if ((g_log.drivers & LOG_DRV_FILE) && g_log.file_fd >= 0) {
        ssize_t w = write(g_log.file_fd, line, off);
        if (w > 0) {
            uint64_t b = atomic_fetch_add_explicit(&g_log.file_bytes,
                                                   (uint64_t)w,
                                                   memory_order_relaxed) + (uint64_t)w;
            if (g_log.file_rotate_size && b >= g_log.file_rotate_size)
                file_rotate();
        }
    }
    if (g_log.drivers & LOG_DRV_SYSLOG) {
        /* syslog() is internally locked but acceptable on the writer thread */
        syslog(syslog_priority((log_level_t)rec->level), "%.*s",
               (int)(off - (off > 0 && line[off-1] == '\n' ? 1 : 0)),
               line);
    }
}

/* ====================================================================
 *  Writer thread
 * ==================================================================== */

static void *writer_thread(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "log-writer");

    /* Lowest scheduling priority - never compete with packet loop */
    struct sched_param sp = { .sched_priority = 0 };
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) return NULL;
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = g_log.efd };
    epoll_ctl(ep, EPOLL_CTL_ADD, g_log.efd, &ev);

    log_record_t *batch[LOGGER_BATCH];

    while (atomic_load_explicit(&g_log.writer_running, memory_order_acquire)) {
        struct epoll_event events[1];
        int n = epoll_wait(ep, events, 1, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        uint64_t v;
        (void)!read(g_log.efd, &v, sizeof(v));

        for (;;) {
            int got = ring_drain(&g_log.ring, batch, LOGGER_BATCH);
            if (got == 0) break;
            for (int i = 0; i < got; i++)
                emit_record(batch[i]);
            ring_advance(&g_log.ring, got);
        }
    }

    /* Final drain on shutdown */
    for (;;) {
        int got = ring_drain(&g_log.ring, batch, LOGGER_BATCH);
        if (got == 0) break;
        for (int i = 0; i < got; i++)
            emit_record(batch[i]);
        ring_advance(&g_log.ring, got);
    }

    close(ep);
    return NULL;
}

static void writer_signal(void)
{
    uint64_t one = 1;
    (void)!write(g_log.efd, &one, sizeof(one));
}

/* ====================================================================
 *  Public API
 * ==================================================================== */

static int apply_config(const logger_config_t *cfg)
{
    /* Copy primitive fields */
    g_log.drivers          = cfg->drivers ? cfg->drivers : LOG_DRV_CONSOLE;
    g_log.file_rotate_size = cfg->file_rotate_size;
    g_log.file_rotate_keep = cfg->file_rotate_keep > 0 ? cfg->file_rotate_keep : LOGGER_DEFAULT_KEEP;
    g_log.console_fd       = cfg->console_stderr ? STDERR_FILENO : STDOUT_FILENO;
    g_log.console_is_tty   = isatty(g_log.console_fd);
    g_log.async            = cfg->async;

    snprintf(g_log.name,   sizeof(g_log.name),
             "%s", cfg->name && cfg->name[0] ? cfg->name : "injspoof");

    const char *fmt = cfg->format && cfg->format[0]
                      ? cfg->format
                      : "%(asctime)s [%(levelname)s] %(name)s: %(message)s";
    snprintf(g_log.format, sizeof(g_log.format), "%s", fmt);
    parse_format(g_log.format, g_log.segments, &g_log.segment_count,
                 LOGGER_MAX_SEGMENTS, &g_log.has_newline);

    /* Open file driver if requested */
    if (g_log.drivers & LOG_DRV_FILE) {
        const char *path = (cfg->file_path && cfg->file_path[0]) ? cfg->file_path : "./injspoof.log";
        if (strcmp(path, g_log.file_path) != 0 || g_log.file_fd < 0) {
            if (g_log.file_fd >= 0) close(g_log.file_fd);
            snprintf(g_log.file_path, sizeof(g_log.file_path), "%s", path);
            g_log.file_fd = open(g_log.file_path,
                                 O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
            if (g_log.file_fd < 0) {
                fprintf(stderr, "logger: failed to open '%s': %s\n",
                        g_log.file_path, strerror(errno));
            } else {
                struct stat st;
                if (fstat(g_log.file_fd, &st) == 0)
                    atomic_store_explicit(&g_log.file_bytes,
                                          (uint64_t)st.st_size,
                                          memory_order_relaxed);
            }
        }
    } else if (g_log.file_fd >= 0) {
        close(g_log.file_fd);
        g_log.file_fd = -1;
        g_log.file_path[0] = '\0';
    }

    /* Syslog */
    if (g_log.drivers & LOG_DRV_SYSLOG) {
        snprintf(g_log.syslog_ident, sizeof(g_log.syslog_ident), "%s",
                 cfg->syslog_ident && cfg->syslog_ident[0] ? cfg->syslog_ident : g_log.name);
        openlog(g_log.syslog_ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    logger_set_level(cfg->level);
    return 0;
}

int logger_init(const logger_config_t *cfg)
{
    if (atomic_exchange(&g_log_initialized, 1)) {
        /* already initialised - treat as reconfigure */
        return logger_reconfigure(cfg);
    }

    g_log.file_fd     = -1;
    g_log.console_fd  = STDERR_FILENO;
    pthread_mutex_init(&g_log.reconfig_mtx, NULL);

    size_t ring_bytes = cfg->ring_capacity ? cfg->ring_capacity : LOGGER_DEFAULT_RING;
    if (ring_init(&g_log.ring, ring_bytes) < 0) {
        fprintf(stderr, "logger: ring init failed\n");
        return -1;
    }

    g_log.efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_log.efd < 0) {
        fprintf(stderr, "logger: eventfd failed: %s\n", strerror(errno));
        ring_free(&g_log.ring);
        return -1;
    }

    if (apply_config(cfg) < 0) return -1;

    if (g_log.async) {
        atomic_store(&g_log.writer_running, 1);
        if (pthread_create(&g_log.writer_tid, NULL, writer_thread, NULL) != 0) {
            fprintf(stderr, "logger: writer thread failed\n");
            atomic_store(&g_log.writer_running, 0);
            g_log.async = 0;
        }
    }

    return 0;
}

int logger_reconfigure(const logger_config_t *cfg)
{
    pthread_mutex_lock(&g_log.reconfig_mtx);
    int rc = apply_config(cfg);
    pthread_mutex_unlock(&g_log.reconfig_mtx);
    return rc;
}

void logger_shutdown(void)
{
    if (!atomic_load(&g_log_initialized)) return;

    if (g_log.async && atomic_exchange(&g_log.writer_running, 0)) {
        writer_signal();
        pthread_join(g_log.writer_tid, NULL);
    } else {
        /* Synchronous mode: just drain */
        log_record_t *batch[LOGGER_BATCH];
        for (;;) {
            int got = ring_drain(&g_log.ring, batch, LOGGER_BATCH);
            if (got == 0) break;
            for (int i = 0; i < got; i++) emit_record(batch[i]);
            ring_advance(&g_log.ring, got);
        }
    }

    if (g_log.efd >= 0) { close(g_log.efd); g_log.efd = -1; }
    if (g_log.file_fd >= 0) { close(g_log.file_fd); g_log.file_fd = -1; }
    if (g_log.drivers & LOG_DRV_SYSLOG) closelog();
    ring_free(&g_log.ring);
    pthread_mutex_destroy(&g_log.reconfig_mtx);
    atomic_store(&g_log_initialized, 0);
}

void logger_flush(void)
{
    if (!atomic_load(&g_log_initialized)) return;

    if (g_log.async) {
        writer_signal();
        /* Spin-drain: in the FATAL path the writer thread may be gone,
         * so we emit directly as a fallback. */
        for (int i = 0; i < 1000; i++) {
            log_record_t *batch[LOGGER_BATCH];
            int got = ring_drain(&g_log.ring, batch, LOGGER_BATCH);
            if (got == 0) break;
            for (int j = 0; j < got; j++) emit_record(batch[j]);
            ring_advance(&g_log.ring, got);
        }
    } else {
        log_record_t *batch[LOGGER_BATCH];
        for (;;) {
            int got = ring_drain(&g_log.ring, batch, LOGGER_BATCH);
            if (got == 0) break;
            for (int i = 0; i < got; i++) emit_record(batch[i]);
            ring_advance(&g_log.ring, got);
        }
    }
}

/* ====================================================================
 *  Emission
 * ==================================================================== */

void logger_vlog(log_level_t lvl,
                 const char *file,
                 int line,
                 const char *func,
                 const char *fmt, va_list ap)
{
    if (!atomic_load_explicit(&g_log_initialized, memory_order_relaxed)) {
        /* Pre-init fallback: write directly to stderr */
        char buf[LOGGER_MAX_MSG];
        int n = vsnprintf(buf, sizeof(buf), fmt, ap);
        if (n < 0) return;
        fprintf(stderr, "[%s] %s:%d %s\n",
                logger_level_to_string(lvl), file ? file : "?", line, buf);
        return;
    }

    if (!g_log.async) {
        /* Synchronous: format directly and emit */
        log_record_t rec;
        clock_gettime(CLOCK_REALTIME, &rec.ts);
        rec.level = (uint8_t)lvl;
        rec.line  = line;
        rec.tid   = fast_gettid();

        int n = vsnprintf(rec.payload, LOGGER_MAX_MSG, fmt, ap);
        if (n < 0) n = 0;
        if (n >= LOGGER_MAX_MSG) n = LOGGER_MAX_MSG - 1;
        rec.msg_len = (uint16_t)n;

        size_t fl = file ? strlen(file) : 0;
        if (fl > 80) fl = 80;
        size_t func_l = func ? strlen(func) : 0;
        if (func_l > 64) func_l = 64;
        size_t left = LOGGER_MAX_MSG - n;
        if (fl + func_l > left) {
            if (fl > left) fl = left;
            func_l = (left > fl) ? (left - fl) : 0;
        }
        memcpy(rec.payload + n, file, fl);             rec.file_len = (uint16_t)fl;
        memcpy(rec.payload + n + fl, func, func_l);    rec.func_len = (uint16_t)func_l;

        emit_record(&rec);
        atomic_fetch_add_explicit(&g_log_emitted, 1, memory_order_relaxed);
        return;
    }

    /* Async: format into a local record, then claim a ring slot. */
    log_record_t local;
    clock_gettime(CLOCK_REALTIME, &local.ts);
    local.level = (uint8_t)lvl;
    local.line  = line;
    local.tid   = fast_gettid();

    int n = vsnprintf(local.payload, LOGGER_MAX_MSG, fmt, ap);
    if (n < 0) n = 0;
    if (n >= LOGGER_MAX_MSG) n = LOGGER_MAX_MSG - 1;
    local.msg_len = (uint16_t)n;

    size_t fl = file ? strlen(file) : 0;   if (fl > 80) fl = 80;
    size_t func_l = func ? strlen(func) : 0; if (func_l > 64) func_l = 64;
    size_t left = LOGGER_MAX_MSG - n;
    if (fl + func_l > left) {
        if (fl > left) fl = left;
        func_l = (left > fl) ? (left - fl) : 0;
    }
    memcpy(local.payload + n,        file, fl);     local.file_len = (uint16_t)fl;
    memcpy(local.payload + n + fl,   func, func_l); local.func_len = (uint16_t)func_l;

    log_record_t *slot = ring_claim(&g_log.ring);
    if (!slot) {
        atomic_fetch_add_explicit(&g_log_dropped, 1, memory_order_relaxed);
        return;
    }
    memcpy(slot, &local, sizeof(local));
    atomic_fetch_add_explicit(&g_log_emitted, 1, memory_order_relaxed);

    /* Wake the writer (cheap eventfd write). */
    writer_signal();
}

void logger_log(log_level_t lvl,
                const char *file,
                int line,
                const char *func,
                const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    logger_vlog(lvl, file, line, func, fmt, ap);
    va_end(ap);
}
