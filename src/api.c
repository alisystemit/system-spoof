/* ====================================================================
 *  injspoof - Management API (HTTP/1.1)
 *
 *  Notes
 *  -----
 *  - Single dedicated thread, edge-triggered epoll, non-blocking I/O.
 *  - No external HTTP library: very small parser sufficient for our
 *    JSON+text endpoints (no chunked encoding, max 1 MiB request body).
 *  - Drops privileges? Out of scope - this binds to a privileged port
 *    only if explicitly configured.
 *  - All write paths go through SO_REUSEADDR + TCP_NODELAY +
 *    SO_LINGER{off} for responsiveness.
 *  - Hot-reload constructs a fresh config_t off the request thread and
 *    invokes the caller-supplied callback synchronously; the callback
 *    (in client.c / server.c) is responsible for the atomic-pointer
 *    swap.
 * ==================================================================== */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "api.h"
#include "logger.h"
#include "metrics.h"
#include "pool.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define API_MAX_CONN     128
#define API_MAX_EVENTS   64
#define API_RECV_BUF     8192
#define API_BODY_MAX     (1u << 20)
#define API_VERSION_STR  "1.0.0"

#ifndef INJSPOOF_BUILD_VERSION
#  define INJSPOOF_BUILD_VERSION "dev"
#endif

extern char **environ;

typedef struct conn_state {
    int      fd;
    char    *rx;
    size_t   rx_len;
    size_t   rx_cap;
    int      header_parsed;
    size_t   content_length;
    size_t   header_end;       /* offset of body start in rx */
    char     method[8];
    char     path[256];
    char     query[256];
    char     auth[160];
    int      keepalive;
} conn_state_t;

static int                g_listen_fd = -1;
static int                g_epoll_fd  = -1;
static int                g_stop_efd  = -1;
static pthread_t          g_api_tid;
static _Atomic int        g_running   = 0;
static api_ctx_t         *g_ctx       = NULL;

/* ====================================================================
 *  Helpers
 * ==================================================================== */

static void conn_close(conn_state_t *c)
{
    if (c->fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    free(c->rx);
    free(c);
}

static void send_response(int fd, int code, const char *reason,
                          const char *content_type, const char *body, size_t body_len,
                          int keepalive)
{
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "Cache-Control: no-store\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS\r\n"
        "\r\n",
        code, reason, content_type, body_len,
        keepalive ? "keep-alive" : "close");
    (void)!send(fd, hdr, (size_t)n, MSG_NOSIGNAL);
    if (body && body_len)
        (void)!send(fd, body, body_len, MSG_NOSIGNAL);
}

static void send_json(int fd, int code, const char *json, int keepalive)
{
    send_response(fd, code, code == 200 ? "OK" : "Error",
                  "application/json", json, strlen(json), keepalive);
}

/* Reserved for future plain-text endpoints. */
__attribute__((unused))
static void send_text(int fd, int code, const char *txt, int keepalive)
{
    send_response(fd, code, code == 200 ? "OK" : "Error",
                  "text/plain; charset=utf-8", txt, strlen(txt), keepalive);
}

/* ====================================================================
 *  Tiny HTTP parser
 * ==================================================================== */

static int parse_request_line(conn_state_t *c)
{
    char *crlf = memchr(c->rx, '\n', c->rx_len);
    if (!crlf) return 0;
    *crlf = 0;
    /* Strip trailing \r */
    if (crlf > c->rx && crlf[-1] == '\r') crlf[-1] = 0;

    char *m = c->rx;
    char *p = strchr(m, ' ');
    if (!p) return -1;
    *p = 0;
    snprintf(c->method, sizeof(c->method), "%s", m);

    char *uri = p + 1;
    p = strchr(uri, ' ');
    if (!p) return -1;
    *p = 0;

    char *q = strchr(uri, '?');
    if (q) {
        *q = 0;
        snprintf(c->query, sizeof(c->query), "%s", q + 1);
    } else {
        c->query[0] = 0;
    }
    snprintf(c->path, sizeof(c->path), "%s", uri);
    return (int)(crlf - c->rx) + 1;
}

static int parse_headers(conn_state_t *c, int body_off)
{
    c->content_length = 0;
    c->keepalive = 1;  /* HTTP/1.1 default */
    int off = body_off;
    while (off < (int)c->rx_len) {
        char *line = c->rx + off;
        char *crlf = memchr(line, '\n', c->rx_len - off);
        if (!crlf) return 0;
        *crlf = 0;
        if (crlf > line && crlf[-1] == '\r') crlf[-1] = 0;

        if (line[0] == 0) {
            c->header_end = (size_t)(crlf - c->rx) + 1;
            c->header_parsed = 1;
            return 1;
        }
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = 0;
            char *val = colon + 1;
            while (*val == ' ' || *val == '\t') val++;

            if (!strcasecmp(line, "Content-Length"))
                c->content_length = (size_t)strtoul(val, NULL, 10);
            else if (!strcasecmp(line, "Authorization"))
                snprintf(c->auth, sizeof(c->auth), "%s", val);
            else if (!strcasecmp(line, "Connection")) {
                if (!strcasecmp(val, "close")) c->keepalive = 0;
            }
        }
        off = (int)(crlf - c->rx) + 1;
    }
    return 0;
}

/* ====================================================================
 *  Auth
 * ==================================================================== */

static int auth_ok(const conn_state_t *c)
{
    const char *tok = g_ctx->cfg->api.token;
    if (!tok || tok[0] == 0) return 1; /* unauthenticated when no token */
    if (strncmp(c->auth, "Bearer ", 7) != 0) return 0;
    return strcmp(c->auth + 7, tok) == 0;
}

/* ====================================================================
 *  JSON helpers (no external deps)
 * ==================================================================== */

__attribute__((unused))
static size_t json_str_escape(char *out, size_t cap, const char *s)
{
    size_t i = 0;
    if (i >= cap) return 0;
    out[i++] = '"';
    for (; *s && i + 2 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            if (i + 2 >= cap) break;
            out[i++] = '\\'; out[i++] = (char)c;
        } else if (c == '\n') { out[i++] = '\\'; out[i++] = 'n'; }
        else if (c == '\r')   { out[i++] = '\\'; out[i++] = 'r'; }
        else if (c == '\t')   { out[i++] = '\\'; out[i++] = 't'; }
        else if (c < 0x20) {
            if (i + 6 >= cap) break;
            i += snprintf(out + i, cap - i, "\\u%04x", c);
        } else out[i++] = (char)c;
    }
    if (i < cap) out[i++] = '"';
    if (i < cap) out[i] = 0;
    return i;
}

/* ====================================================================
 *  Endpoint: GET /api/v1/health
 * ==================================================================== */
static void ep_health(conn_state_t *c)
{
    send_json(c->fd, 200, "{\"status\":\"ok\"}", c->keepalive);
}

/* ====================================================================
 *  Endpoint: GET /api/v1/info
 * ==================================================================== */
static void ep_info(conn_state_t *c)
{
    char body[512];
    int n = snprintf(body, sizeof(body),
        "{\"name\":\"injspoof\",\"version\":\"%s\","
        "\"api_version\":\"%s\",\"mode\":\"%s\","
        "\"pid\":%d,\"config\":\"%s\"}",
        INJSPOOF_BUILD_VERSION, API_VERSION_STR,
        g_ctx->cfg->mode == MODE_CLIENT ? "client" : "server",
        (int)getpid(), g_ctx->cfg->config_path);
    send_response(c->fd, 200, "OK", "application/json", body, (size_t)n, c->keepalive);
}

/* ====================================================================
 *  Endpoint: GET /api/v1/stats[/sub]
 * ==================================================================== */
static void ep_stats(conn_state_t *c, const char *sub)
{
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    char body[2048];
    int n;
    if (!sub || !*sub) {
        n = snprintf(body, sizeof(body),
            "{"
            "\"uptime_ms\":%llu,"
            "\"traffic\":{"
                "\"pkts_in\":%llu,\"pkts_out\":%llu,"
                "\"pkts_in_local\":%llu,\"pkts_in_wire\":%llu,"
                "\"pkts_out_wire\":%llu,\"pkts_out_local\":%llu,"
                "\"bytes_in\":%llu,\"bytes_out\":%llu,"
                "\"frags_sent\":%llu"
            "},"
            "\"drops\":{"
                "\"filter\":%llu,\"parse\":%llu,\"pool\":%llu,"
                "\"send\":%llu,\"oversize\":%llu,"
                "\"send_by_errno\":{"
                    "\"enobufs\":%llu,\"eagain\":%llu,\"emsgsize\":%llu,"
                    "\"enetdown\":%llu,\"eperm\":%llu,\"other\":%llu"
                "}"
            "},"
            "\"syscalls\":{"
                "\"recvmmsg\":%llu,\"sendmmsg\":%llu,\"sendto\":%llu"
            "},"
            "\"reloads\":{\"hot\":%llu,\"hard\":%llu},"
            "\"log\":{\"emitted\":%llu,\"dropped\":%llu},"
            "\"pool\":{\"avail\":%u,\"capacity\":%u,\"hits\":%llu,\"misses\":%llu}"
            "}",
            (unsigned long long)(s.uptime_ns / 1000000ull),
            (unsigned long long)s.pkts_in, (unsigned long long)s.pkts_out,
            (unsigned long long)s.pkts_in_local, (unsigned long long)s.pkts_in_wire,
            (unsigned long long)s.pkts_out_wire, (unsigned long long)s.pkts_out_local,
            (unsigned long long)s.bytes_in, (unsigned long long)s.bytes_out,
            (unsigned long long)s.frags_sent,
            (unsigned long long)s.drop_filter, (unsigned long long)s.drop_parse,
            (unsigned long long)s.drop_pool, (unsigned long long)s.drop_send,
            (unsigned long long)s.drop_oversize,
            (unsigned long long)s.drop_send_enobufs,
            (unsigned long long)s.drop_send_eagain,
            (unsigned long long)s.drop_send_emsgsize,
            (unsigned long long)s.drop_send_enetdown,
            (unsigned long long)s.drop_send_eperm,
            (unsigned long long)s.drop_send_other,
            (unsigned long long)s.recvmmsg_calls, (unsigned long long)s.sendmmsg_calls,
            (unsigned long long)s.sendto_calls,
            (unsigned long long)s.reloads_hot, (unsigned long long)s.reloads_hard,
            (unsigned long long)s.log_emitted, (unsigned long long)s.log_dropped,
            g_ctx->pool ? pool_available((pool_t *)g_ctx->pool) : 0,
            g_ctx->pool ? pool_capacity((pool_t *)g_ctx->pool) : 0,
            g_ctx->pool ? (unsigned long long)pool_alloc_hits((pool_t *)g_ctx->pool) : 0,
            g_ctx->pool ? (unsigned long long)pool_alloc_misses((pool_t *)g_ctx->pool) : 0);
    } else if (!strcmp(sub, "traffic")) {
        n = snprintf(body, sizeof(body),
            "{\"pkts_in\":%llu,\"pkts_out\":%llu,\"bytes_in\":%llu,"
             "\"bytes_out\":%llu,\"frags_sent\":%llu}",
            (unsigned long long)s.pkts_in, (unsigned long long)s.pkts_out,
            (unsigned long long)s.bytes_in, (unsigned long long)s.bytes_out,
            (unsigned long long)s.frags_sent);
    } else if (!strcmp(sub, "pool")) {
        n = snprintf(body, sizeof(body),
            "{\"avail\":%u,\"capacity\":%u,\"hits\":%llu,\"misses\":%llu}",
            g_ctx->pool ? pool_available((pool_t *)g_ctx->pool) : 0,
            g_ctx->pool ? pool_capacity((pool_t *)g_ctx->pool) : 0,
            g_ctx->pool ? (unsigned long long)pool_alloc_hits((pool_t *)g_ctx->pool) : 0,
            g_ctx->pool ? (unsigned long long)pool_alloc_misses((pool_t *)g_ctx->pool) : 0);
    } else if (!strcmp(sub, "log")) {
        n = snprintf(body, sizeof(body),
            "{\"emitted\":%llu,\"dropped\":%llu}",
            (unsigned long long)s.log_emitted, (unsigned long long)s.log_dropped);
    } else {
        send_json(c->fd, 404, "{\"error\":\"unknown stats endpoint\"}", c->keepalive);
        return;
    }
    send_response(c->fd, 200, "OK", "application/json", body, (size_t)n, c->keepalive);
}

/* ====================================================================
 *  Endpoint: GET /api/v1/metrics  (Prometheus text format)
 * ==================================================================== */
static void ep_prometheus(conn_state_t *c)
{
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    char body[2048];
    int n = snprintf(body, sizeof(body),
        "# HELP injspoof_pkts_in Total incoming packets\n"
        "# TYPE injspoof_pkts_in counter\n"
        "injspoof_pkts_in %llu\n"
        "# HELP injspoof_pkts_out Total outgoing packets\n"
        "# TYPE injspoof_pkts_out counter\n"
        "injspoof_pkts_out %llu\n"
        "# HELP injspoof_bytes_in Total incoming bytes\n"
        "# TYPE injspoof_bytes_in counter\n"
        "injspoof_bytes_in %llu\n"
        "# HELP injspoof_bytes_out Total outgoing bytes\n"
        "# TYPE injspoof_bytes_out counter\n"
        "injspoof_bytes_out %llu\n"
        "# HELP injspoof_frags_sent Total IP fragments emitted\n"
        "# TYPE injspoof_frags_sent counter\n"
        "injspoof_frags_sent %llu\n"
        "# HELP injspoof_drops Drops by reason\n"
        "# TYPE injspoof_drops counter\n"
        "injspoof_drops{reason=\"filter\"} %llu\n"
        "injspoof_drops{reason=\"parse\"} %llu\n"
        "injspoof_drops{reason=\"pool\"} %llu\n"
        "injspoof_drops{reason=\"send\"} %llu\n"
        "injspoof_drops{reason=\"oversize\"} %llu\n"
        "# HELP injspoof_send_errno Send-failure breakdown by errno\n"
        "# TYPE injspoof_send_errno counter\n"
        "injspoof_send_errno{errno=\"ENOBUFS\"} %llu\n"
        "injspoof_send_errno{errno=\"EAGAIN\"} %llu\n"
        "injspoof_send_errno{errno=\"EMSGSIZE\"} %llu\n"
        "injspoof_send_errno{errno=\"ENETDOWN\"} %llu\n"
        "injspoof_send_errno{errno=\"EPERM\"} %llu\n"
        "injspoof_send_errno{errno=\"other\"} %llu\n"
        "# HELP injspoof_reloads Configuration reloads\n"
        "# TYPE injspoof_reloads counter\n"
        "injspoof_reloads{mode=\"hot\"} %llu\n"
        "injspoof_reloads{mode=\"hard\"} %llu\n"
        "# HELP injspoof_uptime_seconds Process uptime\n"
        "# TYPE injspoof_uptime_seconds gauge\n"
        "injspoof_uptime_seconds %.3f\n",
        (unsigned long long)s.pkts_in, (unsigned long long)s.pkts_out,
        (unsigned long long)s.bytes_in, (unsigned long long)s.bytes_out,
        (unsigned long long)s.frags_sent,
        (unsigned long long)s.drop_filter, (unsigned long long)s.drop_parse,
        (unsigned long long)s.drop_pool, (unsigned long long)s.drop_send,
        (unsigned long long)s.drop_oversize,
        (unsigned long long)s.drop_send_enobufs,
        (unsigned long long)s.drop_send_eagain,
        (unsigned long long)s.drop_send_emsgsize,
        (unsigned long long)s.drop_send_enetdown,
        (unsigned long long)s.drop_send_eperm,
        (unsigned long long)s.drop_send_other,
        (unsigned long long)s.reloads_hot, (unsigned long long)s.reloads_hard,
        (double)s.uptime_ns / 1e9);
    send_response(c->fd, 200, "OK",
                  "text/plain; version=0.0.4",
                  body, (size_t)n, c->keepalive);
}

/* ====================================================================
 *  Endpoint: GET /api/v1/config  (returns the raw file on disk)
 * ==================================================================== */
static void ep_config_get(conn_state_t *c)
{
    FILE *f = fopen(g_ctx->cfg->config_path, "r");
    if (!f) {
        send_json(c->fd, 500, "{\"error\":\"cannot read config\"}", c->keepalive);
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0 || sz > (long)API_BODY_MAX) { fclose(f); 
        send_json(c->fd, 500, "{\"error\":\"config too large\"}", c->keepalive); return; }
    fseek(f, 0, SEEK_SET);
    char *body = malloc((size_t)sz + 1);
    if (!body) { fclose(f); send_json(c->fd, 500, "{\"error\":\"oom\"}", c->keepalive); return; }
    size_t nread = fread(body, 1, (size_t)sz, f); body[nread] = 0;
    fclose(f);
    send_response(c->fd, 200, "OK", "application/json", body, nread, c->keepalive);
    free(body);
}

/* ====================================================================
 *  Endpoint: PUT /api/v1/config  (replaces config file on disk)
 * ==================================================================== */
static void ep_config_put(conn_state_t *c, const char *body, size_t body_len)
{
    if (body_len == 0 || body_len > API_BODY_MAX) {
        send_json(c->fd, 400, "{\"error\":\"empty or too large body\"}", c->keepalive);
        return;
    }

    /* Atomic write: temp file then rename */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", g_ctx->cfg->config_path, (int)getpid());
    int tfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (tfd < 0) {
        send_json(c->fd, 500, "{\"error\":\"cannot create tmp\"}", c->keepalive);
        return;
    }
    if (write(tfd, body, body_len) != (ssize_t)body_len) {
        close(tfd); unlink(tmp);
        send_json(c->fd, 500, "{\"error\":\"write failed\"}", c->keepalive);
        return;
    }
    fsync(tfd); close(tfd);
    if (rename(tmp, g_ctx->cfg->config_path) < 0) {
        unlink(tmp);
        send_json(c->fd, 500, "{\"error\":\"rename failed\"}", c->keepalive);
        return;
    }
    LOG_INFO("api: config file updated via PUT (%zu bytes)", body_len);
    send_json(c->fd, 200, "{\"status\":\"ok\"}", c->keepalive);
}

/* ====================================================================
 *  Endpoint: POST /api/v1/reload?mode=(hot|hard)
 * ==================================================================== */
static void ep_reload(conn_state_t *c)
{
    int hard = strstr(c->query, "mode=hard") != NULL;

    if (hard) {
        if (!g_ctx->on_hard_reload) {
            send_json(c->fd, 501, "{\"error\":\"hard reload not supported\"}", 0);
            return;
        }
        send_json(c->fd, 202, "{\"status\":\"restarting\"}", 0);
        shutdown(c->fd, SHUT_RDWR);
        METRIC_INC(&g_metrics.reloads_hard);
        LOG_INFO("api: hard reload requested");
        g_ctx->on_hard_reload(g_ctx->reload_ctx);
        return;
    }

    /* Hot reload: re-parse from disk, call callback */
    config_t *new_cfg = calloc(1, sizeof(*new_cfg));
    if (!new_cfg) { send_json(c->fd, 500, "{\"error\":\"oom\"}", c->keepalive); return; }

    if (config_load(new_cfg, g_ctx->cfg->config_path, g_ctx->cfg->mode) < 0) {
        free(new_cfg);
        send_json(c->fd, 400, "{\"error\":\"config parse failed\"}", c->keepalive);
        return;
    }

    int rc = g_ctx->on_hot_reload ? g_ctx->on_hot_reload(new_cfg, g_ctx->reload_ctx) : 0;
    if (rc < 0) {
        config_free(new_cfg); free(new_cfg);
        send_json(c->fd, 400, "{\"error\":\"hot reload rejected\"}", c->keepalive);
        return;
    }
    METRIC_INC(&g_metrics.reloads_hot);
    LOG_INFO("api: hot reload applied");
    /* The callback takes ownership of new_cfg or frees it. */
    send_json(c->fd, 200, "{\"status\":\"reloaded\"}", c->keepalive);
}

/* ====================================================================
 *  Dispatcher
 * ==================================================================== */

static void dispatch(conn_state_t *c, const char *body, size_t body_len)
{
    if (!strcmp(c->method, "OPTIONS")) {
        send_response(c->fd, 204, "No Content", "text/plain", "", 0, c->keepalive);
        return;
    }
    if (!auth_ok(c)) {
        send_json(c->fd, 401, "{\"error\":\"unauthorized\"}", 0);
        c->keepalive = 0;
        return;
    }

    /* Routing */
    if (!strcmp(c->method, "GET")) {
        if (!strcmp(c->path, "/api/v1/health"))         return ep_health(c);
        if (!strcmp(c->path, "/api/v1/info"))           return ep_info(c);
        if (!strcmp(c->path, "/api/v1/stats"))          return ep_stats(c, NULL);
        if (!strcmp(c->path, "/api/v1/stats/traffic")) return ep_stats(c, "traffic");
        if (!strcmp(c->path, "/api/v1/stats/pool"))    return ep_stats(c, "pool");
        if (!strcmp(c->path, "/api/v1/stats/log"))     return ep_stats(c, "log");
        if (!strcmp(c->path, "/api/v1/config"))         return ep_config_get(c);
        if (!strcmp(c->path, "/api/v1/metrics"))        return ep_prometheus(c);
    } else if (!strcmp(c->method, "PUT")) {
        if (!strcmp(c->path, "/api/v1/config"))
            return ep_config_put(c, body, body_len);
    } else if (!strcmp(c->method, "POST")) {
        if (!strcmp(c->path, "/api/v1/reload"))
            return ep_reload(c);
    }
    send_json(c->fd, 404, "{\"error\":\"not found\"}", c->keepalive);
}

/* ====================================================================
 *  Connection state machine
 * ==================================================================== */

static int conn_read(conn_state_t *c)
{
    for (;;) {
        if (c->rx_len + 4096 > c->rx_cap) {
            size_t newcap = c->rx_cap ? c->rx_cap * 2 : API_RECV_BUF;
            if (newcap > API_BODY_MAX + 65536) return -1;
            char *nb = realloc(c->rx, newcap);
            if (!nb) return -1;
            c->rx = nb; c->rx_cap = newcap;
        }
        ssize_t n = recv(c->fd, c->rx + c->rx_len, c->rx_cap - c->rx_len, 0);
        if (n > 0) { c->rx_len += (size_t)n; continue; }
        if (n == 0) return -1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
}

static void conn_progress(conn_state_t *c)
{
    if (!c->header_parsed) {
        int rl = parse_request_line(c);
        if (rl <= 0) return;
        int ok = parse_headers(c, rl);
        if (!ok) return;
    }
    if (!c->header_parsed) return;
    if (c->rx_len < c->header_end + c->content_length) return;

    const char *body = c->rx + c->header_end;
    size_t body_len = c->content_length;
    dispatch(c, body, body_len);

    if (!c->keepalive) {
        conn_close(c);
        return;
    }
    /* Pipeline support: consume processed bytes, parse next request. */
    size_t consumed = c->header_end + c->content_length;
    if (c->rx_len > consumed)
        memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
    c->rx_len -= consumed;
    c->header_parsed = 0;
    c->header_end = 0;
    c->content_length = 0;
    c->method[0] = c->path[0] = c->query[0] = c->auth[0] = 0;
}

/* ====================================================================
 *  Thread main
 * ==================================================================== */

static void *api_thread_main(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "injspoof-api");
    /* Lower priority than packet loop */
    struct sched_param sp = { 0 };
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp);

    struct epoll_event events[API_MAX_EVENTS];

    while (atomic_load_explicit(&g_running, memory_order_acquire)) {
        int n = epoll_wait(g_epoll_fd, events, API_MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == g_listen_fd) {
                for (;;) {
                    int cfd = accept4(g_listen_fd, NULL, NULL,
                                      SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (cfd < 0) break;
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    conn_state_t *c = calloc(1, sizeof(*c));
                    if (!c) { close(cfd); continue; }
                    c->fd = cfd; c->keepalive = 1;
                    struct epoll_event ev = { .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
                                              .data.ptr = c };
                    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0)
                        conn_close(c);
                }
            } else if (fd == g_stop_efd) {
                uint64_t v; (void)!read(g_stop_efd, &v, sizeof(v));
            } else {
                conn_state_t *c = events[i].data.ptr;
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn_close(c);
                    continue;
                }
                if (conn_read(c) < 0) { conn_close(c); continue; }
                conn_progress(c);
            }
        }
    }

    return NULL;
}

/* ====================================================================
 *  Lifecycle
 * ==================================================================== */

int api_start(api_ctx_t *ctx)
{
    if (!ctx || !ctx->cfg) return -1;
    if (!ctx->cfg->api.enabled) {
        LOG_INFO("api: disabled (no api.address/port in config)");
        return 0;
    }

    g_ctx = ctx;

    g_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_listen_fd < 0) { LOG_PERROR("api: socket"); return -1; }

    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(ctx->cfg->api.port);
    if (inet_pton(AF_INET, ctx->cfg->api.address, &sin.sin_addr) != 1)
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(g_listen_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        LOG_PERROR("api: bind"); close(g_listen_fd); return -1;
    }
    if (listen(g_listen_fd, 64) < 0) {
        LOG_PERROR("api: listen"); close(g_listen_fd); return -1;
    }

    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) { LOG_PERROR("api: epoll_create1"); close(g_listen_fd); return -1; }

    g_stop_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_stop_efd < 0) { close(g_listen_fd); close(g_epoll_fd); return -1; }

    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.fd = g_listen_fd;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_listen_fd, &ev);
    ev.events = EPOLLIN; ev.data.fd = g_stop_efd;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_stop_efd, &ev);

    atomic_store(&g_running, 1);
    if (pthread_create(&g_api_tid, NULL, api_thread_main, NULL) != 0) {
        LOG_ERROR("api: pthread_create failed");
        atomic_store(&g_running, 0);
        close(g_listen_fd); close(g_epoll_fd); close(g_stop_efd);
        return -1;
    }
    LOG_INFO("api: listening on %s:%u", ctx->cfg->api.address, ctx->cfg->api.port);
    return 0;
}

void api_stop(void)
{
    if (!atomic_exchange(&g_running, 0)) return;
    uint64_t one = 1; (void)!write(g_stop_efd, &one, sizeof(one));
    pthread_join(g_api_tid, NULL);
    if (g_listen_fd >= 0) close(g_listen_fd);
    if (g_epoll_fd >= 0)  close(g_epoll_fd);
    if (g_stop_efd >= 0)  close(g_stop_efd);
    g_listen_fd = g_epoll_fd = g_stop_efd = -1;
    LOG_INFO("api: stopped");
}
