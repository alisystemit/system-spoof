#ifndef INJSPOOF_API_H
#define INJSPOOF_API_H

#include "config.h"

/* ====================================================================
 *  Management API
 *
 *  Embedded, dependency-free HTTP/1.1 server bound to api.address:port.
 *  Runs in its own thread; the packet loop is never blocked.
 *
 *  Endpoints
 *  ---------
 *      GET  /api/v1/health           - liveness probe
 *      GET  /api/v1/info             - version, mode, pid, uptime
 *      GET  /api/v1/stats            - full metrics snapshot
 *      GET  /api/v1/stats/traffic    - traffic counters
 *      GET  /api/v1/stats/pool       - memory pool usage
 *      GET  /api/v1/stats/log        - log emitted/dropped
 *      GET  /api/v1/config           - effective config (JSON)
 *      PUT  /api/v1/config           - overwrite config on disk
 *      POST /api/v1/reload?mode=hot  - re-parse + apply hot-swappable fields
 *      POST /api/v1/reload?mode=hard - execve(self) restart
 *      GET  /api/v1/metrics          - Prometheus text format
 *
 *  Auth: if cfg->api.token is set, all endpoints require
 *  `Authorization: Bearer <token>`.
 * ==================================================================== */

/* Forward decl for the hot-reload callback used by the reload endpoint.
 * The runtime (client.c / server.c) installs one of these. */
typedef int (*api_hot_reload_fn)(const config_t *new_cfg, void *ctx);
typedef int (*api_hard_reload_fn)(void *ctx);

typedef struct {
    config_t          *cfg;                  /* current effective config */
    api_hot_reload_fn  on_hot_reload;        /* may be NULL */
    api_hard_reload_fn on_hard_reload;       /* may be NULL */
    void              *reload_ctx;
    void              *pool;                 /* pool_t* (opaque) for stats */
} api_ctx_t;

/* Start the API thread. Returns 0 on success, -1 on error.
 * `ctx` and everything it points at must remain valid for the
 * lifetime of the API thread. */
int  api_start(api_ctx_t *ctx);

/* Request the API thread to stop and join it. */
void api_stop(void);

#endif /* INJSPOOF_API_H */
