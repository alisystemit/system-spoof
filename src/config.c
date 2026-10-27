/* ====================================================================
 *  injspoof -- config loader (new core)
 *
 *  Parses + validates new-server.json / new-client.json and fails fast
 *  (returns -1) on any invalid configuration.
 * ==================================================================== */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "config.h"
#include "logger.h"
#include "packet.h"
#include "../vendor/cJSON/cJSON.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- Low-level helpers ---- */

static int parse_mac(const char *str, uint8_t mac[6])
{
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 0;
}

static int detect_iface_mac(const char *iface_name, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_PERROR("socket"); return -1; }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        LOG_PERROR("ioctl SIOCGIFHWADDR"); close(fd); return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int detect_iface_index(const char *iface_name)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_PERROR("socket"); return -1; }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        LOG_PERROR("ioctl SIOCGIFINDEX"); close(fd); return -1;
    }
    int idx = ifr.ifr_ifindex;
    close(fd);
    return idx;
}

static int parse_hostport(const char *s, endpoint_t *out, const char *what)
{
    if (!s) { LOG_ERROR("config: %s: null host:port", what); return -1; }
    const char *colon = strrchr(s, ':');
    if (!colon) { LOG_ERROR("config: %s: '%s' missing ':port'", what, s); return -1; }
    size_t hlen = (size_t)(colon - s);
    if (hlen == 0 || hlen >= INET_ADDRSTRLEN) {
        LOG_ERROR("config: %s: '%s' invalid host length", what, s);
        return -1;
    }
    memcpy(out->address, s, hlen);
    out->address[hlen] = '\0';
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) {
        LOG_ERROR("config: %s: '%s' port out of range", what, s);
        return -1;
    }
    out->port = (uint16_t)p;
    struct in_addr a;
    if (inet_pton(AF_INET, out->address, &a) != 1) {
        LOG_ERROR("config: %s: '%s' not a valid IPv4 address", what, out->address);
        return -1;
    }
    return 0;
}

static inline int ip_is_private(uint32_t host_ip)
{
    return  ((host_ip & 0xFF000000u) == 0x0A000000u) ||
            ((host_ip & 0xFFF00000u) == 0xAC100000u) ||
            ((host_ip & 0xFFFF0000u) == 0xC0A80000u);
}
static inline int ip_is_reserved(uint32_t host_ip)
{
    if ((host_ip & 0xFF000000u) == 0x00000000u) return 1;
    if ((host_ip & 0xFF000000u) == 0x7F000000u) return 1;
    if ((host_ip & 0xFFFF0000u) == 0xA9FE0000u) return 1;
    if ((host_ip & 0xFFFE0000u) == 0xC6120000u) return 1;
    if ((host_ip & 0xF0000000u) == 0xF0000000u) return 1;
    return 0;
}
static inline int ip_is_multicast(uint32_t host_ip)
{
    return (host_ip & 0xF0000000u) == 0xE0000000u;
}

/* Pick a random ephemeral port (1024-65535). Used when a firewall rule's
 * outgoing port.src / port.dst is omitted or null -> auto-select. */
static uint16_t random_ephemeral_port(void)
{
    static int seeded = 0;
    if (!seeded) {
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        srand((unsigned)(ts.tv_nsec ^ ((long)getpid() << 16)));
        seeded = 1;
    }
    return (uint16_t)(1024 + (rand() % (65535 - 1024 + 1)));
}

static int add_cidr_to_pool(source_pool_t *pool, const char *entry)
{
    if (pool->count >= MAX_SOURCE_BLOCKS) {
        LOG_WARN("config: source pool full (max %d blocks)", MAX_SOURCE_BLOCKS);
        return -1;
    }
    char buf[64];
    strncpy(buf, entry, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) {
            LOG_ERROR("config: invalid CIDR prefix /%d in '%s'", prefix, entry);
            return -1;
        }
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        LOG_ERROR("config: invalid IP '%s'", entry);
        return -1;
    }
    uint32_t base = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t broadcast = network | ~mask;

    cidr_t c;
    if (prefix == 32) {
        c.first_ip = base;       c.last_ip = base;       c.host_count = 1;
    } else if (prefix == 31) {
        c.first_ip = network;    c.last_ip = broadcast;  c.host_count = 2;
    } else {
        c.first_ip = network + 1; c.last_ip = broadcast - 1;
        c.host_count = (broadcast - network) - 1;
    }
    if (pool->exclude_private  && ip_is_private(c.first_ip)  && ip_is_private(c.last_ip))  return 0;
    if (pool->exclude_reserved && ip_is_reserved(c.first_ip) && ip_is_reserved(c.last_ip)) return 0;
    if (pool->exclude_multicast&& ip_is_multicast(c.first_ip)&& ip_is_multicast(c.last_ip))return 0;
    if (pool->deduplicate && c.host_count == 1) {
        for (int i = 0; i < pool->count; i++)
            if (pool->subnets[i].first_ip == c.first_ip &&
                pool->subnets[i].last_ip  == c.last_ip)
                return 0;
    }
    pool->subnets[pool->count++] = c;
    pool->total_hosts += c.host_count;
    return 0;
}

static int load_provider_file(source_pool_t *pool, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("config: cannot open provider file '%s': %s", path, strerror(errno));
        return -1;
    }
    char line[128];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        if (pool->count >= MAX_SOURCE_BLOCKS) {
            LOG_WARN("config: pool full at %d blocks, truncating '%s'", pool->count, path);
            break;
        }
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        char *end = p + strlen(p);
        while (end > p && isspace((unsigned char)end[-1])) *--end = '\0';
        if (*p == '\0' || *p == '#') continue;
        if (add_cidr_to_pool(pool, p) == 0) added++;
    }
    fclose(f);
    LOG_INFO("config: loaded %d entries from '%s'", added, path);
    return added > 0 ? 0 : -1;
}

static int cidr_cmp(const void *a, const void *b)
{
    uint32_t fa = ((const cidr_t *)a)->first_ip;
    uint32_t fb = ((const cidr_t *)b)->first_ip;
    return (fa > fb) - (fa < fb);
}

static void build_prefix_sum(source_pool_t *pool)
{
    /* Sort blocks ascending by first_ip so both the userspace filter and
     * the XDP program can early-out once src < block.first_ip (F9). RR
     * selection is order-independent, so this does not change semantics. */
    if (pool->count > 1)
        qsort(pool->subnets, (size_t)pool->count, sizeof(pool->subnets[0]), cidr_cmp);

    uint64_t sum = 0;
    for (int i = 0; i < pool->count; i++) {
        sum += pool->subnets[i].host_count;
        pool->prefix_sum[i] = sum;
    }
    pool->total_hosts = (uint32_t)sum;
}

static int parse_single_provider(source_pool_t *pool, const cJSON *prov)
{
    if (!cJSON_IsObject(prov)) return -1;
    if (pool->provider_count >= MAX_PROVIDERS) {
        LOG_WARN("config: too many providers (max %d), skipping", MAX_PROVIDERS);
        return -1;
    }
    cJSON *type = cJSON_GetObjectItemCaseSensitive(prov, "type");
    cJSON *val  = cJSON_GetObjectItemCaseSensitive(prov, "value");
    if (!cJSON_IsString(type)) {
        LOG_ERROR("config: source provider missing string 'type'");
        return -1;
    }
    provider_t *p = &pool->providers[pool->provider_count++];
    memset(p, 0, sizeof(*p));

    if (!strcmp(type->valuestring, "file")) {
        p->type = ADDR_FILE;
        if (cJSON_IsString(val)) {
            strncpy(p->path, val->valuestring, sizeof(p->path) - 1);
            return load_provider_file(pool, p->path);
        }
        LOG_ERROR("config: file provider requires string 'value'");
        return -1;
    }
    p->type = ADDR_STATIC;
    if (cJSON_IsArray(val)) {
        cJSON *e;
        cJSON_ArrayForEach(e, val)
            if (cJSON_IsString(e) && add_cidr_to_pool(pool, e->valuestring) < 0)
                return -1;
    } else if (cJSON_IsString(val)) {
        if (add_cidr_to_pool(pool, val->valuestring) < 0) return -1;
    } else {
        LOG_ERROR("config: static provider requires string or array 'value'");
        return -1;
    }
    return 0;
}

static select_strategy_t parse_strategy(const cJSON *s, select_strategy_t def)
{
    if (!cJSON_IsString(s)) return def;
    if (!strcasecmp(s->valuestring, "round_robin")) return SELECT_ROUND_ROBIN;
    if (!strcasecmp(s->valuestring, "random"))      return SELECT_RANDOM;
    return def;
}

/* Validate a TCP flags string ("psh+ack"): each '+'-separated token must be
 * one of fin/syn/rst/psh/ack/urg. */
static int valid_tcp_flags(const char *s)
{
    char buf[32];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    if (buf[0] == '\0') return 1;
    for (char *tok = strtok(buf, "+,| "); tok; tok = strtok(NULL, "+,| ")) {
        if (strcasecmp(tok, "fin") && strcasecmp(tok, "syn") && strcasecmp(tok, "rst") &&
            strcasecmp(tok, "psh") && strcasecmp(tok, "ack") && strcasecmp(tok, "urg"))
            return 0;
    }
    return 1;
}

/* Parse a uint32 (number or hex/decimal string), failing on malformed input. */
static int parse_u32_strict(const cJSON *v, uint32_t *out, const char *what)
{
    if (cJSON_IsNumber(v)) { *out = (uint32_t)v->valuedouble; return 0; }
    if (cJSON_IsString(v)) {
        char *end = NULL;
        unsigned long u = strtoul(v->valuestring, &end, 0);
        if (!end || *end != '\0') { LOG_ERROR("config: %s '%s' is not a valid number", what, v->valuestring); return -1; }
        *out = (uint32_t)u;
        return 0;
    }
    LOG_ERROR("config: %s must be a number or hex string", what);
    return -1;
}

static int parse_protocol(const cJSON *proto, protocol_t *out)
{
    strcpy(out->mode, "udp");
    out->flags[0]    = '\0';
    out->tcp_seq_mode = TCP_SEQ_FIXED;
    out->tcp_seq_base = 0x12345678u;
    out->tcp_ack_base = 0x87654321u;
    out->icmp_type    = 8;
    out->icmp_code    = 0;
    if (!cJSON_IsObject(proto)) return 0;

    cJSON *m = cJSON_GetObjectItemCaseSensitive(proto, "name");
    if (!cJSON_IsString(m)) m = cJSON_GetObjectItemCaseSensitive(proto, "mode");
    if (m && !cJSON_IsString(m)) { LOG_ERROR("config: protocol.name must be a string"); return -1; }
    if (cJSON_IsString(m)) {
        strncpy(out->mode, m->valuestring, sizeof(out->mode) - 1);
        out->mode[sizeof(out->mode) - 1] = '\0';
    }
    if (strcasecmp(out->mode, "tcp") && strcasecmp(out->mode, "udp") && strcasecmp(out->mode, "icmp")) {
        LOG_ERROR("config: protocol.name '%s' must be tcp, udp or icmp", out->mode);
        return -1;
    }

    cJSON *opt = cJSON_GetObjectItemCaseSensitive(proto, "options");
    if (opt && !cJSON_IsObject(opt)) { LOG_ERROR("config: protocol.options must be an object"); return -1; }
    if (!cJSON_IsObject(opt)) return 0;

    cJSON *f = cJSON_GetObjectItemCaseSensitive(opt, "flags");
    if (cJSON_IsString(f)) {
        if (!valid_tcp_flags(f->valuestring)) {
            LOG_ERROR("config: protocol.options.flags '%s' has an invalid TCP flag (use fin/syn/rst/psh/ack/urg)", f->valuestring);
            return -1;
        }
        strncpy(out->flags, f->valuestring, sizeof(out->flags) - 1);
        out->flags[sizeof(out->flags) - 1] = '\0';
    } else if (f) {
        LOG_ERROR("config: protocol.options.flags must be a string"); return -1;
    }

    cJSON *sm = cJSON_GetObjectItemCaseSensitive(opt, "seq");
    if (!cJSON_IsString(sm)) sm = cJSON_GetObjectItemCaseSensitive(opt, "tcp_seq");
    if (cJSON_IsString(sm)) {
        if      (!strcasecmp(sm->valuestring, "fixed"))      out->tcp_seq_mode = TCP_SEQ_FIXED;
        else if (!strcasecmp(sm->valuestring, "random"))     out->tcp_seq_mode = TCP_SEQ_RANDOM;
        else if (!strcasecmp(sm->valuestring, "sequential")) out->tcp_seq_mode = TCP_SEQ_SEQUENTIAL;
        else { LOG_ERROR("config: protocol.options.seq '%s' must be fixed, random or sequential", sm->valuestring); return -1; }
    } else if (sm) {
        LOG_ERROR("config: protocol.options.seq must be a string"); return -1;
    }

    cJSON *sb = cJSON_GetObjectItemCaseSensitive(opt, "seq_base");
    if (!sb) sb = cJSON_GetObjectItemCaseSensitive(opt, "tcp_seq_base");
    if (sb && parse_u32_strict(sb, &out->tcp_seq_base, "protocol.options.seq_base") < 0) return -1;
    cJSON *ab = cJSON_GetObjectItemCaseSensitive(opt, "ack_base");
    if (!ab) ab = cJSON_GetObjectItemCaseSensitive(opt, "tcp_ack_base");
    if (ab && parse_u32_strict(ab, &out->tcp_ack_base, "protocol.options.ack_base") < 0) return -1;

    cJSON *it = cJSON_GetObjectItemCaseSensitive(opt, "icmp_type");
    if (it) {
        if (!cJSON_IsNumber(it) || it->valuedouble < 0 || it->valuedouble > 255) {
            LOG_ERROR("config: protocol.options.icmp_type out of range (0-255)"); return -1;
        }
        out->icmp_type = (uint8_t)it->valuedouble;
    }
    cJSON *ic = cJSON_GetObjectItemCaseSensitive(opt, "icmp_code");
    if (ic) {
        if (!cJSON_IsNumber(ic) || ic->valuedouble < 0 || ic->valuedouble > 255) {
            LOG_ERROR("config: protocol.options.icmp_code out of range (0-255)"); return -1;
        }
        out->icmp_code = (uint8_t)ic->valuedouble;
    }
    return 0;
}

static int parse_rule_direction(const cJSON *dir, source_pool_t *pool, protocol_t *proto,
                                const char *what)
{
    memset(pool, 0, sizeof(*pool));
    atomic_store(&pool->rr_ip_index, 0);
    atomic_store(&pool->rr_port_index, 0);
    pool->ip_strategy   = SELECT_ROUND_ROBIN;
    pool->port_strategy = SELECT_ROUND_ROBIN;

    if (!cJSON_IsObject(dir)) {
        LOG_ERROR("config: firewall rule missing '%s' object", what);
        return -1;
    }
    cJSON *opts = cJSON_GetObjectItemCaseSensitive(dir, "options");
    if (cJSON_IsObject(opts)) {
        cJSON *dedup = cJSON_GetObjectItemCaseSensitive(opts, "deduplicate");
        if (cJSON_IsBool(dedup)) pool->deduplicate = cJSON_IsTrue(dedup);
        cJSON *exc = cJSON_GetObjectItemCaseSensitive(opts, "exclude");
        if (cJSON_IsObject(exc)) {
            cJSON *pr = cJSON_GetObjectItemCaseSensitive(exc, "private");
            cJSON *rv = cJSON_GetObjectItemCaseSensitive(exc, "reserved");
            cJSON *mc = cJSON_GetObjectItemCaseSensitive(exc, "multicast");
            if (cJSON_IsBool(pr)) pool->exclude_private   = cJSON_IsTrue(pr);
            if (cJSON_IsBool(rv)) pool->exclude_reserved  = cJSON_IsTrue(rv);
            if (cJSON_IsBool(mc)) pool->exclude_multicast = cJSON_IsTrue(mc);
        }
        cJSON *strat = cJSON_GetObjectItemCaseSensitive(opts, "strategies");
        if (cJSON_IsObject(strat)) {
            pool->ip_strategy   = parse_strategy(cJSON_GetObjectItemCaseSensitive(strat, "ip"),   SELECT_ROUND_ROBIN);
            pool->port_strategy = parse_strategy(cJSON_GetObjectItemCaseSensitive(strat, "port"), SELECT_ROUND_ROBIN);
        }
    }
    cJSON *src = cJSON_GetObjectItemCaseSensitive(dir, "source");
    if (cJSON_IsArray(src)) {
        cJSON *p;
        cJSON_ArrayForEach(p, src)
            if (parse_single_provider(pool, p) < 0) return -1;
    } else if (cJSON_IsObject(src)) {
        if (parse_single_provider(pool, src) < 0) return -1;
    } else {
        LOG_ERROR("config: firewall rule '%s' missing 'source'", what);
        return -1;
    }
    cJSON *port = cJSON_GetObjectItemCaseSensitive(dir, "port");
    if (cJSON_IsObject(port)) {
        cJSON *sp = cJSON_GetObjectItemCaseSensitive(port, "src");
        if (cJSON_IsArray(sp)) {
            cJSON *p; cJSON_ArrayForEach(p, sp) {
                if (!cJSON_IsNumber(p)) continue;
                if (p->valuedouble < 1 || p->valuedouble > 65535) {
                    LOG_ERROR("config: %s port.src out of range", what);
                    return -1;
                }
                if (pool->port_count < MAX_SOURCE_PORTS)
                    pool->ports[pool->port_count++] = (uint16_t)p->valuedouble;
            }
        }
        cJSON *dp = cJSON_GetObjectItemCaseSensitive(port, "dst");
        if (!dp) dp = cJSON_GetObjectItemCaseSensitive(port, "dest");  /* accept "dest" alias */
        if (cJSON_IsArray(dp)) {
            cJSON *p; cJSON_ArrayForEach(p, dp) {
                if (!cJSON_IsNumber(p)) continue;
                if (p->valuedouble < 1 || p->valuedouble > 65535) {
                    LOG_ERROR("config: %s port.dst out of range", what);
                    return -1;
                }
                if (pool->dst_port_count < MAX_SOURCE_PORTS)
                    pool->dst_ports[pool->dst_port_count++] = (uint16_t)p->valuedouble;
            }
        }
    }
    /* Ports are optional. For the OUTGOING direction we must put a
     * concrete value on the wire, so if src/dst was omitted or null we
     * auto-select a random ephemeral port. For INCOMING an empty list
     * means "match any port", which needs no auto-selection. */
    if (strcmp(what, "outgoing") == 0) {
        if (pool->port_count == 0) {
            pool->ports[0] = random_ephemeral_port();
            pool->port_count = 1;
            LOG_INFO("config: %s port.src not set -> auto-selected %u", what, pool->ports[0]);
        }
        if (pool->dst_port_count == 0) {
            pool->dst_ports[0] = random_ephemeral_port();
            pool->dst_port_count = 1;
            LOG_INFO("config: %s port.dst not set -> auto-selected %u", what, pool->dst_ports[0]);
        }
    }

    if (parse_protocol(cJSON_GetObjectItemCaseSensitive(dir, "protocol"), proto) < 0) return -1;
    build_prefix_sum(pool);
    return 0;
}

static void parse_logger(const cJSON *lg, logger_settings_t *out)
{
    out->level = LVL_INFO;
    strcpy(out->driver, "console");
    strcpy(out->format, "%(asctime)s - %(name)s - %(levelname)s - %(message)s");
    out->console = 1;
    out->async = 1;
    out->rotate_size = 0;
    out->rotate_keep = 5;
    if (!cJSON_IsObject(lg)) return;

    cJSON *lvl = cJSON_GetObjectItemCaseSensitive(lg, "level");
    if (cJSON_IsString(lvl)) out->level = logger_level_from_string(lvl->valuestring);
    cJSON *drv = cJSON_GetObjectItemCaseSensitive(lg, "driver");
    if (cJSON_IsString(drv)) strncpy(out->driver, drv->valuestring, sizeof(out->driver) - 1);
    cJSON *fmt = cJSON_GetObjectItemCaseSensitive(lg, "format");
    if (cJSON_IsString(fmt)) strncpy(out->format, fmt->valuestring, sizeof(out->format) - 1);
    cJSON *con = cJSON_GetObjectItemCaseSensitive(lg, "console");
    if (cJSON_IsBool(con)) out->console = cJSON_IsTrue(con);
    cJSON *async = cJSON_GetObjectItemCaseSensitive(lg, "async");
    if (cJSON_IsBool(async)) out->async = cJSON_IsTrue(async);

    cJSON *opts = cJSON_GetObjectItemCaseSensitive(lg, "options");
    if (cJSON_IsObject(opts)) {
        cJSON *fp = cJSON_GetObjectItemCaseSensitive(opts, "file_path");
        if (cJSON_IsString(fp)) strncpy(out->file_path, fp->valuestring, sizeof(out->file_path) - 1);
        cJSON *rs = cJSON_GetObjectItemCaseSensitive(opts, "rotate_size");
        if (cJSON_IsNumber(rs)) out->rotate_size = (uint64_t)rs->valuedouble;
        cJSON *rk = cJSON_GetObjectItemCaseSensitive(opts, "rotate_keep");
        if (cJSON_IsNumber(rk)) out->rotate_keep = (int)rk->valuedouble;
    }
}

void config_build_logger_cfg(const config_t *cfg, logger_config_t *out)
{
    memset(out, 0, sizeof(*out));
    out->level             = cfg->logger.level;
    out->file_path         = cfg->logger.file_path[0] ? cfg->logger.file_path : NULL;
    out->format            = cfg->logger.format;
    out->name              = "injspoof";
    out->console_stderr    = 1;
    out->async             = cfg->logger.async;
    out->ring_capacity     = 0;
    out->file_rotate_size  = cfg->logger.rotate_size;
    out->file_rotate_keep  = cfg->logger.rotate_keep;

    unsigned drivers = 0;
    if (!strcasecmp(cfg->logger.driver, "file"))    drivers |= LOG_DRV_FILE;
    if (!strcasecmp(cfg->logger.driver, "syslog"))  drivers |= LOG_DRV_SYSLOG;
    if (!strcasecmp(cfg->logger.driver, "console")) drivers |= LOG_DRV_CONSOLE;
    if (!strcasecmp(cfg->logger.driver, "composite"))
        drivers |= LOG_DRV_FILE | LOG_DRV_CONSOLE;
    if (cfg->logger.console) drivers |= LOG_DRV_CONSOLE;
    if (drivers == 0) drivers = LOG_DRV_CONSOLE;
    out->drivers = drivers;
}

static const protocol_t *active_outgoing_protocol(const config_t *cfg)
{
    int ri = (cfg->peer_count > 0) ? cfg->peers[0].primary.rule_index : -1;
    if (ri >= 0 && ri < cfg->firewall_count)
        return &cfg->firewall[ri].outgoing_protocol;
    return NULL;
}

void config_apply_tcp_policy(const config_t *cfg)
{
    const protocol_t *proto = active_outgoing_protocol(cfg);
    pkt_tcp_policy_t mode = TCP_POL_FIXED;
    uint32_t seq_base = 0x12345678u, ack_base = 0x87654321u;
    if (proto) {
        switch (proto->tcp_seq_mode) {
            case TCP_SEQ_RANDOM:     mode = TCP_POL_RANDOM;     break;
            case TCP_SEQ_SEQUENTIAL: mode = TCP_POL_SEQUENTIAL; break;
            default:                 mode = TCP_POL_FIXED;      break;
        }
        seq_base = proto->tcp_seq_base;
        ack_base = proto->tcp_ack_base;
    }
    pkt_set_tcp_policy(mode, seq_base, ack_base);
    LOG_INFO("config: tcp policy mode=%s seq_base=0x%08x ack_base=0x%08x",
             mode == TCP_POL_RANDOM ? "random" :
             mode == TCP_POL_SEQUENTIAL ? "sequential" : "fixed",
             seq_base, ack_base);
}

void config_protocol_filter(const protocol_t *proto, protocol_filter_t *out)
{
    strncpy(out->mode, proto->mode, sizeof(out->mode) - 1);
    out->mode[sizeof(out->mode) - 1] = '\0';
    if      (!strcasecmp(proto->mode, "tcp"))  out->proto = IPPROTO_TCP;
    else if (!strcasecmp(proto->mode, "udp"))  out->proto = IPPROTO_UDP;
    else if (!strcasecmp(proto->mode, "icmp")) out->proto = IPPROTO_ICMP;
    else                                        out->proto = 0;
}

static int parse_api(const cJSON *api, api_endpoint_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!cJSON_IsObject(api)) { LOG_ERROR("config: 'api' object is required"); return -1; }
    cJSON *bind = cJSON_GetObjectItemCaseSensitive(api, "bind");
    if (!cJSON_IsString(bind)) {
        LOG_ERROR("config: 'api.bind' (\"host:port\") is required");
        return -1;
    }
    endpoint_t ep;
    if (parse_hostport(bind->valuestring, &ep, "api.bind") < 0) return -1;
    strncpy(out->address, ep.address, INET_ADDRSTRLEN - 1);
    out->port = ep.port;
    cJSON *t = cJSON_GetObjectItemCaseSensitive(api, "token");
    if (!cJSON_IsString(t) || t->valuestring[0] == '\0') {
        LOG_ERROR("config: 'api.token' is mandatory and must be non-empty");
        return -1;
    }
    strncpy(out->token, t->valuestring, sizeof(out->token) - 1);
    out->enabled = 1;
    return 0;
}

static int parse_peer_endpoint(const cJSON *obj, peer_endpoint_t *ep, const char *what)
{
    memset(ep, 0, sizeof(*ep));
    ep->rule_index = -1;
    ep->interface_index = -1;
    if (!cJSON_IsObject(obj)) { LOG_ERROR("config: %s must be an object", what); return -1; }

    cJSON *addr = cJSON_GetObjectItemCaseSensitive(obj, "address");
    if (!cJSON_IsString(addr)) { LOG_ERROR("config: %s.address required", what); return -1; }
    strncpy(ep->address, addr->valuestring, INET_ADDRSTRLEN - 1);

    cJSON *rule = cJSON_GetObjectItemCaseSensitive(obj, "rule");
    if (!cJSON_IsString(rule)) { LOG_ERROR("config: %s.rule required", what); return -1; }
    strncpy(ep->rule_tag, rule->valuestring, sizeof(ep->rule_tag) - 1);

    cJSON *iface = cJSON_GetObjectItemCaseSensitive(obj, "interface");
    if (!cJSON_IsString(iface)) { LOG_ERROR("config: %s.interface required", what); return -1; }
    strncpy(ep->interface_tag, iface->valuestring, sizeof(ep->interface_tag) - 1);

    return 0;
}

/* O(1) hid -> peer index map (FNV-1a + open addressing). */
static uint32_t hid_hash_key(const char *hid)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < HID_LEN; i++) { h ^= (uint8_t)hid[i]; h *= 16777619u; }
    return h;
}

static void build_hid_hash(config_t *cfg)
{
    for (int i = 0; i < HID_HASH_SIZE; i++) cfg->hid_hash[i] = -1;
    for (int i = 0; i < cfg->peer_count; i++) {
        uint32_t h = hid_hash_key(cfg->peers[i].hid) & (HID_HASH_SIZE - 1);
        while (cfg->hid_hash[h] != -1) h = (h + 1) & (HID_HASH_SIZE - 1);
        cfg->hid_hash[h] = i;
    }
}

int config_load(config_t *cfg, const char *path, int mode)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = mode;
    cfg->logger.level = LVL_INFO;
    strncpy(cfg->config_path, path, sizeof(cfg->config_path) - 1);

    FILE *f = fopen(path, "r");
    if (!f) { LOG_ERROR("config: open '%s': %s", path, strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0) { fclose(f); return -1; }
    fseek(f, 0, SEEK_SET);
    char *data = malloc((size_t)fsize + 1);
    if (!data) { fclose(f); return -1; }
    size_t nread = fread(data, 1, (size_t)fsize, f);
    data[nread] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        LOG_ERROR("config: JSON parse error near: %s", cJSON_GetErrorPtr());
        return -1;
    }

    int ret = -1;

    if (parse_api(cJSON_GetObjectItemCaseSensitive(root, "api"), &cfg->api) < 0)
        goto fail;

    parse_logger(cJSON_GetObjectItemCaseSensitive(root, "logger"), &cfg->logger);
    {
        cJSON *lg = cJSON_GetObjectItemCaseSensitive(root, "logger");
        cJSON *lvl = cJSON_IsObject(lg) ? cJSON_GetObjectItemCaseSensitive(lg, "level") : NULL;
        if (lvl && !cJSON_IsString(lvl)) { LOG_ERROR("config: logger.level must be a string"); goto fail; }
        if (cJSON_IsString(lvl)) {
            const char *L = lvl->valuestring;
            if (strcasecmp(L,"trace") && strcasecmp(L,"debug") && strcasecmp(L,"info") &&
                strcasecmp(L,"warn") && strcasecmp(L,"warning") && strcasecmp(L,"error") &&
                strcasecmp(L,"err") && strcasecmp(L,"fatal") && strcasecmp(L,"crit") && strcasecmp(L,"critical")) {
                LOG_ERROR("config: logger.level '%s' is not a valid level", L);
                goto fail;
            }
        }
    }

    strcpy(cfg->fastpath.mode, "auto");
    cfg->fastpath.zero_copy = 1;
    cfg->fastpath.busy_poll = 0;
    cfg->fastpath.queues    = 0;
    {
        cJSON *tuning = cJSON_GetObjectItemCaseSensitive(root, "tuning");
        cJSON *fp = cJSON_IsObject(tuning)
                  ? cJSON_GetObjectItemCaseSensitive(tuning, "fastpath") : NULL;
        if (cJSON_IsObject(fp)) {
            cJSON *m = cJSON_GetObjectItemCaseSensitive(fp, "mode");
            if (cJSON_IsString(m)) snprintf(cfg->fastpath.mode, sizeof(cfg->fastpath.mode), "%s", m->valuestring);
            cJSON *zc = cJSON_GetObjectItemCaseSensitive(fp, "zero_copy");
            if (cJSON_IsBool(zc)) cfg->fastpath.zero_copy = cJSON_IsTrue(zc);
            cJSON *bp = cJSON_GetObjectItemCaseSensitive(fp, "busy_poll");
            if (cJSON_IsBool(bp)) cfg->fastpath.busy_poll = cJSON_IsTrue(bp);
            cJSON *qs = cJSON_GetObjectItemCaseSensitive(fp, "queues");
            if (cJSON_IsNumber(qs)) cfg->fastpath.queues = (int)qs->valuedouble;
        }
        if (strcasecmp(cfg->fastpath.mode, "auto") &&
            strcasecmp(cfg->fastpath.mode, "af_xdp") &&
            strcasecmp(cfg->fastpath.mode, "af_packet")) {
            LOG_ERROR("config: tuning.fastpath.mode '%s' must be auto, af_xdp or af_packet", cfg->fastpath.mode);
            goto fail;
        }
        if (cfg->fastpath.queues < 0 || cfg->fastpath.queues > 4096) {
            LOG_ERROR("config: tuning.fastpath.queues %d out of range (0-4096)", cfg->fastpath.queues);
            goto fail;
        }
    }

    {
        cJSON *fw = cJSON_GetObjectItemCaseSensitive(root, "firewall");
        if (cJSON_IsArray(fw)) {
            cJSON *entry;
            cJSON_ArrayForEach(entry, fw) {
                if (cfg->firewall_count >= MAX_FIREWALL_RULES) {
                    LOG_ERROR("config: too many firewall rules (max %d)", MAX_FIREWALL_RULES);
                    goto fail;
                }
                firewall_rule_t *r = &cfg->firewall[cfg->firewall_count];
                memset(r, 0, sizeof(*r));
                cJSON *tag = cJSON_GetObjectItemCaseSensitive(entry, "tag");
                if (!cJSON_IsString(tag) || tag->valuestring[0] == '\0') {
                    LOG_ERROR("config: firewall rule missing 'tag'");
                    goto fail;
                }
                strncpy(r->tag, tag->valuestring, sizeof(r->tag) - 1);
                if (parse_rule_direction(cJSON_GetObjectItemCaseSensitive(entry, "outgoing"),
                                         &r->outgoing_pool, &r->outgoing_protocol, "outgoing") < 0)
                    goto fail;
                if (parse_rule_direction(cJSON_GetObjectItemCaseSensitive(entry, "incoming"),
                                         &r->incoming_pool, &r->incoming_protocol, "incoming") < 0)
                    goto fail;
                cfg->firewall_count++;
            }
        }
    }

    {
        cJSON *ifs = cJSON_GetObjectItemCaseSensitive(root, "interfaces");
        if (cJSON_IsArray(ifs)) {
            cJSON *entry;
            cJSON_ArrayForEach(entry, ifs) {
                if (cfg->interface_count >= MAX_INTERFACES) {
                    LOG_ERROR("config: too many interfaces (max %d)", MAX_INTERFACES);
                    goto fail;
                }
                interface_t *iface = &cfg->interfaces[cfg->interface_count];
                memset(iface, 0, sizeof(*iface));
                iface->fragment_size = DEFAULT_FRAGMENT_SIZE;
                iface->incoming_index = -1;
                iface->outgoing_index = -1;

                cJSON *tag = cJSON_GetObjectItemCaseSensitive(entry, "tag");
                if (!cJSON_IsString(tag) || tag->valuestring[0] == '\0') {
                    LOG_ERROR("config: interface missing 'tag'");
                    goto fail;
                }
                strncpy(iface->tag, tag->valuestring, sizeof(iface->tag) - 1);

                cJSON *in = cJSON_GetObjectItemCaseSensitive(entry, "incoming");
                if (cJSON_IsObject(in)) {
                    cJSON *name = cJSON_GetObjectItemCaseSensitive(in, "name");
                    if (cJSON_IsString(name)) strncpy(iface->incoming_name, name->valuestring, sizeof(iface->incoming_name) - 1);
                }
                cJSON *out = cJSON_GetObjectItemCaseSensitive(entry, "outgoing");
                if (cJSON_IsObject(out)) {
                    cJSON *name = cJSON_GetObjectItemCaseSensitive(out, "name");
                    if (cJSON_IsString(name)) strncpy(iface->outgoing_name, name->valuestring, sizeof(iface->outgoing_name) - 1);
                    cJSON *gw = cJSON_GetObjectItemCaseSensitive(out, "gateway");
                    if (cJSON_IsObject(gw)) {
                        cJSON *mac = cJSON_GetObjectItemCaseSensitive(gw, "mac_address");
                        if (cJSON_IsString(mac) && parse_mac(mac->valuestring, iface->outgoing_gateway_mac) < 0) {
                            LOG_ERROR("config: interface '%s' invalid gateway mac_address", iface->tag);
                            goto fail;
                        }
                    }
                }
                cJSON *frag = cJSON_GetObjectItemCaseSensitive(entry, "fragment_size");
                if (frag) {
                    if (!cJSON_IsNumber(frag) || frag->valuedouble < 576 || frag->valuedouble > 9216) {
                        LOG_ERROR("config: interface '%s' fragment_size out of range (576-9216)", iface->tag);
                        goto fail;
                    }
                    iface->fragment_size = (uint16_t)frag->valuedouble;
                }

                if (iface->outgoing_name[0] == '\0') {
                    LOG_ERROR("config: interface '%s' missing outgoing.name", iface->tag);
                    goto fail;
                }
                if (iface->incoming_name[0] == '\0')
                    strncpy(iface->incoming_name, iface->outgoing_name, sizeof(iface->incoming_name) - 1);

                if (detect_iface_mac(iface->outgoing_name, iface->outgoing_mac) < 0) {
                    LOG_ERROR("config: cannot detect MAC for interface '%s' (%s)",
                              iface->tag, iface->outgoing_name);
                    goto fail;
                }
                iface->outgoing_index = detect_iface_index(iface->outgoing_name);
                iface->incoming_index = detect_iface_index(iface->incoming_name);
                if (iface->outgoing_index < 0 || iface->incoming_index < 0) {
                    LOG_ERROR("config: cannot resolve index for interface '%s'", iface->tag);
                    goto fail;
                }
                cfg->interface_count++;
            }
        }
    }
    if (cfg->interface_count == 0) {
        LOG_ERROR("config: at least one interface is required");
        goto fail;
    }

    /* ---- Peers (both modes use a top-level "peers" array) ---- */
    {
        cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "peers");
        if (!cJSON_IsArray(peers))            /* tolerate legacy "peer" key */
            peers = cJSON_GetObjectItemCaseSensitive(root, "peer");
        if (!cJSON_IsArray(peers)) { LOG_ERROR("config: 'peers' array is required"); goto fail; }

        cJSON *entry;
        cJSON_ArrayForEach(entry, peers) {
            if (cfg->peer_count >= MAX_PEERS) {
                LOG_ERROR("config: too many peers (max %d)", MAX_PEERS);
                goto fail;
            }
            peer_t *p = &cfg->peers[cfg->peer_count];
            memset(p, 0, sizeof(*p));

            cJSON *hid = cJSON_GetObjectItemCaseSensitive(entry, "hid");
            if (!cJSON_IsString(hid) || strlen(hid->valuestring) != HID_LEN) {
                LOG_ERROR("config: peers[%d].hid must be a %d-char string", cfg->peer_count, HID_LEN);
                goto fail;
            }
            strncpy(p->hid, hid->valuestring, HID_LEN);

            if (parse_peer_endpoint(entry, &p->primary, "peers[]") < 0) goto fail;

            /* Client peers own a set of forwarders. */
            if (mode == MODE_CLIENT) {
                cJSON *fwds = cJSON_GetObjectItemCaseSensitive(entry, "forwards");
                if (!fwds) fwds = cJSON_GetObjectItemCaseSensitive(entry, "forwarder");
                if (cJSON_IsArray(fwds)) {
                    cJSON *fw;
                    cJSON_ArrayForEach(fw, fwds) {
                        if (p->forward_count >= MAX_FORWARDERS_PER_PEER) {
                            LOG_ERROR("config: peer '%s' has too many forwards (max %d)",
                                      p->hid, MAX_FORWARDERS_PER_PEER);
                            goto fail;
                        }
                        forwarder_t *f = &p->forwards[p->forward_count];
                        memset(f, 0, sizeof(*f));
                        cJSON *b = cJSON_GetObjectItemCaseSensitive(fw, "bind");
                        cJSON *r = cJSON_GetObjectItemCaseSensitive(fw, "redirect");
                        if (!cJSON_IsString(b) || parse_hostport(b->valuestring, &f->bind, "forwards.bind") < 0)
                            goto fail;
                        if (!cJSON_IsString(r) || parse_hostport(r->valuestring, &f->redirect, "forwards.redirect") < 0)
                            goto fail;
                        struct in_addr ra;
                        inet_pton(AF_INET, f->redirect.address, &ra);
                        f->redirect_ip_be   = ra.s_addr;
                        f->redirect_port_be = htons(f->redirect.port);
                        p->forward_count++;
                    }
                }
            }
            cfg->peer_count++;
        }
        if (cfg->peer_count == 0) { LOG_ERROR("config: at least one peer is required"); goto fail; }
    }

    /* ---- Resolve + validate peer references; build the hid hash ---- */
    {
        for (int i = 0; i < cfg->peer_count; i++) {
            for (int j = i + 1; j < cfg->peer_count; j++)
                if (!memcmp(cfg->peers[i].hid, cfg->peers[j].hid, HID_LEN)) {
                    LOG_ERROR("config: duplicate peer hid '%s'", cfg->peers[i].hid);
                    goto fail;
                }
            peer_endpoint_t *ep = &cfg->peers[i].primary;
            struct in_addr a;
            if (inet_pton(AF_INET, ep->address, &a) != 1) {
                LOG_ERROR("config: peer '%s' address '%s' is not valid IPv4", cfg->peers[i].hid, ep->address);
                goto fail;
            }
            ep->addr_be = a.s_addr;
            ep->rule_index = config_find_rule(cfg, ep->rule_tag);
            if (ep->rule_index < 0) {
                LOG_ERROR("config: peer '%s' references unknown rule '%s'", cfg->peers[i].hid, ep->rule_tag);
                goto fail;
            }
            ep->interface_index = config_find_interface(cfg, ep->interface_tag);
            if (ep->interface_index < 0) {
                LOG_ERROR("config: peer '%s' references unknown interface '%s'", cfg->peers[i].hid, ep->interface_tag);
                goto fail;
            }
        }
        build_hid_hash(cfg);

        if (mode == MODE_CLIENT) {
            int total_fwd = 0;
            for (int i = 0; i < cfg->peer_count; i++) total_fwd += cfg->peers[i].forward_count;
            if (total_fwd == 0) {
                LOG_ERROR("config: client requires at least one forwarder across its peers");
                goto fail;
            }
        }
    }

    ret = 0;
fail:
    cJSON_Delete(root);
    return ret;
}

void config_free(config_t *cfg) { (void)cfg; }

static void dump_endpoint(const char *label, const peer_endpoint_t *ep)
{
    LOG_INFO("config:   %s addr=%s rule=%s(%d) iface=%s(%d)",
             label, ep->address, ep->rule_tag, ep->rule_index,
             ep->interface_tag, ep->interface_index);
}

void config_dump(const config_t *cfg)
{
    const char *mode_str = (cfg->mode == MODE_CLIENT) ? "CLIENT" : "SERVER";
    LOG_INFO("config[%s]: api=%s:%u firewall_rules=%d interfaces=%d",
             mode_str, cfg->api.address, cfg->api.port,
             cfg->firewall_count, cfg->interface_count);

    LOG_INFO("config: %d peer(s)", cfg->peer_count);
    for (int i = 0; i < cfg->peer_count; i++) {
        const peer_t *p = &cfg->peers[i];
        LOG_INFO("config: peer[%d] hid=%s forwards=%d", i, p->hid, p->forward_count);
        dump_endpoint("endpoint", &p->primary);
        for (int f = 0; f < p->forward_count; f++)
            LOG_INFO("config:     forward[%d] bind=%s:%u redirect=%s:%u", f,
                     p->forwards[f].bind.address, p->forwards[f].bind.port,
                     p->forwards[f].redirect.address, p->forwards[f].redirect.port);
    }
    for (int i = 0; i < cfg->firewall_count; i++) {
        const firewall_rule_t *r = &cfg->firewall[i];
        LOG_INFO("config: rule[%d] tag=%s out=%u hosts/%d sport/%d dport proto=%s | in=%u hosts/%d sport proto=%s",
                 i, r->tag, r->outgoing_pool.total_hosts, r->outgoing_pool.port_count,
                 r->outgoing_pool.dst_port_count, r->outgoing_protocol.mode,
                 r->incoming_pool.total_hosts, r->incoming_pool.port_count,
                 r->incoming_protocol.mode);
    }
    for (int i = 0; i < cfg->interface_count; i++) {
        const interface_t *fc = &cfg->interfaces[i];
        LOG_INFO("config: iface[%d] tag=%s in=%s(%d) out=%s(%d) frag=%u gw=%02x:%02x:%02x:%02x:%02x:%02x",
                 i, fc->tag, fc->incoming_name, fc->incoming_index,
                 fc->outgoing_name, fc->outgoing_index, fc->fragment_size,
                 fc->outgoing_gateway_mac[0], fc->outgoing_gateway_mac[1], fc->outgoing_gateway_mac[2],
                 fc->outgoing_gateway_mac[3], fc->outgoing_gateway_mac[4], fc->outgoing_gateway_mac[5]);
    }
    LOG_INFO("config: api endpoint %s:%u (auth=token)", cfg->api.address, cfg->api.port);
}

int config_find_rule(const config_t *cfg, const char *tag)
{
    if (!tag || !tag[0]) return -1;
    for (int i = 0; i < cfg->firewall_count; i++)
        if (!strcmp(cfg->firewall[i].tag, tag)) return i;
    return -1;
}

int config_find_interface(const config_t *cfg, const char *tag)
{
    if (!tag || !tag[0]) return -1;
    for (int i = 0; i < cfg->interface_count; i++)
        if (!strcmp(cfg->interfaces[i].tag, tag)) return i;
    return -1;
}

int config_find_peer_by_hid(const config_t *cfg, const char *hid)
{
    if (!hid) return -1;
    uint32_t h = hid_hash_key(hid) & (HID_HASH_SIZE - 1);
    for (int probes = 0; probes < HID_HASH_SIZE; probes++) {
        int32_t idx = cfg->hid_hash[h];
        if (idx < 0) return -1;                       /* empty slot -> miss */
        if (!memcmp(cfg->peers[idx].hid, hid, HID_LEN)) return idx;
        h = (h + 1) & (HID_HASH_SIZE - 1);
    }
    return -1;
}

#include <time.h>
#include <sys/syscall.h>

static __thread uint64_t s_xorshift_state = 0;
static inline uint64_t fast_rand(void)
{
    uint64_t x = s_xorshift_state;
    if (__builtin_expect(x == 0, 0)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t tid = (uint64_t)syscall(SYS_gettid);
        x = (uint64_t)ts.tv_sec * 1000000007ull
          ^ (uint64_t)ts.tv_nsec
          ^ (tid * 0x9E3779B97F4A7C15ull)
          ^ (uint64_t)(uintptr_t)&x;
        if (x == 0) x = 0xDEADBEEFDEADBEEFull;
        s_xorshift_state = x;
    }
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    s_xorshift_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static int locate_block(const source_pool_t *p, uint32_t idx)
{
    int lo = 0, hi = p->count - 1;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if ((uint64_t)idx >= p->prefix_sum[mid]) lo = mid + 1;
        else                                      hi = mid;
    }
    return lo;
}

uint32_t config_pool_next_source_ip(source_pool_t *pool)
{
    if (pool->total_hosts == 0) return 0;
    if (pool->total_hosts == 1) return htonl(pool->subnets[0].first_ip);
    uint32_t idx;
    if (pool->ip_strategy == SELECT_RANDOM)
        idx = (uint32_t)(fast_rand() % pool->total_hosts);
    else
        idx = atomic_fetch_add_explicit(&pool->rr_ip_index, 1,
                                        memory_order_relaxed) % pool->total_hosts;
    int b = locate_block(pool, idx);
    uint64_t base = (b == 0) ? 0 : pool->prefix_sum[b - 1];
    uint32_t off  = (uint32_t)((uint64_t)idx - base);
    return htonl(pool->subnets[b].first_ip + off);
}

uint16_t config_pool_next_source_port(source_pool_t *pool)
{
    if (pool->port_count == 0) return 0;
    if (pool->port_count == 1) return pool->ports[0];
    uint32_t idx;
    if (pool->port_strategy == SELECT_RANDOM)
        idx = (uint32_t)(fast_rand() % (uint32_t)pool->port_count);
    else
        idx = atomic_fetch_add_explicit(&pool->rr_port_index, 1,
                                        memory_order_relaxed) % (uint32_t)pool->port_count;
    return pool->ports[idx];
}
