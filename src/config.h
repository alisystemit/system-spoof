#ifndef INJSPOOF_CONFIG_H
#define INJSPOOF_CONFIG_H

#include <stdint.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <net/if.h>

#include "logger.h"

#define MODE_CLIENT 0
#define MODE_SERVER 1

/* Capacity limits */
#define MAX_SOURCE_BLOCKS  4096
#define MAX_SOURCE_PORTS   64
#define MAX_PROVIDERS      8
#define MAX_PATH_LEN       256
#ifndef MAX_PEERS
#define MAX_PEERS          4096   /* peers (server) / client peers; build-override */
#endif
#define MAX_FORWARDERS_PER_PEER 16    /* client forwarders per peer */
#define MAX_FIREWALL_RULES 32
#define MAX_INTERFACES     16
#define HID_LEN            5
#define HID_HASH_SIZE      16384  /* power of two; O(1) hid -> peer lookup */

#define DEFAULT_FRAGMENT_SIZE 1400

typedef enum { ADDR_STATIC = 0, ADDR_FILE = 1 } addr_type_t;
typedef enum { SELECT_ROUND_ROBIN = 0, SELECT_RANDOM = 1 } select_strategy_t;

typedef struct {
    char     address[INET_ADDRSTRLEN];
    uint16_t port;
} endpoint_t;

typedef enum {
    TCP_SEQ_FIXED      = 0,
    TCP_SEQ_RANDOM     = 1,
    TCP_SEQ_SEQUENTIAL = 2,
} tcp_seq_mode_t;

typedef struct {
    char mode[16];
    char flags[32];
    tcp_seq_mode_t tcp_seq_mode;
    uint32_t tcp_seq_base;
    uint32_t tcp_ack_base;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
} protocol_t;

typedef struct {
    uint32_t first_ip;
    uint32_t last_ip;
    uint32_t host_count;
} cidr_t;

typedef struct {
    addr_type_t type;
    char        path[MAX_PATH_LEN];
} provider_t;

typedef struct {
    provider_t providers[MAX_PROVIDERS];
    int        provider_count;

    cidr_t     subnets[MAX_SOURCE_BLOCKS];
    int        count;
    uint32_t   total_hosts;

    uint64_t   prefix_sum[MAX_SOURCE_BLOCKS];

    uint16_t   ports[MAX_SOURCE_PORTS];
    int        port_count;

    uint16_t   dst_ports[MAX_SOURCE_PORTS];
    int        dst_port_count;

    int        deduplicate;
    int        exclude_private;
    int        exclude_reserved;
    int        exclude_multicast;
    select_strategy_t ip_strategy;
    select_strategy_t port_strategy;

    _Atomic uint32_t rr_ip_index;
    _Atomic uint32_t rr_port_index;
} source_pool_t;

typedef struct {
    char          tag[16];
    source_pool_t outgoing_pool;
    protocol_t    outgoing_protocol;
    source_pool_t incoming_pool;
    protocol_t    incoming_protocol;
} firewall_rule_t;

/* A client forwarder: a local UDP listener whose traffic is tunnelled to
 * its owning peer; the redirect (server-side target) is encoded into the
 * per-packet header. */
typedef struct {
    endpoint_t bind;
    endpoint_t redirect;
    uint32_t   redirect_ip_be;    /* network order */
    uint16_t   redirect_port_be;  /* network order */
} forwarder_t;

typedef struct {
    char     tag[16];
    char     incoming_name[IFNAMSIZ];
    char     outgoing_name[IFNAMSIZ];
    uint8_t  outgoing_gateway_mac[6];
    uint16_t fragment_size;
    int      incoming_index;
    int      outgoing_index;
    uint8_t  outgoing_mac[6];
} interface_t;

/* The (address, rule, interface) tuple every peer resolves to. */
typedef struct {
    char     address[INET_ADDRSTRLEN];
    char     rule_tag[16];
    char     interface_tag[16];
    uint32_t addr_be;            /* resolved, network order */
    int      rule_index;         /* -> firewall[]   (-1 if unresolved) */
    int      interface_index;    /* -> interfaces[] (-1 if unresolved) */
} peer_endpoint_t;

/* A peer (HID-identified). Server peers carry just the endpoint; client
 * peers additionally own a set of forwarders. */
typedef struct {
    char            hid[HID_LEN + 1];
    peer_endpoint_t primary;
    /* client only */
    forwarder_t     forwards[MAX_FORWARDERS_PER_PEER];
    int             forward_count;
} peer_t;

typedef struct {
    char mode[16];
    int  proto;
} protocol_filter_t;

typedef struct {
    char     address[INET_ADDRSTRLEN];
    uint16_t port;
    char     token[128];
    int      enabled;
} api_endpoint_t;

typedef struct {
    char mode[16];
    int  zero_copy;
    int  busy_poll;
    int  queues;
} fastpath_settings_t;

typedef struct {
    log_level_t level;
    char        driver[16];
    char        file_path[MAX_PATH_LEN];
    char        format[256];
    int         console;
    int         async;
    uint64_t    rotate_size;
    int         rotate_keep;
} logger_settings_t;

typedef struct {
    api_endpoint_t  api;

    /* Peers: server "peers"[] OR client "peer"[] (both arrays now). */
    peer_t          peers[MAX_PEERS];
    int             peer_count;
    /* O(1) hid -> peer index map (open addressing; -1 = empty). */
    int32_t         hid_hash[HID_HASH_SIZE];

    firewall_rule_t firewall[MAX_FIREWALL_RULES];
    int             firewall_count;
    interface_t     interfaces[MAX_INTERFACES];
    int             interface_count;
    fastpath_settings_t fastpath;
    logger_settings_t logger;
    int             mode;
    char            config_path[MAX_PATH_LEN];
} config_t;

int  config_load(config_t *cfg, const char *path, int mode);
void config_free(config_t *cfg);
void config_dump(const config_t *cfg);
uint32_t config_pool_next_source_ip(source_pool_t *pool);
uint16_t config_pool_next_source_port(source_pool_t *pool);
void config_build_logger_cfg(const config_t *cfg, logger_config_t *out);
void config_apply_tcp_policy(const config_t *cfg);
int config_find_rule(const config_t *cfg, const char *tag);
int config_find_interface(const config_t *cfg, const char *tag);
int config_find_peer_by_hid(const config_t *cfg, const char *hid);
void config_protocol_filter(const protocol_t *proto, protocol_filter_t *out);

#endif /* INJSPOOF_CONFIG_H */
