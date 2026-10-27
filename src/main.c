/* ====================================================================
 *  injspoof — entry point
 *
 *  Initialises the logger and metrics before parsing config so that
 *  config_load() messages flow through the standardised logger from
 *  the very first call. After config_load, the logger is
 *  reconfigured with user-specified driver / level / format.
 * ==================================================================== */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include "client.h"
#include "server.h"
#include "logger.h"
#include "metrics.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Global shutdown flag, monitored by client/server event loops. */
volatile sig_atomic_t g_shutdown = 0;

/* argv preserved so we can execve() ourselves on hard reload. */
char **g_argv_saved = NULL;

static void on_signal(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --mode <client|server> --config <path.json>\n\n"
        "Options:\n"
        "  -m, --mode    'client' or 'server'\n"
        "  -c, --config  JSON configuration path\n"
        "  -h, --help    show this help and exit\n\n"
        "Requires root or CAP_NET_RAW.\n",
        prog);
}

static void early_logger_bootstrap(void)
{
    logger_config_t cfg = {
        .level = LVL_INFO,
        .drivers = LOG_DRV_CONSOLE,
        .name = "injspoof",
        .format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        .console_stderr = 1,
        .async = 1,
    };
    logger_init(&cfg);
}

int main(int argc, char *argv[])
{
    g_argv_saved = argv;

    const char *mode_str = NULL, *config_path = NULL;

    static struct option longs[] = {
        {"mode",   required_argument, 0, 'm'},
        {"config", required_argument, 0, 'c'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:c:h", longs, NULL)) != -1) {
        switch (opt) {
            case 'm': mode_str    = optarg; break;
            case 'c': config_path = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (!mode_str || !config_path) {
        fprintf(stderr, "%s: --mode and --config are required\n", argv[0]);
        print_usage(argv[0]);
        return 1;
    }

    int mode;
    if      (!strcmp(mode_str, "client")) mode = MODE_CLIENT;
    else if (!strcmp(mode_str, "server")) mode = MODE_SERVER;
    else {
        fprintf(stderr, "%s: invalid mode '%s'\n", argv[0], mode_str);
        return 1;
    }

    /* Bring up logger + metrics before anything else logs. */
    early_logger_bootstrap();
    metrics_init();

    if (getuid() != 0 && geteuid() != 0)
        LOG_WARN("not running as root - raw socket operations may fail");

    /* Signal handlers */
    struct sigaction sa = { 0 };
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Load config */
    config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) { LOG_ERROR("oom"); return 1; }

    if (config_load(cfg, config_path, mode) < 0) {
        LOG_ERROR("config load failed from '%s'", config_path);
        free(cfg); return 1;
    }

    /* Reconfigure logger with user-specified settings */
    logger_config_t lcfg;
    config_build_logger_cfg(cfg, &lcfg);
    logger_reconfigure(&lcfg);

    /* Push protocol.options.tcp_seq{,_base},tcp_ack_base into packet.c
     * globals so the JSON values actually take effect. */
    config_apply_tcp_policy(cfg);

    config_dump(cfg);
    LOG_INFO("injspoof starting in %s mode", mode_str);

    int rc = (mode == MODE_CLIENT) ? client_run(cfg) : server_run(cfg);

    LOG_INFO("injspoof exited rc=%d", rc);
    logger_shutdown();
    config_free(cfg);
    free(cfg);
    return rc;
}
