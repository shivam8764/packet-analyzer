#include "capture.h"
#include "parser.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *g_handle; /* only for signal handler */

static void signal_handler(int sig)
{
    (void)sig;
    if (g_handle)
        pcap_breakloop(g_handle);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s <interface> [packet_count] [filter_expression]\n"
            "  %s --list\n\n"
            "Examples:\n"
            "  %s eth0              Capture all packets on eth0\n"
            "  %s eth0 100          Capture 100 packets on eth0\n"
            "  %s eth0 0 \"tcp\"      Capture TCP packets until interrupted\n"
            "  %s eth0 50 \"udp port 53\"  Capture 50 DNS packets\n",
            prog, prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--list") == 0)
        return list_interfaces() < 0 ? 1 : 0;

    const char *interface = argv[1];
    int packet_count = 0; /* 0 = unlimited */
    const char *filter_expr = NULL;

    if (argc >= 3)
        packet_count = atoi(argv[2]);
    if (argc >= 4)
        filter_expr = argv[3];

    capture_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ctx.log_fp = fopen("capture.log", "w");
    if (!ctx.log_fp)
        fprintf(stderr, "Warning: could not open capture.log for writing\n");

    /* Set up Ctrl+C handler */
    signal(SIGINT, signal_handler);

    int ret = start_capture(&ctx, interface, packet_count, filter_expr,
                            &g_handle);

    stop_capture(&ctx);
    return ret < 0 ? 1 : 0;
}
