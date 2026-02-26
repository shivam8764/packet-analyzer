#include "capture.h"
#include "parser.h"

#include <pcap.h>
#include <stdio.h>
#include <string.h>

int list_interfaces(void)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }

    printf("Available network interfaces:\n");
    int i = 0;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        printf("  %d. %s", ++i, dev->name);
        if (dev->description)
            printf("  (%s)", dev->description);
        printf("\n");
    }

    if (i == 0)
        printf("  No interfaces found. Are you running as root/sudo?\n");

    pcap_freealldevs(alldevs);
    return 0;
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    capture_ctx_t *ctx = (capture_ctx_t *)user_data;
    ctx->packets_captured++;

    print_packet(stdout, ctx->log_fp, packet, header->caplen,
                 ctx->packets_captured);
}

int start_capture(capture_ctx_t *ctx, const char *interface,
                  int packet_count, const char *filter_expr,
                  pcap_t **sig_handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    ctx->handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
    if (!ctx->handle) {
        fprintf(stderr, "Error opening %s: %s\n", interface, errbuf);
        return -1;
    }

    if (filter_expr && filter_expr[0] != '\0') {
        struct bpf_program fp;
        if (pcap_compile(ctx->handle, &fp, filter_expr, 0,
                         PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Bad filter '%s': %s\n",
                    filter_expr, pcap_geterr(ctx->handle));
            pcap_close(ctx->handle);
            ctx->handle = NULL;
            return -1;
        }
        if (pcap_setfilter(ctx->handle, &fp) == -1) {
            fprintf(stderr, "Error setting filter: %s\n",
                    pcap_geterr(ctx->handle));
            pcap_freecode(&fp);
            pcap_close(ctx->handle);
            ctx->handle = NULL;
            return -1;
        }
        pcap_freecode(&fp);
    }

    ctx->packet_count = packet_count;
    ctx->packets_captured = 0;

    /* Expose handle for signal handler before entering pcap_loop */
    if (sig_handle)
        *sig_handle = ctx->handle;

    printf("Capturing on %s", interface);
    if (filter_expr && filter_expr[0] != '\0')
        printf(" with filter: %s", filter_expr);
    if (packet_count > 0)
        printf(" (max %d packets)", packet_count);
    printf("\nPress Ctrl+C to stop...\n");

    pcap_loop(ctx->handle, packet_count, packet_handler, (unsigned char *)ctx);

    printf("\n%d packet(s) captured.\n", ctx->packets_captured);
    return 0;
}

void stop_capture(capture_ctx_t *ctx)
{
    if (ctx->handle) {
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }
    if (ctx->log_fp) {
        fclose(ctx->log_fp);
        ctx->log_fp = NULL;
    }
}
