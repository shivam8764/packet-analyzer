#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <stdio.h>

typedef struct {
    pcap_t *handle;
    FILE *log_fp;
    int packet_count;
    int packets_captured;
} capture_ctx_t;

/* List all available network interfaces. Returns 0 on success, -1 on error. */
int list_interfaces(void);

/* Open a capture session on the given interface with an optional BPF filter.
   ctx->log_fp must be set before calling this (or NULL for no file logging).
   If sig_handle is non-NULL, *sig_handle is set to the pcap handle after open
   but before pcap_loop, so a signal handler can call pcap_breakloop.
   Returns 0 on success, -1 on error. */
int start_capture(capture_ctx_t *ctx, const char *interface,
                  int packet_count, const char *filter_expr,
                  pcap_t **sig_handle);

/* Packet handler callback for pcap_loop. */
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *header,
                    const unsigned char *packet);

/* Close the capture session and release resources. */
void stop_capture(capture_ctx_t *ctx);

#endif /* CAPTURE_H */
