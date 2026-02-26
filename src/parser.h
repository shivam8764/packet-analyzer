#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* Parsed Ethernet frame info */
typedef struct {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
} eth_info_t;

/* Parsed IPv4 header info */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t ttl;
    uint8_t protocol;
    uint8_t ihl; /* header length in 32-bit words */
} ip_info_t;

/* Parsed TCP segment info */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t flags; /* raw flags byte: FIN=0x01 SYN=0x02 RST=0x04 ACK=0x10 */
    int syn;
    int ack;
    int fin;
    int rst;
} tcp_info_t;

/* Parsed UDP datagram info */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
} udp_info_t;

/* Parsed ICMP message info */
typedef struct {
    uint8_t type;
    uint8_t code;
} icmp_info_t;

/* Parse an Ethernet frame. Returns 0 on success, -1 if packet is too short. */
int parse_ethernet(const uint8_t *packet, size_t len, eth_info_t *info);

/* Parse an IPv4 header starting at `data`. Returns 0 on success, -1 on error. */
int parse_ipv4(const uint8_t *data, size_t len, ip_info_t *info);

/* Parse a TCP header starting at `data`. Returns 0 on success, -1 on error. */
int parse_tcp(const uint8_t *data, size_t len, tcp_info_t *info);

/* Parse a UDP header starting at `data`. Returns 0 on success, -1 on error. */
int parse_udp(const uint8_t *data, size_t len, udp_info_t *info);

/* Parse an ICMP header starting at `data`. Returns 0 on success, -1 on error. */
int parse_icmp(const uint8_t *data, size_t len, icmp_info_t *info);

/* Format a MAC address into buf (at least 18 bytes). */
void format_mac(const uint8_t *mac, char *buf, size_t buflen);

/* Format an IPv4 address (network byte order) into buf (at least 16 bytes). */
void format_ipv4(uint32_t ip, char *buf, size_t buflen);

/* Print full packet analysis to the given stream(s). */
void print_packet(FILE *out, FILE *log_fp, const uint8_t *packet, size_t len,
                  int packet_num);

#endif /* PARSER_H */
