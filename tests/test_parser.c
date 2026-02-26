#include "../src/parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, name)                                    \
    do {                                                      \
        tests_run++;                                          \
        if (cond) {                                           \
            printf("[PASS] %s\n", name);                      \
            tests_passed++;                                   \
        } else {                                              \
            printf("[FAIL] %s  (%s:%d)\n", name, __FILE__,    \
                   __LINE__);                                 \
        }                                                     \
    } while (0)

/* ------------------------------------------------------------------ */
/* Test: short/malformed packets don't crash the parser               */
/* ------------------------------------------------------------------ */
static void test_short_packets(void)
{
    eth_info_t eth;
    ip_info_t ip;
    tcp_info_t tcp;
    udp_info_t udp;
    icmp_info_t icmp;

    /* Empty packet */
    ASSERT(parse_ethernet(NULL, 0, &eth) == -1,
           "ethernet: NULL packet returns -1");
    ASSERT(parse_ethernet((const uint8_t *)"", 0, &eth) == -1,
           "ethernet: zero-length packet returns -1");

    /* Too-short Ethernet (< 14 bytes) */
    uint8_t short_eth[10] = {0};
    ASSERT(parse_ethernet(short_eth, sizeof(short_eth), &eth) == -1,
           "ethernet: 10-byte packet returns -1");

    /* Too-short IP (< 20 bytes) */
    uint8_t short_ip[10] = {0x45}; /* version 4, ihl 5 */
    ASSERT(parse_ipv4(short_ip, sizeof(short_ip), &ip) == -1,
           "ipv4: 10-byte packet returns -1");

    /* Bad IP version */
    uint8_t bad_ver[20] = {0x65}; /* version 6 pretending to be IPv4 */
    ASSERT(parse_ipv4(bad_ver, sizeof(bad_ver), &ip) == -1,
           "ipv4: version != 4 returns -1");

    /* IHL too large for packet */
    uint8_t big_ihl[20] = {0x4F}; /* ihl = 15 => 60 bytes, but only 20 */
    ASSERT(parse_ipv4(big_ihl, sizeof(big_ihl), &ip) == -1,
           "ipv4: ihl exceeds length returns -1");

    /* Too-short TCP (< 20 bytes) */
    uint8_t short_tcp[10] = {0};
    ASSERT(parse_tcp(short_tcp, sizeof(short_tcp), &tcp) == -1,
           "tcp: 10-byte data returns -1");

    /* Too-short UDP (< 8 bytes) */
    uint8_t short_udp[4] = {0};
    ASSERT(parse_udp(short_udp, sizeof(short_udp), &udp) == -1,
           "udp: 4-byte data returns -1");

    /* Too-short ICMP (< 4 bytes) */
    uint8_t short_icmp[2] = {0};
    ASSERT(parse_icmp(short_icmp, sizeof(short_icmp), &icmp) == -1,
           "icmp: 2-byte data returns -1");

    /* NULL pointers */
    ASSERT(parse_ipv4(NULL, 20, &ip) == -1,  "ipv4: NULL data returns -1");
    ASSERT(parse_tcp(NULL, 20, &tcp) == -1,   "tcp: NULL data returns -1");
    ASSERT(parse_udp(NULL, 8, &udp) == -1,    "udp: NULL data returns -1");
    ASSERT(parse_icmp(NULL, 4, &icmp) == -1,  "icmp: NULL data returns -1");
}

/* ------------------------------------------------------------------ */
/* Test: ARP EtherType is correctly identified                        */
/* ------------------------------------------------------------------ */
static void test_arp_ethertype(void)
{
    /* Build a minimal 14-byte Ethernet header with EtherType = ARP (0x0806) */
    uint8_t frame[14];
    memset(frame, 0, sizeof(frame));

    /* dst MAC: ff:ff:ff:ff:ff:ff (broadcast) */
    memset(frame, 0xFF, 6);
    /* src MAC: aa:bb:cc:dd:ee:ff */
    frame[6]  = 0xAA; frame[7]  = 0xBB; frame[8]  = 0xCC;
    frame[9]  = 0xDD; frame[10] = 0xEE; frame[11] = 0xFF;
    /* EtherType: 0x0806 (ARP) in network byte order */
    frame[12] = 0x08;
    frame[13] = 0x06;

    eth_info_t eth;
    int rc = parse_ethernet(frame, sizeof(frame), &eth);

    ASSERT(rc == 0, "arp: parse succeeds");
    ASSERT(eth.ethertype == 0x0806, "arp: ethertype is 0x0806");
    ASSERT(eth.dst_mac[0] == 0xFF && eth.dst_mac[5] == 0xFF,
           "arp: dst MAC is broadcast");
    ASSERT(eth.src_mac[0] == 0xAA && eth.src_mac[5] == 0xFF,
           "arp: src MAC parsed correctly");
}

/* ------------------------------------------------------------------ */
/* Test: TCP flags are correctly parsed                               */
/* ------------------------------------------------------------------ */
static void test_tcp_flags(void)
{
    /* Build a minimal 20-byte TCP header */
    uint8_t tcp_hdr[20];
    memset(tcp_hdr, 0, sizeof(tcp_hdr));

    /* src port: 12345 (0x3039) */
    tcp_hdr[0] = 0x30;
    tcp_hdr[1] = 0x39;
    /* dst port: 443 (0x01BB) */
    tcp_hdr[2] = 0x01;
    tcp_hdr[3] = 0xBB;
    /* Flags byte at offset 13: SYN (0x02) */
    tcp_hdr[13] = 0x02;

    tcp_info_t tcp;
    int rc = parse_tcp(tcp_hdr, sizeof(tcp_hdr), &tcp);

    ASSERT(rc == 0, "tcp_syn: parse succeeds");
    ASSERT(tcp.src_port == 12345, "tcp_syn: src port is 12345");
    ASSERT(tcp.dst_port == 443, "tcp_syn: dst port is 443");
    ASSERT(tcp.syn == 1, "tcp_syn: SYN flag set");
    ASSERT(tcp.ack == 0, "tcp_syn: ACK flag not set");
    ASSERT(tcp.fin == 0, "tcp_syn: FIN flag not set");
    ASSERT(tcp.rst == 0, "tcp_syn: RST flag not set");

    /* SYN+ACK */
    tcp_hdr[13] = 0x12; /* SYN=0x02 | ACK=0x10 */
    rc = parse_tcp(tcp_hdr, sizeof(tcp_hdr), &tcp);
    ASSERT(rc == 0, "tcp_synack: parse succeeds");
    ASSERT(tcp.syn == 1, "tcp_synack: SYN flag set");
    ASSERT(tcp.ack == 1, "tcp_synack: ACK flag set");

    /* FIN+ACK */
    tcp_hdr[13] = 0x11; /* FIN=0x01 | ACK=0x10 */
    rc = parse_tcp(tcp_hdr, sizeof(tcp_hdr), &tcp);
    ASSERT(rc == 0, "tcp_finack: parse succeeds");
    ASSERT(tcp.fin == 1, "tcp_finack: FIN flag set");
    ASSERT(tcp.ack == 1, "tcp_finack: ACK flag set");
    ASSERT(tcp.syn == 0, "tcp_finack: SYN flag not set");

    /* RST */
    tcp_hdr[13] = 0x04; /* RST=0x04 */
    rc = parse_tcp(tcp_hdr, sizeof(tcp_hdr), &tcp);
    ASSERT(rc == 0, "tcp_rst: parse succeeds");
    ASSERT(tcp.rst == 1, "tcp_rst: RST flag set");
    ASSERT(tcp.syn == 0, "tcp_rst: SYN flag not set");
    ASSERT(tcp.ack == 0, "tcp_rst: ACK flag not set");
}

/* ------------------------------------------------------------------ */
/* Test: UDP length is correctly parsed                               */
/* ------------------------------------------------------------------ */
static void test_udp_length(void)
{
    /* Build a minimal 8-byte UDP header */
    uint8_t udp_hdr[8];
    memset(udp_hdr, 0, sizeof(udp_hdr));

    /* src port: 53 (0x0035) */
    udp_hdr[0] = 0x00;
    udp_hdr[1] = 0x35;
    /* dst port: 1024 (0x0400) */
    udp_hdr[2] = 0x04;
    udp_hdr[3] = 0x00;
    /* length: 512 (0x0200) */
    udp_hdr[4] = 0x02;
    udp_hdr[5] = 0x00;

    udp_info_t udp;
    int rc = parse_udp(udp_hdr, sizeof(udp_hdr), &udp);

    ASSERT(rc == 0, "udp: parse succeeds");
    ASSERT(udp.src_port == 53, "udp: src port is 53");
    ASSERT(udp.dst_port == 1024, "udp: dst port is 1024");
    ASSERT(udp.length == 512, "udp: length is 512");
}

/* ------------------------------------------------------------------ */
/* Test: format helpers                                               */
/* ------------------------------------------------------------------ */
static void test_format_helpers(void)
{
    char buf[32];

    uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    format_mac(mac, buf, sizeof(buf));
    ASSERT(strcmp(buf, "de:ad:be:ef:ca:fe") == 0, "format_mac: correct output");

    /* 192.168.1.1 in network byte order */
    uint32_t ip;
    uint8_t ip_bytes[4] = {192, 168, 1, 1};
    memcpy(&ip, ip_bytes, 4);
    format_ipv4(ip, buf, sizeof(buf));
    ASSERT(strcmp(buf, "192.168.1.1") == 0, "format_ipv4: correct output");
}

/* ------------------------------------------------------------------ */
/* Test: print_packet with malformed data doesn't crash               */
/* ------------------------------------------------------------------ */
static void test_print_packet_no_crash(void)
{
    /* Discard output to /dev/null */
    FILE *devnull = fopen("/dev/null", "w");

    /* Empty packet */
    print_packet(devnull, NULL, (const uint8_t *)"", 0, 1);
    /* Just an Ethernet header, no payload */
    uint8_t eth_only[14] = {0};
    eth_only[12] = 0x08; eth_only[13] = 0x00; /* IPv4 ethertype */
    print_packet(devnull, NULL, eth_only, sizeof(eth_only), 2);

    if (devnull)
        fclose(devnull);

    ASSERT(1, "print_packet: no crash on malformed data");
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== Packet Parser Unit Tests ===\n\n");

    test_short_packets();
    test_arp_ethertype();
    test_tcp_flags();
    test_udp_length();
    test_format_helpers();
    test_print_packet_no_crash();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
