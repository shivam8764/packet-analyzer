#include "parser.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define ETH_HEADER_LEN 14
#define IP_MIN_HEADER_LEN 20
#define TCP_MIN_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define ICMP_MIN_HEADER_LEN 4

/* EtherType constants */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86DD

/* IP protocol numbers */
#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

int parse_ethernet(const uint8_t *packet, size_t len, eth_info_t *info)
{
    if (!packet || !info || len < ETH_HEADER_LEN)
        return -1;

    memcpy(info->dst_mac, packet, 6);
    memcpy(info->src_mac, packet + 6, 6);
    info->ethertype = ntohs(*(const uint16_t *)(packet + 12));
    return 0;
}

int parse_ipv4(const uint8_t *data, size_t len, ip_info_t *info)
{
    if (!data || !info || len < IP_MIN_HEADER_LEN)
        return -1;

    uint8_t ver_ihl = data[0];
    uint8_t version = (ver_ihl >> 4) & 0x0F;
    if (version != 4)
        return -1;

    info->ihl = ver_ihl & 0x0F;
    if (info->ihl < 5 || (size_t)(info->ihl * 4) > len)
        return -1;

    info->ttl = data[8];
    info->protocol = data[9];
    memcpy(&info->src_ip, data + 12, 4);
    memcpy(&info->dst_ip, data + 16, 4);
    return 0;
}

int parse_tcp(const uint8_t *data, size_t len, tcp_info_t *info)
{
    if (!data || !info || len < TCP_MIN_HEADER_LEN)
        return -1;

    info->src_port = ntohs(*(const uint16_t *)(data));
    info->dst_port = ntohs(*(const uint16_t *)(data + 2));
    info->flags = data[13];
    info->syn = (info->flags & 0x02) ? 1 : 0;
    info->ack = (info->flags & 0x10) ? 1 : 0;
    info->fin = (info->flags & 0x01) ? 1 : 0;
    info->rst = (info->flags & 0x04) ? 1 : 0;
    return 0;
}

int parse_udp(const uint8_t *data, size_t len, udp_info_t *info)
{
    if (!data || !info || len < UDP_HEADER_LEN)
        return -1;

    info->src_port = ntohs(*(const uint16_t *)(data));
    info->dst_port = ntohs(*(const uint16_t *)(data + 2));
    info->length = ntohs(*(const uint16_t *)(data + 4));
    return 0;
}

int parse_icmp(const uint8_t *data, size_t len, icmp_info_t *info)
{
    if (!data || !info || len < ICMP_MIN_HEADER_LEN)
        return -1;

    info->type = data[0];
    info->code = data[1];
    return 0;
}

void format_mac(const uint8_t *mac, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void format_ipv4(uint32_t ip, char *buf, size_t buflen)
{
    uint8_t *bytes = (uint8_t *)&ip;
    snprintf(buf, buflen, "%u.%u.%u.%u",
             bytes[0], bytes[1], bytes[2], bytes[3]);
}

static void out(FILE *f1, FILE *f2, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void out(FILE *f1, FILE *f2, const char *fmt, ...)
{
    va_list ap;
    if (f1) {
        va_start(ap, fmt);
        vfprintf(f1, fmt, ap);
        va_end(ap);
    }
    if (f2) {
        va_start(ap, fmt);
        vfprintf(f2, fmt, ap);
        va_end(ap);
    }
}

void print_packet(FILE *fp, FILE *log_fp, const uint8_t *packet, size_t len,
                  int packet_num)
{
    eth_info_t eth;
    char src_mac[18], dst_mac[18];

    out(fp, log_fp, "\n========== Packet #%d (%zu bytes) ==========\n",
        packet_num, len);

    if (parse_ethernet(packet, len, &eth) < 0) {
        out(fp, log_fp, "  [!] Packet too short for Ethernet header\n");
        return;
    }

    format_mac(eth.src_mac, src_mac, sizeof(src_mac));
    format_mac(eth.dst_mac, dst_mac, sizeof(dst_mac));
    out(fp, log_fp, "  Ethernet: %s -> %s", src_mac, dst_mac);

    const char *type_str = "Unknown";
    if (eth.ethertype == ETHERTYPE_IPV4)
        type_str = "IPv4";
    else if (eth.ethertype == ETHERTYPE_ARP)
        type_str = "ARP";
    else if (eth.ethertype == ETHERTYPE_IPV6)
        type_str = "IPv6";
    out(fp, log_fp, "  EtherType: 0x%04x (%s)\n", eth.ethertype, type_str);

    if (eth.ethertype != ETHERTYPE_IPV4)
        return;

    const uint8_t *ip_data = packet + ETH_HEADER_LEN;
    size_t ip_len = len - ETH_HEADER_LEN;
    ip_info_t ip;

    if (parse_ipv4(ip_data, ip_len, &ip) < 0) {
        out(fp, log_fp, "  [!] Malformed IPv4 header\n");
        return;
    }

    char src_ip[16], dst_ip[16];
    format_ipv4(ip.src_ip, src_ip, sizeof(src_ip));
    format_ipv4(ip.dst_ip, dst_ip, sizeof(dst_ip));
    out(fp, log_fp, "  IPv4: %s -> %s  TTL=%u  Protocol=%u\n",
        src_ip, dst_ip, ip.ttl, ip.protocol);

    size_t ip_hdr_len = (size_t)ip.ihl * 4;
    const uint8_t *transport = ip_data + ip_hdr_len;
    size_t transport_len = ip_len > ip_hdr_len ? ip_len - ip_hdr_len : 0;

    if (ip.protocol == PROTO_TCP) {
        tcp_info_t tcp;
        if (parse_tcp(transport, transport_len, &tcp) < 0) {
            out(fp, log_fp, "  [!] Malformed TCP header\n");
            return;
        }
        out(fp, log_fp, "  TCP: %u -> %u  Flags: [%s%s%s%s]\n",
            tcp.src_port, tcp.dst_port,
            tcp.syn ? "SYN " : "",
            tcp.ack ? "ACK " : "",
            tcp.fin ? "FIN " : "",
            tcp.rst ? "RST " : "");
    } else if (ip.protocol == PROTO_UDP) {
        udp_info_t udp;
        if (parse_udp(transport, transport_len, &udp) < 0) {
            out(fp, log_fp, "  [!] Malformed UDP header\n");
            return;
        }
        out(fp, log_fp, "  UDP: %u -> %u  Length=%u\n",
            udp.src_port, udp.dst_port, udp.length);
    } else if (ip.protocol == PROTO_ICMP) {
        icmp_info_t icmp;
        if (parse_icmp(transport, transport_len, &icmp) < 0) {
            out(fp, log_fp, "  [!] Malformed ICMP header\n");
            return;
        }
        out(fp, log_fp, "  ICMP: Type=%u  Code=%u\n", icmp.type, icmp.code);
    }
}
