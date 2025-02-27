#ifndef PRTC_H
#define PRTC_H

#include <nps.h>
#include <hdr.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char *get_mac_str(const unsigned char *mac) {
    char *mac_str = (char *)malloc(ETH_II_MAC_LEN + 1);
    memset(mac_str, 0, ETH_II_MAC_LEN + 1);
    memcpy(mac_str, mac, ETH_II_MAC_LEN);
    if (mac_str == NULL) return NULL;
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

static uint8_t *from_mac_str(const char *mac_str) {
    uint8_t *mac = malloc(ETH_II_MAC_LEN);
    memcpy(mac, mac_str, ETH_II_MAC_LEN);
    return mac;
}

static char *get_ip_str(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char *ip_inet = inet_ntoa(addr);
    char *ip_str = malloc(strlen(ip_inet) + 1);
    strcpy(ip_str, ip_inet);
    return ip_str;
}

static uint32_t from_ip_str(char *ip_str) {
    /* 存储转换后的IP地址 */
    struct in_addr ip_addr;
    /* 使用inet_pton将IP地址字符串转换为网络字节序 */
    if (inet_pton(AF_INET, ip_str, &ip_addr) <= 0) {
        perror("inet_pton failed");
        return 0;
    }
    return ip_addr.s_addr;
}

static int host_mac(uint8_t *mac_val) {
    const char *mac = getenv("HOST_MAC");
    int i;
    for (i = 0; i < ETH_II_MAC_LEN; i++) {
        if (sscanf(mac + 3 * i, "%2hhx", &mac_val[i]) != 1) {
            return -1;
        }
    }
    return 0;
}

static uint16_t checksum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = data;
    /* 遍历数据，按16位单元累加 */
    while (len > 1) {
        sum += *ptr++;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + 1; /* 如果有进位，将进位加回 */
        }
        len -= 2;
    }
    /* 如果长度是奇数，处理最后一个字节 */
    if (len == 1) {
        uint8_t last_byte = *(uint8_t *)ptr;
        sum += (last_byte << 8); /* 高位补齐 */
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + 1;
        }
    }
    /* 取反，返回校验和 */
    return ~sum;
}

EthII_Hdr *eth_ii_parse(const unsigned char *data);
void eth_ii_print(const EthII_Hdr *eth_ii);

#define ARP_GRATUITOUS  1
#define ARP_REQUEST     2
Arp_Hdr *arp_parse(const unsigned char *data);
void arp_print(const Arp_Hdr *arp);

#define IPv4_VERSION    4
#define IPv6_VERSION    6
#define IP_TOP_ICMP     1
#define IP_TOP_TCP      6
#define IP_TOP_UDP      17
Ip_Hdr *ip_parse(const unsigned char *data);
bool ip_checksum(Ip_Hdr *ip_hdr);
void ip_print(const Ip_Hdr *ip_hdr);

Icmp_Hdr *icmp_parse(const unsigned char *data, uint16_t len);
bool icmp_checksum(Icmp_Hdr *icmp_hdr, uint16_t len);
void icmp_print(const Icmp_Hdr *icmp);

Udp_Hdr *udp_parse(const unsigned char *data, uint16_t len);
bool udp_checksum(Udp_Hdr *udp_hdr, uint16_t len);
void udp_print(const Udp_Hdr *udp);

#define FLAG_URG     0b100000
#define FLAG_ACK     0b010000
#define FLAG_PSH     0b001000
#define FLAG_RST     0b000100
#define FLAG_SYN     0b000010
#define FLAG_FIN     0b000001
Tcp_Hdr *tcp_parse(const unsigned char *data);
bool tcp_checksum(Tcp_Hdr *tcp_hdr);
void tcp_print(const Tcp_Hdr *tcp);
Tcp_Option *tcp_option(const unsigned char *data);
#endif
