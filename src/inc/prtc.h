//
// Created by Administrator on 24-12-23.
//

#ifndef PRTC_H
#define PRTC_H

#include <hdr.h>
#include <string.h>
#include <winsock2.h>

static char *get_mac_str(const unsigned char *mac) {
    char *mac_str = malloc(ETH_II_MAC_LEN + 1);
    memset(mac_str, 0, ETH_II_MAC_LEN + 1);
    memcpy(mac_str, mac, ETH_II_MAC_LEN);
    if (mac_str == NULL) return nullptr;
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

static char *get_ip_str(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char *ip_inet = inet_ntoa(addr);
    char *ip_str = malloc(strlen(ip_inet) + 1);
    strcpy(ip_str, ip_inet);
    return ip_str;
}

EthII_Hdr *eth_ii_parse(const unsigned char *data);

void eth_ii_print(const EthII_Hdr *eth_ii);

Arp_Hdr *arp_parse(const unsigned char *data);

void arp_print(const Arp_Hdr *arp);

#endif //PRTC_H
