//
// Created by Administrator on 24-12-23.
//
#include <stdlib.h>
#include <stdio.h>
#include <prtc.h>
#include <string.h>
#include <winsock2.h>

char *get_mac_str(const unsigned char *mac) {
    char *mac_str = malloc(ETH_II_MAC_LEN + 1);
    memset(mac_str, 0, ETH_II_MAC_LEN + 1);
    memcpy(mac_str, mac, ETH_II_MAC_LEN);
    if (mac_str == NULL) return nullptr;
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

EthII_Hdr *eth_ii_parse(const unsigned char *data) {
    EthII_Hdr *eth_ii = malloc(sizeof(EthII_Hdr));
    if (eth_ii == NULL)
        return eth_ii;
    memcpy(eth_ii, data, sizeof(EthII_Hdr));
    eth_ii->type = ntohs(eth_ii->type);
    return eth_ii;
}

void eth_ii_print(const EthII_Hdr *eth_ii) {
    if (eth_ii == NULL) return;
    if (eth_ii->type == 0x800) {
        printf("IPv4");
    } else if (eth_ii->type == 0x86DD) {
        printf("IPv6");
    } else if (eth_ii->type == 0x806) {
        printf("ARP");
    } else {
        printf("Unknown");
    }
    printf(":\t %s → %s\n", get_mac_str(eth_ii->source_mac), get_mac_str(eth_ii->target_mac));
}
