#include <stdlib.h>
#include <stdio.h>
#include <prtc.h>
#include <string.h>

EthII_Hdr *eth_ii_parse(const unsigned char *data) {
    EthII_Hdr *eth_ii = malloc(sizeof(EthII_Hdr));
    if (eth_ii == NULL)
        return eth_ii;
    memcpy(eth_ii, data, sizeof(EthII_Hdr));
    eth_ii->type = ntohs(eth_ii->type);
    return eth_ii;
}

uint8_t *eth_ii_serialize(const EthII_Hdr *eth_ii_hdr) {
    uint8_t *data = malloc(sizeof(EthII_Hdr));
    if (data == NULL) return NULL;

    return data;
}

void eth_ii_print(const EthII_Hdr *eth_ii) {
    if (eth_ii == NULL) return;
    if (eth_ii->type == ETH_II_TYPE_IPv4) {
        printf("IPv4");
    } else if (eth_ii->type == ETH_II_TYPE_IPv6) {
        printf("IPv6");
    } else if (eth_ii->type == ETH_II_TYPE_ARP) {
        printf("ARP");
    } else {
        printf("Unknown");
    }
    printf(":\t %s → %s\n", get_mac_str(eth_ii->source_mac), get_mac_str(eth_ii->target_mac));
}
