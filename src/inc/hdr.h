//
// Created by Administrator on 24-12-23.
//

#ifndef HDR_H
#define HDR_H

#include <stdint.h>

#define ETH_II_MAC_LEN      6
#define ETH_II_TYPE_IPV4    0x0800
#define ETH_II_TYPE_ARP     0x0806
#define ETH_II_TYPE_IPV6    0x86DD

#define IP_STR_LEN          12

// Ethernet II Header
typedef struct __attribute__((__packed__)) {
    uint8_t target_mac[ETH_II_MAC_LEN];
    uint8_t source_mac[ETH_II_MAC_LEN];
    uint16_t type;
} EthII_Hdr;

// ARP Header
typedef struct __attribute__((__packed__)) {
    uint16_t h_type;
    uint16_t p_type;
    uint8_t h_len;
    uint8_t p_len;
    uint16_t operate;
    uint8_t sha[ETH_II_MAC_LEN];
    uint32_t spa;
    uint8_t tha[ETH_II_MAC_LEN];
    uint32_t tpa;
} Arp_Hdr;

// IP Header
typedef struct __attribute__((__packed__)) {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t len;
    uint16_t identification;
    union {
        uint16_t v;
        struct {
            uint16_t fo:13;
            uint16_t flag:3;
        };
    } ff;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} Ip_Hdr;
#endif //HDR_H
