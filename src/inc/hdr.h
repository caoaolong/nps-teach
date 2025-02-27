#ifndef HDR_H
#define HDR_H

#include <stdint.h>

#define ETH_II_MAC_LEN      6
#define ETH_II_TYPE_IPv4    0x0800
#define ETH_II_TYPE_ARP     0x0806
#define ETH_II_TYPE_IPv6    0x86DD

#define IP_STR_LEN          12

/* Ethernet II Header */
typedef struct __attribute__((__packed__)) {
    uint8_t target_mac[ETH_II_MAC_LEN];
    uint8_t source_mac[ETH_II_MAC_LEN];
    uint16_t type;
} EthII_Hdr;

/* ARP Header */
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

/* IP Header */
typedef struct __attribute__((__packed__)) {
    uint8_t ihl: 4;
    uint8_t version: 4;
    uint8_t tos;
    uint16_t len;
    uint16_t identification;

    union {
        uint16_t v;

        struct {
            uint16_t fo: 13;
            uint16_t flag: 3;
        };
    } ff;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} Ip_Hdr;

/* ICMP Header */
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t data[];
} Icmp_Hdr;

/* UDP Header */
typedef struct __attribute__((__packed__)) {
    uint16_t sp;
    uint16_t tp;
    uint16_t length;
    uint16_t checksum;
    uint8_t data[];
} Udp_Hdr;

/* TCP Header */
typedef struct __attribute__((__packed__)) {
    uint16_t sp;
    uint16_t tp;
    uint32_t seq;
    uint32_t ack;

    union {
        uint16_t v;

        struct {
            uint16_t flags: 6;
            uint16_t unused: 6;
            uint16_t offset: 4;
        };
    } ff;

    uint16_t ws;
    uint16_t checksum;
    uint16_t up;
} Tcp_Hdr;

typedef struct __attribute__((__packed__)) {
    uint8_t kind;
    uint8_t length;
    union {
        uint16_t mss_value;
        uint8_t shift_count;
    };
} Tcp_Option;

#endif
