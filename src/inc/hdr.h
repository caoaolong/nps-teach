//
// Created by Administrator on 24-12-23.
//

#ifndef HDR_H
#define HDR_H

#include <stdint.h>

#define ETH_II_MAC_LEN    6

// Ethernet II Header
typedef struct {
  uint8_t target_mac[ETH_II_MAC_LEN];
  uint8_t source_mac[ETH_II_MAC_LEN];
  uint16_t type;
} EthII_Hdr;

#endif //HDR_H
