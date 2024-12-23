//
// Created by Administrator on 24-12-23.
//

#ifndef PRTC_H
#define PRTC_H

#include <hdr.h>

EthII_Hdr *eth_ii_parse(const unsigned char *data);

void eth_ii_print(const EthII_Hdr *eth_ii);

#endif //PRTC_H
