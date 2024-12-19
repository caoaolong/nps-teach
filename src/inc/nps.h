//
// Created by admin on 24-12-18.
//

#ifndef NPS_H
#define NPS_H

#include <pcap.h>

void devices_info(pcap_if_t *alldevs);

pcap_if_t *device_find(pcap_if_t *alldevs, const char *name);

void device_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
#endif //NPS_H
