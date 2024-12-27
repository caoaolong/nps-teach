//
// Created by admin on 24-12-18.
//
#include <nps.h>
#include <prtc.h>

struct in_addr HOST_IP;

void devices_info(pcap_if_t *alldevs) {
    pcap_if_t *device; // 当前设备
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓冲区

    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    printf("Network devices found:\n");

    // 遍历设备列表
    for (device = alldevs; device != NULL; device = device->next) {
        printf("\nDevice Name: %s\n", device->name);

        // 显示描述（如果存在）
        if (device->description)
            printf("Description: %s\n", device->description);
        else
            printf("No description available.\n");

        // 遍历设备地址
        pcap_addr_t *addr;
        for (addr = device->addresses; addr != NULL; addr = addr->next) {
            // 仅获取 IPv4 地址
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *ip_addr = (struct sockaddr_in *) addr->addr;
                struct sockaddr_in *netmask = (struct sockaddr_in *) addr->netmask;

                printf("IP Address: %s\n", inet_ntoa(ip_addr->sin_addr));
                if (netmask)
                    printf("Subnet Mask: %s\n", inet_ntoa(netmask->sin_addr));
            }
        }
    }

    // 释放设备列表
    pcap_freealldevs(alldevs);
}

pcap_if_t *device_find(pcap_if_t *alldevs, const char *name) {
    // 当前设备
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓冲区
    char nbuf[64];
    sprintf(nbuf, "\\Device\\NPF_{%s}", name);
    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return nullptr;
    }

    // 遍历设备列表
    for (pcap_if_t *device = alldevs; device != NULL; device = device->next) {
        if (!strcmp(device->name, nbuf)) {
            // 遍历设备地址
            pcap_addr_t *addr;
            for (addr = device->addresses; addr != NULL; addr = addr->next) {
                // 仅获取 IPv4 地址
                if (addr->addr && addr->addr->sa_family == AF_INET) {
                    struct sockaddr_in *ip_addr = (struct sockaddr_in *) addr->addr;
                    char *ip_str = inet_ntoa(ip_addr->sin_addr);
                    inet_pton(AF_INET, ip_str, &HOST_IP);
                }
            }
            return device;
        }
    }
    return nullptr;
}

void device_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    printf("\nPacket captured:\n");
    printf("Timestamp: %ld.%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
    printf("Packet length: %d bytes\n", header->len);

    const unsigned char *data = pkt_data;
    // 以太网帧头
    EthII_Hdr *eth_ii = eth_ii_parse(data);
    eth_ii_print(eth_ii);
    data += sizeof(EthII_Hdr);
    switch (eth_ii->type) {
        case ETH_II_TYPE_ARP:
            const Arp_Hdr *arp = arp_parse(data);
            arp_print(arp);
            break;
        case ETH_II_TYPE_IPV4:
            const Ip_Hdr *ip = ip_parse(data);
            ip_print(ip);
            break;
        default:
            printf("Unknown packet type: %d\n", eth_ii->type);
            break;
    }
}
