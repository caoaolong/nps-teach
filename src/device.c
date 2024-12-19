//
// Created by admin on 24-12-18.
//
#include <nps.h>

void devices_info(pcap_if_t *alldevs) {
    pcap_if_t *device;  // 当前设备
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
                struct sockaddr_in *ip_addr = (struct sockaddr_in *)addr->addr;
                struct sockaddr_in *netmask = (struct sockaddr_in *)addr->netmask;

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
    pcap_if_t *device;  // 当前设备
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓冲区
    char nbuf[64];
    sprintf(nbuf, "\\Device\\NPF_{%s}", name);
    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return nullptr;
    }

    // 遍历设备列表
    for (device = alldevs; device != NULL; device = device->next) {
        if (!strcmp(device->name, nbuf)) {
            // pcap_freealldevs(alldevs);
            return device;
        }
    }
    return nullptr;
}

void device_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    printf("\nPacket captured:\n");
    printf("Timestamp: %ld.%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
    printf("Packet length: %d bytes\n", header->len);
}