//
// Created by admin on 24-12-18.
//
#include <nps.h>
#include <prtc.h>
#include <stack.h>

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
    Stack *stack = stack_new();
    int top_type = SP_ETH;
    do {
        switch (top_type) {
            default:
                printf("Unknown packet type\n");
                return;
            case SP_ETH: {
                // 以太网帧头
                EthII_Hdr *eth_ii = eth_ii_parse(data);
                // 获取上层协议类型
                if (eth_ii->type == ETH_II_TYPE_ARP) {
                    top_type = SP_ARP;
                } else if (eth_ii->type == ETH_II_TYPE_IPv4) {
                    top_type = SP_IPv4;
                } else if (eth_ii->type == ETH_II_TYPE_IPv6) {
                    top_type = SP_IPv6;
                } else {
                    return;
                }
                stack_push(stack, eth_ii, SP_ETH, top_type);
                // 计算长度偏移量
                data += sizeof(EthII_Hdr);
                // 输出
                eth_ii_print(eth_ii);
                break;
            }
            case SP_ARP: {
                // ARP协议
                Arp_Hdr *arp_hdr = arp_parse(data);
                top_type = SP_NULL;
                stack_push(stack, arp_hdr, SP_ARP, top_type);
                // 计算长度偏移量
                data += sizeof(Arp_Hdr);
                // 输出
                arp_print(arp_hdr);
                break;
            }
            case SP_IPv4: {
                Ip_Hdr *ip_hdr = ip_parse(data);
                // 获取上层协议类型
                if (ip_hdr->protocol == IPPROTO_ICMP) {
                    top_type = SP_ICMP;
                } else if (ip_hdr->protocol == IPPROTO_TCP) {
                    top_type = SP_TCP;
                } else if (ip_hdr->protocol == IPPROTO_UDP) {
                    top_type = SP_UDP;
                } else {
                    return;
                }
                stack_push(stack, ip_hdr, SP_IPv4, top_type);
                // 计算长度偏移量
                data += ip_hdr->ihl * 4;
                // 输出
                ip_print(ip_hdr);
                break;
            }
            case SP_ICMP: {
                const StackNode *node = stack_peek(stack);
                const uint16_t len = ((Ip_Hdr *) node->data)->len - ((Ip_Hdr *) node->data)->ihl * 4;
                Icmp_Hdr *icmp_hdr = icmp_parse(data, len);
                top_type = SP_NULL;
                stack_push(stack, icmp_hdr, SP_ICMP, top_type);
                // 计算长度偏移量
                data += len;
                // 输出
                icmp_print(icmp_hdr);
                break;
            }
            case SP_UDP: {
                const StackNode *node = stack_peek(stack);
                const uint16_t len = ((Ip_Hdr *) node->data)->len - ((Ip_Hdr *) node->data)->ihl * 4;
                Udp_Hdr *udp_hdr = udp_parse(data, len);
                top_type = SP_NULL;
                stack_push(stack, udp_hdr, SP_UDP, top_type);
                // 计算长度偏移量
                data += len;
                udp_print(udp_hdr);
                break;
            }
        }
    } while (top_type > 0);
}
