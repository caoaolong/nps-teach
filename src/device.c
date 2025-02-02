//
// Created by admin on 24-12-18.
//
#include <nps.h>
#include <prtc.h>
#include <stack.h>

struct in_addr HOST_IP;

Dev_Service services[SERVICES_SIZE];

void service_init() {
    for (int i = 0; i < SERVICES_SIZE; i++) {
        memset(&services[i], 0, sizeof(Dev_Service));
    }
}

int service_register(uint8_t protocol, uint16_t port) {
    Dev_Service *service = nullptr;
    int i = 0;
    for (; i < SERVICES_SIZE; i++) {
        service = &services[i];
        if (service->protocol == protocol && service->port == port)
            return i;
        if (service->protocol == 0)
            break;
    }
    if (service) {
        service->protocol = protocol;
        service->port = port;
        memset(&services[i].buffer, 0, sizeof(Dev_Buffer));
        return i;
    }
    return -1;
}

void service_unregister(uint16_t sid) {
    memset( &services[sid], 0, sizeof(Dev_Service));
}

void service_put_packet(uint8_t protocol, uint16_t port, Stack *data) {
    for (int i = 0; i < SERVICES_SIZE; i++) {
        Dev_Service *service = &services[i];
        if (service->protocol == protocol && service->port == port) {
            Dev_Buffer *buffer = &services[i].buffer;
            buffer->data[buffer->size++] = data;
            break;
        }
    }
}

Stack *service_get_packet(uint16_t sid) {
    Dev_Service *service = &services[sid];
    if (service->protocol == 0 || service->buffer.size == 0)
        return nullptr;
    Stack *data = service->buffer.data[0];
    for (int i = 0; i < service->buffer.size; i++) {
        service->buffer.data[i] = service->buffer.data[i + 1];
    }
    service->buffer.size--;
    return data;
}

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
        if (device->flags & PCAP_IF_LOOPBACK) {
            printf("Loopback enabled\n");
        }
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
    sprintf(nbuf, "\\Device\\NPF_%s", name);
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
    // printf("\nPacket captured:\n");
    // printf("Timestamp: %ld.%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
    // printf("Packet length: %d bytes\n", header->len);
    const unsigned char *data = pkt_data;
    Stack *stack = stack_new();
    int top_type = SP_ETH;
    if (*(uint32_t *)data == 2) {
        top_type = SP_LB;
    }
    int port = 0;
    do {
        switch (top_type) {
            default:
                printf("Unknown packet type\n");
                return;
            case SP_LB:
                // printf("Loopback\n");
                data += 4;
                top_type = SP_IPv4;
                break;
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
                // eth_ii_print(eth_ii);
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
                // arp_print(arp_hdr);
                break;
            }
            case SP_IPv4: {
                Ip_Hdr *ip_hdr = ip_parse(data);
                if (!ip_hdr) return;
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
                // ip_print(ip_hdr);
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
                // icmp_print(icmp_hdr);
                break;
            }
            case SP_UDP: {
                const StackNode *node = stack_peek(stack);
                const uint16_t len = ((Ip_Hdr *) node->data)->len - ((Ip_Hdr *) node->data)->ihl * 4;
                Udp_Hdr *udp_hdr = udp_parse(data, len);
                top_type = SP_NULL;
                port = udp_hdr->tp;
                stack_push(stack, udp_hdr, SP_UDP, top_type);
                // 计算长度偏移量
                data += len;
                // udp_print(udp_hdr);
                break;
            }
            case SP_TCP: {
                Tcp_Hdr *tcp_hdr = tcp_parse(data);
                top_type = SP_NULL;
                port = tcp_hdr->tp;
                stack_push(stack, tcp_hdr, SP_TCP, top_type);
                // 计算长度偏移量
                data += sizeof(Tcp_Hdr);
                // tcp_print(tcp_hdr);
                break;
            }
        }
    } while (top_type > 0);
    // fflush(stdout);
    // 检测服务分发数据包
    StackNode *top = stack_peek(stack);
    service_put_packet(top->protocol, port, stack);
}
