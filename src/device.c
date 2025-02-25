#include <nps.h>
#include <prtc.h>
#include <stack.h>
#include <sock2.h>

struct in_addr HOST_IP;

Dev_Service services[SERVICES_SIZE];

void service_init(pcap_t *pcap) {
    int i;
    for (i = 0; i < SERVICES_SIZE; i++) {
        memset(&services[i], 0, sizeof(Dev_Service));
        services[i].handle = pcap;
    }
}

Dev_Service *service_table() {
    return services;
}

int service_register(uint8_t protocol, uint16_t port, uint16_t sockid) {
    Dev_Service *service = NULL;
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
        service->port = ntohs(port);
        service->sockid = sockid;
        memset(&service->ibuf, 0, sizeof(Dev_Buffer));
        nps_view();
        return i;
    }
    return -1;
}

void service_unregister(uint16_t sid) {
    memset( &services[sid], 0, sizeof(Dev_Service));
}

void service_put_packet(uint8_t protocol, uint16_t port, Stack *data) {
    int i;
    for (i = 0; i < SERVICES_SIZE; i++) {
        Dev_Service *service = &services[i];
        if (service->protocol == protocol && service->port == port) {
            Dev_Buffer *buffer = &services[i].ibuf;
            buffer->data[buffer->size++] = data;
            nps_view();
            break;
        }
    }
}

void service_send_packet(uint16_t sid, Stack *data) {
    Dev_Service *service = &services[sid];
    if (service->obuf.size < BUFFER_SIZE - 1) {
        service->obuf.data[service->obuf.size++] = data;
    }
}

void service_send_packets() {
    int i;
    for (i = 0; i < SERVICES_SIZE; i++) {
        Dev_Service *service = &services[i];
        if (service->protocol < 0)
            continue;
        Dev_Buffer *buffer = &services[i].obuf;
        if (buffer->size == 0)
            continue;
        int size = 0;
        uint8_t *data = stack_encode(service_get_packet(i, 2), &size);
        if (!data) {
            perror("stack_encode");
            continue;
        }
        if (pcap_sendpacket(service->handle, data, size) != 0) {
            nps_set_result(pcap_geterr(service->handle));
            nps_view();
            continue;
        }
        free(data);
        nps_view();
    }
}

const char *service_protocol_str(const Dev_Service *service) {
    switch (service->protocol) {
        case SP_TCP:
            return "TCP";
        case SP_UDP:
            return "UDP";
        default:
            return "Unknown";
    }
}

const char *service_status_str(const Dev_Service *service) {
    TcpState state = sock2fd(service->sockid)->state;
    switch (state) {
        case CLOSED:
            return "CLOSED";
        case LISTEN:
            return "LISTEN";
        case ESTABLISHED:
            return "ESTABLISHED";
        case SYN_SENT:
            return "SYN_SENT";
        case SYN_RECEIVED:
            return "SYN_RECEIVED";
        case FIN_WAIT1:
            return "FIN_WAIT1";
        case FIN_WAIT2:
            return "FIN_WAIT2";
        case CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TIME_WAIT:
            return "TIME_WAIT";
        case LAST_ACK:
            return "LAST_ACK";
        default:
            return "Unknown";
    }
}

/* 
type = 1 : ibuf
type = 2 : obuf
*/
Stack *service_get_packet(uint16_t sid, uint8_t type) {
    Dev_Service *service = &services[sid];
    if (service->protocol == 0)
        return NULL;
    if (type == 1) {
        if (service->ibuf.size == 0)
            return NULL;
        Stack *data = service->ibuf.data[0];
        int i;
        for (i = 0; i < service->ibuf.size; i++) {
            service->ibuf.data[i] = service->ibuf.data[i + 1];
        }
        service->ibuf.size--;
        return data;
    }
    if (type == 2) {
        if (service->obuf.size == 0)
            return NULL;
        Stack *data = service->obuf.data[0];
        int i;
        for (i = 0; i < service->obuf.size; i++) {
            service->obuf.data[i] = service->obuf.data[i + 1];
        }
        service->obuf.size--;
        return data;
    }
    return NULL;
}

void devices_info(pcap_if_t *alldevs) {
    pcap_if_t *device; /* 当前设备 */
    char errbuf[PCAP_ERRBUF_SIZE]; /* 错误信息缓冲区 */

    /* 获取设备列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    printf("Network devices found:\n");

    /* 遍历设备列表 */
    for (device = alldevs; device != NULL; device = device->next) {
        printf("\nDevice Name: %s\n", device->name);
        if (device->flags & PCAP_IF_LOOPBACK) {
            printf("Loopback enabled\n");
        }
        /* 显示描述（如果存在） */
        if (device->description)
            printf("Description: %s\n", device->description);
        else
            printf("No description available.\n");

        /* 遍历设备地址 */
        pcap_addr_t *addr;
        for (addr = device->addresses; addr != NULL; addr = addr->next) {
            /* 仅获取 IPv4 地址 */
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *ip_addr = (struct sockaddr_in *) addr->addr;
                struct sockaddr_in *netmask = (struct sockaddr_in *) addr->netmask;

                printf("IP Address: %s\n", inet_ntoa(ip_addr->sin_addr));
                if (netmask)
                    printf("Subnet Mask: %s\n", inet_ntoa(netmask->sin_addr));
            }
        }
    }

    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
}

pcap_if_t *device_find(pcap_if_t *alldevs, const char *name) {
    /* 当前设备 */
    char errbuf[PCAP_ERRBUF_SIZE]; /* 错误信息缓冲区 */
    char nbuf[64];
    sprintf(nbuf, "\\Device\\NPF_%s", name);
    /* 获取设备列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

    /* 遍历设备列表 */
    pcap_if_t *device;
    for (device = alldevs; device != NULL; device = device->next) {
        if (!strcmp(device->name, nbuf)) {
            /* 遍历设备地址 */
            pcap_addr_t *addr;
            for (addr = device->addresses; addr != NULL; addr = addr->next) {
                /* 仅获取 IPv4 地址 */
                if (addr->addr && addr->addr->sa_family == AF_INET) {
                    struct sockaddr_in *ip_addr = (struct sockaddr_in *) addr->addr;
                    char *ip_str = inet_ntoa(ip_addr->sin_addr);
                    inet_pton(AF_INET, ip_str, &HOST_IP);
                }
            }
            return device;
        }
    }
    return NULL;
}

void device_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    /* 检测服务发送数据包 */
    service_send_packets();
    /* 解码数据包 */
    uint16_t port;
    Stack *stack = stack_decode(pkt_data, &port);
    /* 检测服务分发数据包 */
    if (stack) {
        StackNode *top = stack_peek(stack);
        if (top->protocol == SP_TCP_OP) {
            service_put_packet(SP_TCP, port, stack);
        } else {
            service_put_packet(top->protocol, port, stack);
        }
    }
}
