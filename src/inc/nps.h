//
// Created by admin on 24-12-18.
//

#ifndef NPS_H
#define NPS_H

#include <pcap.h>
#include <stack.h>

#define BUFFER_SIZE     1024
#define SERVICES_SIZE   1024

typedef struct Dev_Buffer {
    Stack *data[BUFFER_SIZE];
    int size;
}Dev_Buffer;

typedef struct Dev_Service {
    uint8_t protocol;
    uint16_t port;
    Dev_Buffer buffer;
} Dev_Service;

void service_init();

int service_register(uint8_t protocol, uint16_t port);

void service_unregister(uint16_t sid);

void service_put_packet(uint8_t protocol, uint16_t port, Stack *data);

Stack *service_get_packet(uint16_t sid);

void devices_info(pcap_if_t *alldevs);

pcap_if_t *device_find(pcap_if_t *alldevs, const char *name);

void device_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data);

void dispatch(Stack *stack);

void nps_main();
#endif //NPS_H
