//
// Created by admin on 24-12-18.
//

#ifndef NPS_H
#define NPS_H

#include <pcap.h>
#include <stack.h>
#include <winsock2.h>

#define CMD_SIZE        64
#define BUFFER_SIZE     128
#define SERVICES_SIZE   1024
#define CLIENTS_SIZE    1024

typedef struct Cmd {
    int write;
    char cmd[64];
    char rst[80];
} Cmd;

void cmd_put_char(char c);

void cmd_pop_char();

void cmd_exec();

typedef struct Dev_Buffer {
    Stack *data[BUFFER_SIZE];
    int size;
}Dev_Buffer;

typedef struct Dev_Client {
    uint16_t size;
    struct sockaddr address[CLIENTS_SIZE];
} Dev_Client;

typedef struct Dev_Service {
    uint8_t protocol;
    uint16_t port;
    uint16_t sockid;
    Dev_Buffer ibuf, obuf;
    Dev_Client clients;
    pcap_t *handle;
} Dev_Service;

typedef enum Bd_Type {
    UP, DOWN, NORMAL
} Bd_Type;

void service_init(pcap_t *pcap);

int service_register(uint8_t protocol, uint16_t port, uint16_t sockid);

void service_unregister(uint16_t sid);

void service_put_packet(uint8_t protocol, uint16_t port, Stack *data);

void service_send_packet(uint16_t sid, Stack *data);

const char *service_protocol_str(const Dev_Service *service);

const char *service_status_str(const Dev_Service *service);

Stack *service_get_packet(uint16_t sid, uint8_t type);

Dev_Service *service_table();

void devices_info(pcap_if_t *alldevs);

pcap_if_t *device_find(pcap_if_t *alldevs, const char *name);

void device_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data);

void nps_main();

void nps_set_result(const char *msg);

void nps_view();

void view_init();

// utils

uint32_t gen_uint32_number();

#endif //NPS_H
