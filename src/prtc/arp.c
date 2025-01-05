//
// Created by Administrator on 24-12-24.
//
#include <prtc.h>
#include <stdlib.h>
#include <string.h>

Arp_Hdr *arp_parse(const unsigned char *data) {
    Arp_Hdr *arp_hdr = malloc(sizeof(Arp_Hdr));
    if (!arp_hdr) return nullptr;
    memcpy(arp_hdr, data, sizeof(Arp_Hdr));
    arp_hdr->h_type = ntohs(arp_hdr->h_type);
    arp_hdr->p_type = ntohs(arp_hdr->p_type);
    arp_hdr->operate = ntohs(arp_hdr->operate);
    arp_hdr->spa = ntohl(arp_hdr->spa);
    arp_hdr->tpa = ntohl(arp_hdr->tpa);
    return arp_hdr;
}

void arp_print(const Arp_Hdr *arp) {
    if (arp->p_type == ETH_II_TYPE_IPv4) {
        printf("\t\t who has %s, tell %s\n", get_ip_str(arp->tpa), get_ip_str(arp->spa));
    }
}

extern struct in_addr HOST_IP;

int arp_send(pcap_t *handle, char *tpa, uint8_t type) {
    EthII_Hdr eth_ii_hdr = {.type = htons(ETH_II_TYPE_ARP)};
    host_mac(eth_ii_hdr.source_mac);
    memset(eth_ii_hdr.target_mac, 0xFF, ETH_II_MAC_LEN);
    Arp_Hdr arp_hdr = {
        .h_type = htons(1), .p_type = htons(ETH_II_TYPE_IPv4), .h_len = 6, .p_len = 4,
        .operate = htons(1),
        .spa = HOST_IP.s_addr,
        .tpa = HOST_IP.s_addr
    };
    host_mac(arp_hdr.sha);
    int pl = 0;
    if (type == ARP_GRATUITOUS) {
        pl = 60;
        memset(arp_hdr.tha, 0xFF, ETH_II_MAC_LEN);
    } else if (type == ARP_REQUEST) {
        pl = sizeof(EthII_Hdr) + sizeof(Arp_Hdr);
        memset(arp_hdr.tha, 0, ETH_II_MAC_LEN);
        arp_hdr.tpa = from_ip_str(tpa);
    }
    uint8_t data[pl];
    memset(data, 0, pl);
    memcpy(data, &eth_ii_hdr, sizeof(EthII_Hdr));
    memcpy(data + sizeof(EthII_Hdr), &arp_hdr, sizeof(Arp_Hdr));
    // Send the packet
    if (pcap_sendpacket(handle, data, pl) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    } else {
        printf("sent successfully.\n");
    }
    return 0;
}
