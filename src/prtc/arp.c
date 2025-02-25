#include <prtc.h>
#include <stdlib.h>
#include <string.h>

Arp_Hdr *arp_parse(const unsigned char *data) {
    Arp_Hdr *arp_hdr = malloc(sizeof(Arp_Hdr));
    if (!arp_hdr) return NULL;
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