//
// Created by admin on 24-12-27.
//
#include <prtc.h>

Ip_Hdr *ip_parse(const unsigned char *data) {
    Ip_Hdr *ip_hdr = malloc(sizeof(Ip_Hdr));
    if (ip_hdr == NULL) return nullptr;
    memcpy(ip_hdr, data, sizeof(Ip_Hdr));
    ip_hdr->len = ntohs(ip_hdr->len);
    ip_hdr->identification = ntohs(ip_hdr->identification);
    ip_hdr->ff.v = ntohs(ip_hdr->ff.v);
    ip_hdr->checksum = ntohs(ip_hdr->checksum);
    ip_hdr->src = ntohl(ip_hdr->src);
    ip_hdr->dst = ntohl(ip_hdr->dst);
    return ip_hdr;
}

void ip_print(const Ip_Hdr *ip) {
    printf("\t\t Header: %u bytes, Total: %u bytes\n", ip->ihl * 4, ip->len);
    printf("\t\t CHK: %#4x\n", ip->checksum);
    printf("\t\t TTL: %u\n", ip->ttl);
    if (ip->protocol == IP_TOP_TCP) {
        printf("\t\t TOP: TCP\n");
    } else {
        printf("\t\t TOP: UDP\n");
    }
    printf("\t\t %s → %s\n", get_ip_str(ip->src), get_ip_str(ip->dst));
}