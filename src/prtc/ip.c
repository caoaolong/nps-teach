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
    ip_hdr->src = ntohl(ip_hdr->src);
    ip_hdr->dst = ntohl(ip_hdr->dst);
    // 计算校验和
    if (!ip_checksum(data, ip_hdr->checksum)) {
        free(ip_hdr);
        return nullptr;
    }
    return ip_hdr;
}

BOOL ip_checksum(const unsigned char *data, uint16_t cs) {
    // 计算校验和
    Ip_Hdr *ip_hdr_cks = malloc(sizeof(Ip_Hdr));
    if (ip_hdr_cks == NULL) return 0;
    memcpy(ip_hdr_cks, data, sizeof(Ip_Hdr));
    ip_hdr_cks->checksum = 0;
    uint16_t cv = checksum(ip_hdr_cks,  ip_hdr_cks->ihl * 4);
    free(ip_hdr_cks);
    return cv == cs;
}

void ip_print(const Ip_Hdr *ip) {
    if (ip == NULL) return;
    printf("\t\t Header: %u bytes, Total: %u bytes\n", ip->ihl * 4, ip->len);
    printf("\t\t TTL: %u\n", ip->ttl);
    if (ip->protocol == IP_TOP_TCP) {
        printf("\t\t TOP: TCP\n");
    } else {
        printf("\t\t TOP: UDP\n");
    }
    printf("\t\t %s → %s\n", get_ip_str(ip->src), get_ip_str(ip->dst));
}