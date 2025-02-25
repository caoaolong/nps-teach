#include <prtc.h>

Udp_Hdr *udp_parse(const unsigned char *data, uint16_t len) {
    Udp_Hdr *udp_hdr = malloc(len);
    if (udp_hdr == NULL)return NULL;
    memcpy(udp_hdr, data, len);
    /* if (udp_checksum(udp_hdr, len) != 0) return NULL; */

    udp_hdr->sp = ntohs(udp_hdr->sp);
    udp_hdr->tp = ntohs(udp_hdr->tp);
    udp_hdr->length = ntohs(udp_hdr->length);
    return udp_hdr;
}

bool udp_checksum(Udp_Hdr *udp_hdr, uint16_t len) {
    return checksum(udp_hdr, len);
}

void udp_print(const Udp_Hdr *udp) {
    printf("\t\t\t Port: %u -> %u, Length: %u\n", udp->sp, udp->tp, udp->length);
}