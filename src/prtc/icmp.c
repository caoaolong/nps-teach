#include <prtc.h>

Icmp_Hdr *icmp_parse(const unsigned char *data, uint16_t len) {
    Icmp_Hdr *icmp_hdr = malloc(len);
    if (icmp_hdr == NULL) return NULL;
    memcpy(icmp_hdr, data, len);
    /* if (!icmp_checksum(icmp_hdr, len)) return NULL; */
    return icmp_hdr;
}

bool icmp_checksum(Icmp_Hdr *icmp_hdr, uint16_t len) {
    if (checksum(icmp_hdr, len) !=0) {
        free(icmp_hdr);
        return false;
    }
    return true;
}

void icmp_print(const Icmp_Hdr *icmp_hdr) {
    printf("ICMP:\t Type: ");
    if (icmp_hdr->type == 0 && icmp_hdr->code == 0) {
        printf("Echo Reply\n");
    } else if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
        printf("Echo Request\n");
    }
}