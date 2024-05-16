#ifndef IF_ETHER_H
#define IF_ETHER_H

#include <stdint.h>

#define HW_ADDR_LEN 6
#define PROTO_IPV4 0x0800
#define PROTO_ARP 0x0806

struct ether_hdr {
    uint8_t dest[HW_ADDR_LEN];
    uint8_t source[HW_ADDR_LEN];
    uint16_t proto;
} __attribute__((packed));

#endif  /* !IF_ETHER_H */
