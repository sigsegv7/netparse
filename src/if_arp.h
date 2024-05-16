#ifndef IF_ARP_H
#define IF_ARP_H

#include <stdint.h>
#include "if_ether.h"
#include "if_ip.h"

#define ARP_REQUEST 1
#define ARP_REPLY   2

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sender_mac[HW_ADDR_LEN];
    uint8_t sender_ip[IPV4_LEN];
    uint8_t target_mac[HW_ADDR_LEN];
    uint8_t target_ip[IPV4_LEN];
} __attribute__((packed));

#endif  /*! IF_ARP_H */
