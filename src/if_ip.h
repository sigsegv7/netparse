#ifndef IF_IP_H
#define IF_IP_H

#define IPV4_LEN 4

/* Protocols */
#define IPV4_ICMP   1
#define IPV4_TCP    6

struct ipv4_hdr {
    uint8_t ver_hcl;
    uint8_t dscp_ecn;
    uint16_t length;
    uint16_t ident;
    uint16_t flags_off;
    uint16_t ttl_proto;
    uint16_t checksum;
    uint8_t source[IPV4_LEN];
    uint8_t dest[IPV4_LEN];
} __attribute__((packed));

#endif  /* IF_IP_H */
