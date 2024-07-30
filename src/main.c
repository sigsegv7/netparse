#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "if_ether.h"
#include "if_arp.h"

/*
 * Convert a MAC address to string.
 *
 * @mac: MAC address
 */
static char *
mac_to_str(uint8_t mac[HW_ADDR_LEN])
{
    const size_t MAX_BUF_LEN = 18;
    char *addrstr;

    addrstr = malloc(MAX_BUF_LEN);
    assert(addrstr != NULL);

    snprintf(addrstr, MAX_BUF_LEN, "%X:%X:%X:%X:%X:%X",
        ntohs(mac[0]) >> 8,
        ntohs(mac[1]) >> 8,
        ntohs(mac[2]) >> 8,
        ntohs(mac[3]) >> 8,
        ntohs(mac[4]) >> 8,
        ntohs(mac[5]) >> 8);

    return addrstr;

}

/*
 * Convert an IPv4 address to string.
 *
 * @ip: IPv4 address
 */
static char *
ip_to_str(uint8_t ip[IPV4_LEN])
{
    const size_t MAX_BUF_LEN = 16;
    char *addrstr;

    addrstr = malloc(MAX_BUF_LEN);
    assert(addrstr != NULL);

    snprintf(addrstr, MAX_BUF_LEN, "%d.%d.%d.%d",
        ntohs(ip[0]) >> 8,
        ntohs(ip[1]) >> 8,
        ntohs(ip[2]) >> 8,
        ntohs(ip[3]) >> 8);

    return addrstr;

}

/*
 * Dump ARP header packet
 *
 * @arp: ARP header
 */
static void
dump_arp(struct arp_hdr *arp)
{
    uint8_t op = ntohs(arp->oper);
    char *target_ip, *sender_ip;
    char *sender_mac;

    target_ip = ip_to_str(arp->target_ip);
    sender_ip = ip_to_str(arp->sender_ip);

    switch (op) {
    case ARP_REQUEST:
        printf("\tWho has %s?\n", target_ip);
        break;
    case ARP_REPLY:
        sender_mac = mac_to_str(arp->sender_mac);
        printf("\t%s is at %s\n", sender_ip, sender_mac);
        free(sender_mac);
        break;
    }

    free(target_ip);
}

static inline void
log_packet(char *type, char *source, char *dest)
{
    printf("%s [\n"
        "\t%s (source) -> %s (dest)\n", type, source, dest);
}

/*
 * Dump IPv4 packet
 *
 * @ipv4: IPv4 headr
 */
static void
dump_ipv4(struct ipv4_hdr *ipv4, char *source_mac, char *dest_mac)
{
    char *dest_ip, *source_ip;
    char *type;
    uint8_t proto;

    dest_ip = ip_to_str(ipv4->dest);
    source_ip = ip_to_str(ipv4->source);
    proto = (ipv4->ttl_proto >> 8);

    switch (proto) {
    case IPV4_ICMP:
        type = "ICMP";
        break;
    case IPV4_TCP:
        type = "TCP";
        break;
    default:
        type = "IPv4";
        break;
    }

    log_packet(type, source_mac, dest_mac);
    printf("\t%s => %s\n", dest_ip, source_ip);

    free(dest_ip);
    free(source_ip);
}

/*
 * For logging purposes
 */
static inline void
dump_ether(struct ether_hdr *ether)
{
    char *source, *dest;
    char *type;
    uint16_t proto_id;
    void *packet;

    packet = (char *)ether + sizeof(struct ether_hdr);
    proto_id = ntohs(ether->proto);

    source = mac_to_str(ether->source);
    dest = mac_to_str(ether->dest);

    switch (proto_id) {
    case PROTO_IPV4:
        dump_ipv4(packet, source, dest);
        break;
    case PROTO_ARP:
        type = "ARP";
        log_packet(type, source, dest);
        dump_arp(packet);
        break;
    default:
        type = "???";
        log_packet(type, source, dest);
        break;
    }

    printf("]\n");
    free(source);
    free(dest);
}

static void
packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    struct ether_hdr *ether = (struct ether_hdr *)bytes;

    dump_ether(ether);
}

int
main(int argc, char **argv)
{
    char iface[16];
    char errbuf[PCAP_ERRBUF_SIZE];
    char c;
    pcap_t *pcap;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s -i <iface> <flags>\n", argv[0]);
        return 1;
    }

    /* Parse the arguments */
    while ((c = getopt(argc, argv, "i:")) != -1) {
        switch (c) {
        case 'i':
            snprintf(iface, sizeof(iface), "%s", optarg);
            break;
        default:
            return -1;
        }
    }

    pcap = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return -1;
    }

    pcap_set_promisc(pcap, 1);
    pcap_loop(pcap, -1, packet_handler, NULL);
    pcap_close(pcap);
    return 0;
}
