#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "if_ether.h"
#include "if_arp.h"

#define LINE_LEN 16
#define RUNFLAG_DUMP    (1 << 0)
#define RUNFLAG_FILTER  (1 << 1)

/* Filters */
typedef enum {
    FILTER_IPV4,
    FILTER_ARP,
    FILTER__MAX
} filter_t;

struct filter_op {
    void(*log)(void *hdr, char *srcmac, char *destmac);
    char *filter_name;
};

static void dump_ipv4(void *hdr, char *source_mac, char *dest_mac);
static void dump_arp(void *hdr, char *source_mac, char *dest_mac);

static char filter[16];
static int runflags = 0;

/* Filter table */
static struct filter_op protos[] = {
    [FILTER_IPV4] = { dump_ipv4, "ipv4" },
    [FILTER_ARP]  = { dump_arp, "arp" }
};

static void
help(char **argv)
{
    const char *opstr =
        " -h, help\n"
        " -i, interface\n"
        " -d, hexdump\n"
        " -f, layer 2 filtering\n\n"
        " filters:\n"
        " arp, ipv4\n";

    fprintf(stderr, "Usage: %s -i <iface> <flags>\n", argv[0]);
    fprintf(stderr, opstr);
}

/*
 * Attempt filtering.
 *
 * Returns -1 if filtering is not enabled with '-f',
 * returns 0 if not in fitler, and returns non-zero
 * if protocol should be filtered out.
 */
static int
try_filter(filter_t type, void *hdr, char *srcmac, char *destmac)
{
    struct filter_op *fp;

    if ((runflags & RUNFLAG_FILTER) == 0)
        return -1;
    if (type >= FILTER__MAX)
        return -1;

    fp = &protos[type];
    if (strcmp(fp->filter_name, filter) == 0) {
        fp->log(hdr, srcmac, destmac);
        return 1;
    }

    return 0;
}

static void
strlower(char *s)
{
    for (char *p = s; *p != '\0'; ++p) {
        *p = tolower(*p);
    }
}

static void
hexdump_line(const void *data, size_t len)
{
    /* The amount of bytes we write */
    const uint8_t BYTE_COUNT = 2;
    const char *line = data;

    printf("\t");
    for (size_t i = 0; i < LINE_LEN; ++i) {
        if (i < len) {
            printf("%02X", line[i] & 0xFF);
        } else {
            printf("  ");
        }

        /* Put spacing between bytes */
        if (((i + 1) % BYTE_COUNT) == 0) {
            printf(" ");
        }
    }

    printf(" ");
    for (size_t i = 0; i < len; ++i) {
        if (line[i] > 31 && line[i] < 127) {
            printf("%c", line[i]);
        } else {
            printf(".");
        }
    }

    printf("\n");
}

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

static inline void
log_packet(char *type, char *source, char *dest)
{
    printf("%s:\t%s (source) -> %s (dest)\n", type, source, dest);
}

/*
 * Dump ARP header packet
 *
 * @arp: ARP header
 */
static void
dump_arp(void *hdr, char *src_mac, char *dest_mac)
{
    struct arp_hdr *arp = hdr;
    uint8_t op = ntohs(arp->oper);
    char *target_ip, *sender_ip;
    char *sender_mac;

    target_ip = ip_to_str(arp->target_ip);
    sender_ip = ip_to_str(arp->sender_ip);
    log_packet("ARP", src_mac, dest_mac);

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
    printf("\n");
}

/*
 * Dump IPv4 packet
 *
 * @ipv4: IPv4 headr
 */
static void
dump_ipv4(void *hdr, char *source_mac, char *dest_mac)
{
    struct ipv4_hdr *ipv4 = hdr;
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
    printf("\n");
}

/*
 * For logging purposes
 */
static inline void
dump_ether(struct ether_hdr *ether)
{
    int tmp;
    char *source, *dest;
    char *type;
    uint16_t proto_id;
    size_t psize = 0;
    void *packet;

    packet = (char *)ether + sizeof(struct ether_hdr);
    proto_id = ntohs(ether->proto);

    source = mac_to_str(ether->source);
    dest = mac_to_str(ether->dest);

    switch (proto_id) {
    case PROTO_IPV4:
        psize = sizeof(struct ipv4_hdr);
        tmp = try_filter(FILTER_IPV4, packet, source, dest);
        if (tmp >= 0) {
            goto done;
        }

        dump_ipv4(packet, source, dest);
        break;
    case PROTO_ARP:
        tmp = try_filter(FILTER_ARP, packet, source, dest);
        if (tmp >= 0) {
            goto done;
        }

        psize = sizeof(struct arp_hdr);
        dump_arp(packet, source, dest);
        break;
    default:
        /* Drop unknown packets if filtering */
        if ((runflags & RUNFLAG_FILTER) != 0) {
            goto done;
        }

        type = "???";
        log_packet(type, source, dest);
        break;
    }

    if ((runflags & RUNFLAG_DUMP) != 0) {
        hexdump_line(ether, sizeof(*ether));
        hexdump_line(packet, psize);
        printf("\n");
    }

done:
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
    short have_iface = 0;
    char iface[16];
    char errbuf[PCAP_ERRBUF_SIZE];
    char c;
    pcap_t *pcap;

    if (argc < 2) {
        help(argv);
        return 1;
    }

    /* Parse the arguments */
    while ((c = getopt(argc, argv, "i:dhf:")) != -1) {
        switch (c) {
        case 'i':
            snprintf(iface, sizeof(iface), "%s", optarg);
            have_iface = 1;
            break;
        case 'd':
            runflags |= RUNFLAG_DUMP;
            break;
        case 'f':
            snprintf(filter, sizeof(filter), "%s", optarg);
            runflags |= RUNFLAG_FILTER;
            break;
        case 'h':
            help(argv);
            return 0;
        default:
            return -1;
        }
    }

    /* Check if we have an interface passed */
    if (!have_iface) {
        fprintf(stderr, "No interface specified!\n");
        help(argv);
        return -1;
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
