#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <ctype.h>

#define ETHERNET_HEADER_SIZE 14

struct eth_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short eth_type;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct eth_header *eth = (struct eth_header *)packet;

    printf("\n[Ethernet Header]\n");
    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
           eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);

    if (ntohs(eth->eth_type) != ETHERTYPE_IP) return;

    struct ip *ip_hdr = (struct ip *)(packet + ETHERNET_HEADER_SIZE);
    int ip_header_len = ip_hdr->ip_hl * 4;

    printf("[IP Header]\n");
    printf("Src IP : %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Dst IP : %s\n", inet_ntoa(ip_hdr->ip_dst));

    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
    int tcp_header_len = tcp_hdr->doff * 4;

    printf("[TCP Header]\n");
    printf("Src Port: %d\n", ntohs(tcp_hdr->source));
    printf("Dst Port: %d\n", ntohs(tcp_hdr->dest));

    const u_char *payload = packet + ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - (ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len);

    printf("[Payload]\n");
    if (payload_len > 0) {
        for (int i = 0; i < payload_len; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    }

    // HTTP 메시지 출력 (포트 80 기준)
    if (ntohs(tcp_hdr->source) == 80 || ntohs(tcp_hdr->dest) == 80) {
        printf("[HTTP Message]\n");
        for (int i = 0; i < payload_len; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Capturing on device: %s\n", dev);
    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}

