#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#inclue "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_len = ip->iph_ihl * 4;

        if(ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;

            printf("\n< Packet Captured>\n");
            printf("Ethernet Header\n");
            printf("- Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("- Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("IP Header\n");
            printf("- Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("- Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("TCP Header\n");
            printf("- Source Port: %u\n", ntohs(tcp->tcp_sport));
            printf("- Destination Port: %u\n", ntohs(tcp->tcp_dport));

            int headers_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->len - headers_size;
            const u_char *payload = packet + headers_size;

            if(payload_len > 0) {
                if(memmem(payload, payload_len, "GET ", 4) || memmem(payload, payload_len, "HTTP/", 5)) {
                    if(memmem(payload, payload_len, "WHS Fighting!", 13)) {
                        printf("\n<WHS Fighting! 메시지를 포함한 HTTP Message 발견>\n");
                        int print_len = payload_len < 200 ? payload_len : 200;
                        printf("%.*s\n", print_len, payload);
                        printf("\nWHS Fighting!\n");
                    }
                }
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}