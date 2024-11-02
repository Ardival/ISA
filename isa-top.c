#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Define pointers to packet headers
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip the Ethernet header (usually 14 bytes)

    // Determine the protocol and print the type of packet
    switch (ip_header->ip_p) {
        case IPPROTO_ICMP:
            printf("Got packet - ICMP\n");
            break;
        case IPPROTO_TCP:
            printf("Got packet - TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Got packet - UDP\n");
            break;
        default:
            printf("Got packet - Other\n");
            break;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto \\icmp or ip proto \\tcp or ip proto \\udp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name "enp0s3"
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    // Step 2: Compile filter into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
