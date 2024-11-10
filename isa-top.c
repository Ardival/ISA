#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ncurses.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define MAX_ENTRIES 100 // Maximum number of unique connections

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int src_port;
    int dst_port;
    char protocol[10];
    long long int rx_bytes;
    long long int tx_bytes;
    int rx_packets;
    int tx_packets;
} ConnectionStats;

ConnectionStats stats[MAX_ENTRIES];
int entry_count = 0;
int sort_option = 1;
void display_stats(int sort_option);
void update_display(__attribute__((unused)) int sig) {
    display_stats(sort_option); // Aktualizuje štatistiky
    entry_count = 0;
    alarm(1); // Opäť nastaví alarm na 1 sekundu
}

void got_packet(__attribute__((unused)) u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)
    
    // Print IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    int src_port = 0, dst_port = 0;
    char protocol[10];

    if (ip_header->ip_p == IPPROTO_TCP) {
        strcpy(protocol, "tcp");
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        strcpy(protocol, "udp");
        struct udphdr *udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        strcpy(protocol, "icmp");
    } else {
        return; // Ignore other protocols
    }
    
    // Update stats for the connection
    int type = 0;
    int index = 0;
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(stats[i].src_ip, src_ip) == 0 && stats[i].src_port == src_port &&
            strcmp(stats[i].dst_ip, dst_ip) == 0 && stats[i].dst_port == dst_port) {
            type = 1; // Return the index of the existing entry
            index = i;
        }
    }
    if (type == 0){
        for (int i = 0; i < entry_count; i++) {
            if (strcmp(stats[i].src_ip, dst_ip) == 0 && stats[i].src_port == dst_port &&
                strcmp(stats[i].dst_ip, src_ip) == 0 && stats[i].dst_port == src_port) {
                type = 2; // Return the index of the existing entry
                index = i;
            }
    }
    }
    if (type == 1) {
        stats[index].rx_bytes += header->len;
        stats[index].rx_packets++;
        // You may need additional logic for counting Tx bytes and packets, depending on your capture strategy.
    } else if (type == 2) {
        stats[index].tx_bytes += header->len;
        stats[index].tx_packets++;
    } else {
        if (entry_count < MAX_ENTRIES) {
            strcpy(stats[entry_count].src_ip, src_ip);
            strcpy(stats[entry_count].dst_ip, dst_ip);
            stats[entry_count].src_port = src_port;
            stats[entry_count].dst_port = dst_port;
            strcpy(stats[entry_count].protocol, protocol);
            stats[entry_count].rx_bytes = 0;
            stats[entry_count].tx_bytes = 0;
            stats[entry_count].rx_packets = 0;
            stats[entry_count].tx_packets = 0;
            entry_count++;
        }
    }
}

void display_stats(int sort_option) {
    clear();
    mvprintw(0, 0, "%-30s %-30s %-10s %-21s %-20s", "Src IP:port", "Dst IP:port", "Proto", "Rx", "Tx");
    mvprintw(1, 0, "%-72s %-10s %-10s %-10s %-10s","", "b/s", "p/s", "b/s", "p/s");
    mvprintw(2, 0, "%s","---------------------------------------------------------------------------------------------------------------");
    
    
    // Sort based on sort_option
    for (int i = 0; i < entry_count - 1; i++) {
        for (int j = i + 1; j < entry_count; j++) {
            int swap = 0;
            if (sort_option == 1 && stats[i].rx_bytes < stats[j].rx_bytes) swap = 1; // Sort by bytes
            if (sort_option == 2 && stats[i].rx_packets < stats[j].rx_packets) swap = 1; // Sort by packets
            
            if (swap) {
                ConnectionStats temp = stats[i];
                stats[i] = stats[j];
                stats[j] = temp;
            }
        }
    }

    // Display the top 10 connections
    for (int i = 0; i < entry_count && i < 10; i++) {
        char rx_human_packet[24], tx_human_packet[24], rx_human_byte[24], tx_human_byte[24];
        if(stats[i].rx_bytes > 1000000000){
            snprintf(rx_human_byte, sizeof(rx_human_byte), "%.1lfG", stats[i].rx_bytes/1000000000.0); 
        } else if (stats[i].rx_bytes > 1000000){
            snprintf(rx_human_byte, sizeof(rx_human_byte), "%.1lfM", stats[i].rx_bytes/1000000.0); 
        } else if (stats[i].rx_bytes > 1000){
            snprintf(rx_human_byte, sizeof(rx_human_byte), "%.1lfk", stats[i].rx_bytes/1000.0); 
        } else {
            snprintf(rx_human_byte, sizeof(rx_human_byte), "%lld", stats[i].rx_bytes);         
        }

        if(stats[i].tx_bytes > 1000000000){
            snprintf(tx_human_byte, sizeof(tx_human_byte), "%.1lfG", stats[i].tx_bytes/1000000000.0);
        } else if (stats[i].tx_bytes > 1000000){        
            snprintf(tx_human_byte, sizeof(tx_human_byte), "%.1lfM", stats[i].tx_bytes/1000000.0);
        } else if (stats[i].tx_bytes > 1000){        
            snprintf(tx_human_byte, sizeof(tx_human_byte), "%.1lfk", stats[i].tx_bytes/1000.0);
        } else {        
            snprintf(tx_human_byte, sizeof(tx_human_byte), "%lld", stats[i].tx_bytes);
        
        }

        if (stats[i].rx_packets > 1000){
            snprintf(rx_human_packet, sizeof(rx_human_packet), "%.1fk", stats[i].rx_packets/1000.0);
        } else {
            snprintf(rx_human_packet, sizeof(rx_human_packet), "%d", stats[i].rx_packets);
        }
        
        if (stats[i].tx_packets > 1000){
            snprintf(tx_human_packet, sizeof(tx_human_packet), "%.1fk", stats[i].tx_packets/1000.0);
        } else {
            snprintf(tx_human_packet, sizeof(tx_human_packet), "%d", stats[i].tx_packets);
        }
        char src_combined[INET_ADDRSTRLEN + 6]; // Sufficient size for IP:port
        char dst_combined[INET_ADDRSTRLEN + 6];

        // Combine IP address and port
        snprintf(src_combined, sizeof(src_combined), "%.15s:%d", stats[i].src_ip, stats[i].src_port);
        snprintf(dst_combined, sizeof(dst_combined), "%.15s:%d", stats[i].dst_ip, stats[i].dst_port);

        // Formatted output
        mvprintw(i + 3, 0, "%-30s %-30s %-10s %-10s %-10s %-10s %-10s", src_combined, dst_combined, stats[i].protocol, rx_human_byte, rx_human_packet, tx_human_byte, tx_human_packet);
    }
    
    refresh();
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto \\icmp or ip proto \\tcp or ip proto \\udp";
    bpf_u_int32 net = 0;

    // Parse command-line arguments
    char *interface = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            if(strcmp(argv[i+1], "p") == 0){
                sort_option = 2;
            }
        }
    }

    if (interface == NULL) {
        fprintf(stderr, "Interface is required. Use -i <interface>\n");
        return 1;
    }

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    signal(SIGALRM, update_display);
    alarm(1); 

    // Initialize ncurses and display header
    initscr();
    noecho();
    cbreak();
    refresh();
    
    pcap_loop(handle, 0, got_packet, NULL); // Process packets

    pcap_freecode(&fp);
    pcap_close(handle);
    endwin(); // End ncurses mode
    return 0;
}
