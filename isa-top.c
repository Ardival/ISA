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

// Function to find or add a connection
int find_or_add_connection(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *protocol) {
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(stats[i].src_ip, src_ip) == 0 && stats[i].src_port == src_port &&
            strcmp(stats[i].dst_ip, dst_ip) == 0 && stats[i].dst_port == dst_port) {
            return i; // Return the index of the existing entry
        }
    }
    
    // If not found, add new entry
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
        return entry_count++; // Return the index of the new entry
    }
    
    return -1; // No space for new entries
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
    int index = find_or_add_connection(src_ip, src_port, dst_ip, dst_port, protocol);
    if (index != -1) {
        stats[index].rx_bytes += header->len;
        stats[index].rx_packets++;
        // You may need additional logic for counting Tx bytes and packets, depending on your capture strategy.
    }
}

void display_stats(int sort_option) {
    clear();
    mvprintw(0, 0, "%-30s %-30s %-10s %-20s %-20s", "Src IP:port", "Dst IP:port", "Proto", "Rx", "Tx");
    
    // Sort based on sort_option
    for (int i = 0; i < entry_count - 1; i++) {
        for (int j = i + 1; j < entry_count; j++) {
            int swap = 0;
            if (sort_option == 'b' && stats[i].rx_bytes < stats[j].rx_bytes) swap = 1; // Sort by bytes
            if (sort_option == 'p' && stats[i].rx_packets < stats[j].rx_packets) swap = 1; // Sort by packets
            
            if (swap) {
                ConnectionStats temp = stats[i];
                stats[i] = stats[j];
                stats[j] = temp;
            }
        }
    }

    // Display the top 10 connections
    for (int i = 0; i < entry_count && i < 10; i++) {
        char rx_human[20], tx_human[20];
        snprintf(rx_human, sizeof(rx_human), "%lld", stats[i].rx_bytes);
        snprintf(tx_human, sizeof(tx_human), "%lld", stats[i].tx_bytes);
        
        char src_combined[INET_ADDRSTRLEN + 6]; // Sufficient size for IP:port
        char dst_combined[INET_ADDRSTRLEN + 6];

        // Combine IP address and port
        snprintf(src_combined, sizeof(src_combined), "%s:%d", stats[i].src_ip, stats[i].src_port);
        snprintf(dst_combined, sizeof(dst_combined), "%s:%d", stats[i].dst_ip, stats[i].dst_port);

        // Formatted output
        mvprintw(i + 1, 0, "%-30s %-30s %-10s %-20s %-20s", src_combined, dst_combined, stats[i].protocol, rx_human, tx_human);
    }
    
    refresh();
}


int main(int argc, char *argv[]) {
    pcap_t *handle; // Deklaruje ukazovateľ handle typu pcap_t, ktorý bude odkazovať na otvorenú reláciu na zachytávanie paketov
    char errbuf[PCAP_ERRBUF_SIZE]; // Vytvára buffer errbuf na ukladanie chybových správ od funkcií knižnice libpcap
    struct bpf_program fp; // Deklaruje fp, čo je štruktúra typu bpf_program. Táto štruktúra bude obsahovať filtrovaný výraz vo formáte BPF (Berkeley Packet Filter), ktorý sa použije na filtrovanie zachytávaných paketov.
    char filter_exp[] = "ip proto \\icmp or ip proto \\tcp or ip proto \\udp"; // Filter hovorí, že má zachytávať iba pakety s protokolom ICMP, TCP alebo UDP
    bpf_u_int32 net = 0; // Deklaruje premennú net typu bpf_u_int32, ktorá bude obsahovať IP adresu siete. Táto hodnota sa nepoužíva v kóde, ale je potrebná pre kompatibilitu s funkciami knižnice libpcap

    // Parse command-line arguments
    char *interface = NULL;
    char sort_option = 'b'; // Default sort by bytes

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            sort_option = argv[++i][0]; // Use first char of sorting option
        }
    }

    if (interface == NULL) {
        fprintf(stderr, "Interface is required. Use -i <interface>\n");
        return 1;
    }

    /*Otvorí reláciu na zachytávanie paketov na zadanom rozhraní interface pomocou pcap_open_live.
        - BUFSIZ určuje maximálnu veľkosť paketov, ktoré sa majú zachytávať.
        - 1 znamená, že zachytí aj pakety, ktoré sú cielené na iné zariadenia (promiskuitný režim).
        - 1000 je časový limit v milisekundách, po ktorom sa načítajú dostupné pakety.
        - errbuf obsahuje chybové správy v prípade neúspešného otvorenia.*/
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    // Pokúsi sa skompilovať filter definovaný v filter_exp do pseudo-kódu BPF pomocou pcap_compile. Ak sa to nepodarí, vypíše chybu a program sa skončí.
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    // Nastaví skompilovaný filter fp na handle pomocou pcap_setfilter. Ak nastavenie zlyhá, vypíše chybové hlásenie a program sa skončí.
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Step 3: Initialize ncurses and display header
    initscr();
    noecho();
    cbreak(); // Disable line buffering
    refresh();
    
    /* Spustí nekonečný cyklus, kde sa neustále zachytáva a spracúva 10 paketov súčasne pomocou pcap_loop.
        Funkcia got_packet bude zavolaná pre každý zachytený paket.*/
    while (1) {
        pcap_loop(handle, 10, got_packet, NULL); // Process 10 packets at a time
        
        // Display updated stats
        display_stats(sort_option);
        
        sleep(1); // Update every second
    }

    endwin();
    pcap_close(handle); // Close the handle
    return 0;
}
