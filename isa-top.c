#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ncurses.h>
#include <string.h>

WINDOW *win;
int line_count = 1;  // Start at 1 to account for header line

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)

    // Print IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    char buffer[6];
    if (ip_header->ip_p == IPPROTO_TCP) {
        strcpy(buffer, "TCP");
        // You can add port extraction logic here
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        strcpy(buffer, "UDP");
        // You can add port extraction logic here
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        strcpy(buffer, "ICMP");
    } else {
        strcpy(buffer, "Other");
    }

    // Print packet information to the window
    mvwprintw(win, line_count, 0, "%-15s %-15s %-5s", src_ip, dst_ip, buffer);
    
    // Increment line count
    line_count++;

    // Refresh the window to show the new line
    wrefresh(win);

    // If we've reached the bottom of the window, scroll up
    if (line_count >= 10) { // Adjust based on window size
        scroll(win);
        line_count--;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto \\icmp or ip proto \\tcp or ip proto \\udp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name "eth0"
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    // Step 2: Compile filter into BPF pseudo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Step 3: Capture packets
    initscr();
    noecho();
    cbreak(); // Disable line buffering, pass everything to me
    win = newwin(11, 250, 2, 2); // Create a window
    box(win, 0, 0); // Draw a border around the window
    refresh();
    wrefresh(win);

    mvwprintw(win, 0, 0, "Src IP          Dst IP          Proto");
    wrefresh(win); // Refresh to show the header line

    pcap_loop(handle, -1, got_packet, NULL);

    endwin();
    pcap_close(handle); // Close the handle
    return 0;
}
