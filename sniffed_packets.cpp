/*
 * Program: Packet Sniffer
 * Description: Source file sniffed.packets.cpp, in which is implemented printing of captured packets.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */

#include "sniffed_packets.hpp"

void PacketProcessing::parse_frame(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    (void)user;

    // Print timestamp
    print_timestamp(header);

    // Parse and print IP addresses and ports if available
    print_ip_and_ports(frame, header);

    // Print byte offset, hexa, and ASCII
    print_byte_offset_hexa_ascii(frame, header->len);
}

void PacketProcessing::print_timestamp(const struct pcap_pkthdr *header)
{
    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);

    // Buffer for storing
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);
    char tzbuffer[6];
    strftime(tzbuffer, sizeof(tzbuffer), "%z", timeinfo);
    std::string tzformatted = std::string(tzbuffer).insert(3, ":");
    std::string timestamp = std::string(buffer) + tzformatted;
    std::cout << "timestamp: " << timestamp << std::endl;
}

void PacketProcessing::print_mac_addresses(const u_char *frame)
{
    // Parse and print source MAC address
    std::cout << "src MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        printf("%02X", frame[i]);
        if (i < ETHER_ADDR_LEN - 1)
        {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    // Parse and print destination MAC address
    std::cout << "dst MAC: ";
    for (int i = ETHER_ADDR_LEN; i < ETHER_ADDR_LEN * 2; ++i)
    {
        printf("%02X", frame[i]);
        if (i < ETHER_ADDR_LEN * 2 - 1)
        {
            std::cout << ":";
        }
    }
    std::cout << std::endl;
}

void PacketProcessing::process_v4(const u_char *frame, const struct pcap_pkthdr *header)
{
    auto ip4 = reinterpret_cast<const struct ip *>(frame + sizeof(struct ether_header));

    // Print source and destination MAC addresses
    print_mac_addresses(frame);

    // Print frame length
    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    // Determine the protocol and process accordingly
    int ip_header_len = ip4->ip_hl * 4;
    switch (ip4->ip_p)
    {
    case IPPROTO_ICMP:
    {
        // Print source and destination IP addresses
        std::cout << "src IP: " << inet_ntoa(ip4->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip4->ip_dst) << std::endl;
    }
    break;
    case IPPROTO_TCP:
    {
        // Print source and destination IP addresses
        std::cout << "src IP: " << inet_ntoa(ip4->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip4->ip_dst) << std::endl;
        const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(frame + sizeof(struct ether_header) + ip_header_len);
        std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;
    }
    break;
    case IPPROTO_UDP:
    {
        // Print source and destination IP addresses
        std::cout << "src IP: " << inet_ntoa(ip4->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip4->ip_dst) << std::endl;
        const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + ip_header_len);
        std::cout << "src port: " << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "dst port: " << ntohs(udp_header->uh_dport) << std::endl;
    }
    break;
    case IPPROTO_IGMP:
    {
        // Print source and destination IP addresses
        std::cout << "src IP: " << inet_ntoa(ip4->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip4->ip_dst) << std::endl;
    }
    break;
    default:
        std::cout << "Error: Unknown protocol" << std::endl;
        exit(EXIT_FAILURE);
        break;
    }
}

void PacketProcessing::process_v6(const u_char *frame, const struct pcap_pkthdr *header)
{
    print_mac_addresses(frame);
    // Print frame length
    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    auto ip6 = reinterpret_cast<const struct ip6_hdr *>(frame + sizeof(struct ether_header)); // Get IPv6 header

    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];

    // Convert source and destination IP addresses to string format
    inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);

    // Print source and destination IP addresses
    std::cout << "src IP: " << src_ip_str << std::endl;
    std::cout << "dst IP: " << dst_ip_str << std::endl;

    // Check the next header field to determine the protocol
    uint8_t next_header = ip6->ip6_nxt;
    switch (next_header)
    {
    case IPPROTO_TCP:
    {
        const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(frame + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;
    }
    break;
    case IPPROTO_UDP:
    {
        const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        std::cout << "src port: " << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "dst port: " << ntohs(udp_header->uh_dport) << std::endl;
    }
    break;
    }
}

void PacketProcessing::process_arp(const u_char *frame, const struct pcap_pkthdr *header)
{
    const struct ether_arp *arp_packet = reinterpret_cast<const struct ether_arp *>(frame + sizeof(struct ether_header));

    // Print sender MAC address
    std::cout << "src MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        printf("%02X", arp_packet->arp_sha[i]);
        if (i < ETHER_ADDR_LEN - 1)
        {
            std::cout << ":";
        }
    }
    std::cout << "\n";

    // Print target MAC address
    std::cout << "dst MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        printf("%02X", arp_packet->arp_tha[i]);
        if (i < ETHER_ADDR_LEN - 1)
        {
            std::cout << ":";
        }
    }
    std::cout << "\n";

    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    // Print sender IP address
    std::cout << "src IP: " << inet_ntoa(*(struct in_addr *)arp_packet->arp_spa) << "\n";

    // Print target IP address
    std::cout << "dst IP: " << inet_ntoa(*(struct in_addr *)arp_packet->arp_tpa) << "\n";
}

void PacketProcessing::print_ip_and_ports(const u_char *frame, const struct pcap_pkthdr *header)
{
    const struct ether_header *eth_header = reinterpret_cast<const struct ether_header *>(frame);
    // Get the Ethernet type
    auto ether_type = ntohs(eth_header->ether_type);

    // Check the Ethernet type and print corresponding information
    if (ether_type == ETHERTYPE_IP)
    {
        process_v4(frame, header);
    }
    else if (ether_type == ETHERTYPE_IPV6)
    {
        process_v6(frame, header);
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        process_arp(frame, header);
    }
}

void PacketProcessing::print_byte_offset_hexa_ascii(const u_char *frame, int frame_len)
{
    printf("\n");
    // Loop through the frame data
    for (int i = 0; i < frame_len; i += 16)
    {
        // Print the current byte offset in hexadecimal format
        printf("0x%04x: ", i);

        // Print the hexadecimal representation of the bytes
        for (int j = i; j < i + 8; j++)
        {
            if (j < frame_len)
            {
                printf("%02x ", frame[j]);
            }
            else
            {
                // Print extra spaces if we don't have a full line of bytes
                printf("   ");
            }
        }

        printf(" "); // Space separating the two hex blocks

        for (int j = i + 8; j < i + 16; j++)
        {
            if (j < frame_len)
            {
                printf("%02x ", frame[j]);
            }
            else
            {
                // Print extra spaces if we don't have a full line of bytes
                printf("   ");
            }
        }

        printf("  "); // Two spaces before ASCII representation

        // Print the ASCII representation of the bytes
        for (int j = i; j < i + 16 && j < frame_len; j++)
        {
            if (j == i + 8)
            {
                printf(" "); // Space separating the hex and ASCII part in the middle
            }

            // Check if the byte is printable
            if (frame[j] >= 32 && frame[j] <= 126)
            {
                printf("%c", frame[j]);
            }
            else
            {
                // Print a dot for non-printable characters
                printf(".");
            }
        }

        // Print a newline character at the end of each 16-byte row
        printf("\n");
    }

    // Print an extra newline character for better formatting
    printf("\n");
}