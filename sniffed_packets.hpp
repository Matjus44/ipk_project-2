/*
 * Program: Packet Sniffer
 * Description: Header file for sniffed_packets.cpp.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */

#ifndef SNIFFED_PACKETS_HPP
#define SNIFFED_PACKETS_HPP

#include "parse_arguments.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h> // For inet_ntop
#include <netinet/if_ether.h> // For Ethernet header
#include <netinet/ip.h> // For IP header
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <pcap.h>
#include <netinet/igmp.h> // For IGMP header

#define ETHERTYPE_IGMP 0x0802

class PacketProcessing
{
    public:
        static void parse_frame(u_char *user, const struct pcap_pkthdr *header,const u_char *frame);
        static void print_timestamp(const struct pcap_pkthdr *header);
        static void print_mac_addresses(const u_char *frame);
        static void print_ip_and_ports(const u_char *frame,const struct pcap_pkthdr *header);
        static void process_v4(const u_char *frame,const struct pcap_pkthdr *header);
        static void process_v6(const u_char *frame,const struct pcap_pkthdr *header);
        static void process_arp(const u_char *frame, const struct pcap_pkthdr *header);
        static void print_byte_offset_hexa_ascii(const u_char *frame, int frame_len);
};

#endif