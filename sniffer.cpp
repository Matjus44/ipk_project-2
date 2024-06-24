/*
 * Program: Packet Sniffer
 * Description: Source file sniffer.cpp in which we implemented creation of sniffer.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */

#include "sniffer.hpp"
#include "sniffed_packets.hpp"

static char errbuf[PCAP_ERRBUF_SIZE];

// Method where we call other methods for better track of program run.
void Sniffer::run_sniffer(Argument_parser &parser)
{
    pcap_t* handle = init_sniffer(parser);
    build_filter(parser, handle);
    capture_packets(parser,handle);
}

// Initialize interface
pcap_t* Sniffer::init_sniffer(Argument_parser &parser)
{
    // Open interface
    auto handle = pcap_open_live(parser.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Error: Could not open interface: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        std::cerr << "Error: Ethernet not supported on specified interface" << std::endl;
        exit(EXIT_FAILURE);
    }
    return handle;
}

// Build up and set sniffer
void Sniffer::build_filter(Argument_parser &parser, pcap_t *handle)
{
    auto filter = filters_parameters(parser);
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct bpf_program bpf_prog;

    if (pcap_lookupnet(parser.interface.c_str(), &net, &mask, errbuf) == PCAP_ERROR)
    {
        std::cerr << "Error: Looking up network: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }
    // Compile filter
    if (pcap_compile(handle, &bpf_prog, filter.c_str(), 0, mask) == PCAP_ERROR)
    {
        std::cerr << "Error: Filter compiling: " << pcap_geterr(handle) << std::endl;
        exit(EXIT_FAILURE);
    }
    // Set filter
    if (pcap_setfilter(handle, &bpf_prog) == PCAP_ERROR)
    {
        std::cerr << "Error: Setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&bpf_prog); // Dealloc pcap_compile
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&bpf_prog); // // Dealloc pcap_compile
}

// Supporting function for adding port into filter
void Sniffer::port_select(Argument_parser &parser, std::string *filter,std::string protocol)
{
    // According to port paramter we add it into filter with corresponding protocol
    if (!filter->empty())
    {
        *filter += " or ";
    }
    if(parser.port != -1)
    {
        *filter += protocol + " port " + std::to_string(parser.port);
    }
    else if(parser.port_source != -1)
    {
        *filter += protocol + " src port " + std::to_string(parser.port_source);
    }
    else if(parser.port_destination != -1)
    {
        *filter += protocol + " dst port " + std::to_string(parser.port_source);
    }
    else
    {
        *filter += protocol;
    }
}



// Set filters arguments
std::string Sniffer::filters_parameters(Argument_parser &parser)
{
    std::string filter;

    // If only port is specified, then it can be both tcp and udp
    if((parser.tcp == false && parser.udp == false) && (parser.port == true || parser.port_destination == true || parser.port_source == true))
    {
        port_select(parser,&filter,"tcp");
        port_select(parser,&filter,"udp");
    }

    // TCP
    if (parser.tcp)
    {
        port_select(parser,&filter,"tcp");
    }

    // UDP
    if (parser.udp)
    {
        port_select(parser,&filter,"udp");
    }

    // ICMP4
    if (parser.icmp4)
    {
        if (!filter.empty())
        {
            filter += " or ";
        }
        filter += "icmp";
    }
    // ICMP6
    if (parser.icmp6)
    {
        if(!filter.empty())
        {
            filter += " or ";
        }
        filter += "icmp6";
    }

    // ARP
    if (parser.arp)
    {
        if (!filter.empty())
        {
            filter += " or ";
        }
        filter += "arp";
    }
    // NDP
    if(parser.ndp)
    {
        if (!filter.empty())
        {
            filter += " or ";
        }
        filter += "(icmp6 and (ip6[40] == 135 or ip6[40] == 136 or ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 137))";
    }
    // IGMP
    if (parser.igmp)
    {
        if (!filter.empty())
        {
            filter += " or ";
        }
        filter += "igmp";
    }
    // MLD
    if(parser.mld)
    {
        if (!filter.empty())
        {
            filter += " or ";
        }
        // MLD messages typically involve the following types
        filter += "(icmp6 and (ip6[40] >= 130 and ip6[40] <= 132 or ip6[40] = 143))";
    }
    
    return filter;
}

// Start capturing packets
void Sniffer::capture_packets(Argument_parser &parser, pcap_t *handle)
{
    if (pcap_loop(handle, parser.n, PacketProcessing::parse_frame, nullptr) < 0) 
    {
        std::cerr << "Error: Issue while capturing packets: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    // Close filter
    pcap_close(handle);
}