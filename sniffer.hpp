/*
 * Program: Packet Sniffer
 * Description: Header file for sniffer.cpp.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */

#ifndef SNIFFER_HPP
#define SNIFFER_HPP
#include "parse_arguments.hpp"
#include <pcap.h>

// Class for static methods used for creating filter and capturing packets.
class Sniffer
{  
    public:
        static void run_sniffer(Argument_parser& parser);
        static pcap_t* init_sniffer(Argument_parser& parser);
        static void build_filter(Argument_parser& parser, pcap_t* handle);
        static std::string filters_parameters(Argument_parser& parser);
        static void capture_packets(Argument_parser& parser, pcap_t *handle);
        static void port_select(Argument_parser &parser,std::string *filter,std::string protocol);
};

#endif