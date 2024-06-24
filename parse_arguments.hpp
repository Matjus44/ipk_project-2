/*
 * Program: Packet Sniffer
 * Description: Header file for parse_argument.cpp.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */

#ifndef PARSE_ARGUMENTS_HPP
#define PARSE_ARGUMENTS_HPP

#include <iostream>
#include <map>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>

// Class for storing arguments from command line as well as methods for parsing arguments
class Argument_parser 
{
    public:
        std::string interface = "";
        bool all = false;
        bool tcp = false;
        bool udp = false;
        int port = -1;
        int port_destination = -1;
        int port_source = -1;
        bool icmp4 = false;
        bool icmp6 = false;
        bool arp = false;
        bool ndp = false;
        bool igmp = false;
        bool mld = false;
        int n = 1;

    public:
        void parse(int argc, char* argv[]);
        void parse_interface(const std::string& arg);
        void parse_port(const std::string& arg,const std::string& arg_next);
        void parse_num(const std::string& arg);
        void print_help();
};

#endif // PARSE_ARGUMENTS_HPP