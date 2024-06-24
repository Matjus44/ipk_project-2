/*
 * Program: Packet Sniffer
 * Description: Source file parse_arguments.cpp in which is implemented logic of argument parsing.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */

#include "parse_arguments.hpp"

void Argument_parser::print_help()
{
    printf("Usage: packet_sniffer [OPTIONS]\n");
    printf("Options:\n");
    printf("  -i, --interface <interface>  Specify the network interface to sniff. If not specified, prints a list of active interfaces.\n");
    printf("  -t, --tcp                    Display TCP segments. Can be combined with -p or --port-* options for port filtering.\n");
    printf("  -u, --udp                    Display UDP datagrams. Can be combined with -p or --port-* options for port filtering.\n");
    printf("  -p <port>                    Filter TCP/UDP traffic by the specified port number (source or destination).\n");
    printf("  --port-destination <port>    Filter TCP/UDP traffic by the specified destination port number.\n");
    printf("  --port-source <port>         Filter TCP/UDP traffic by the specified source port number.\n");
    printf("  --icmp4                      Display only ICMPv4 packets.\n");
    printf("  --icmp6                      Display only ICMPv6 echo request/response packets.\n");
    printf("  --arp                        Display only ARP frames.\n");
    printf("  --ndp                        Display only NDP packets.\n");
    printf("  --igmp                       Display only IGMP packets.\n");
    printf("  --mld                        Display only MLD packets.\n");
    printf("  -n <number>                  Specify the number of packets to capture and display. Default is 1.\n");
    printf("All parameters are optional and can be combined in any order.\n");
}

// Add interface
void Argument_parser::parse_interface(const std::string &arg)
{
    interface = arg;
}

// Add port number
void Argument_parser::parse_port(const std::string &arg, const std::string &arg_next)
{
    try
    {
        int tmp = std::stoi(arg_next);
        if (arg == "-p")
        {
            port = tmp;
        }
        else if (arg == "--port-source")
        {
            port_source = tmp;
        }
        else if (arg == "--port-destination")
        {
            port_destination = tmp;
        }
    }
    catch (const std::invalid_argument &)
    {
        std::cerr << "Error: Port number must be a valid integer." << std::endl;
        exit(EXIT_FAILURE);
    }
}

// Parse number for amount of capturing packets
void Argument_parser::parse_num(const std::string &arg)
{
    try
    {
        n = std::stoi(arg);
    }
    catch (const std::invalid_argument &)
    {
        std::cerr << "Error: Number of packets must be a valid integer." << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Argument_parser::parse(int argc, char *argv[])
{
    // Loop through arguments

    bool port_occured = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        // Interface, if arguments requires another argument for specification, for example like port number after -p {-p 20} => check if the second argument is not empty and suits expected format
        if ((arg == "-i" || arg == "--interface") && interface == "")
        {
            if (argv[i + 1] == nullptr || argv[i + 1][0] == '\0')
            {
                break;
            };
            parse_interface(argv[i + 1]);
            i++;
        }
        // Port
        else if ((arg == "-p" || arg == "--port-source" || arg == "--port-destination") && port_occured == false)
        {
            port_occured = true;
            if (argv[i + 1] == nullptr || argv[i + 1][0] == '\0')
            {
                std::cerr << "Error: Missing port number" << std::endl;
                exit(EXIT_FAILURE);
            };
            parse_port(arg, argv[i + 1]);
            i++;
        }
        // Number of capturing packets
        else if (arg == "-n" && n == 1)
        {
            if (argv[i + 1] == nullptr || argv[i + 1][0] == '\0')
            {
                std::cerr << "Error: Missing number for count of captured packets" << std::endl;
                exit(EXIT_FAILURE);
            };
            parse_num(argv[i + 1]);
            i++;
        }
        // TCP
        else if ((arg == "--tcp" || arg == "-t") && tcp == false)
        {
            tcp = true;
        }
        // UDP
        else if ((arg == "--udp" || arg == "-u") && udp == false)
        {
            udp = true;
        }
        // ARP
        else if (arg == "--arp" && arp == false)
        {
            arp = true;
        }
        // ICMPV4
        else if (arg == "--icmp4" && icmp4 == false)
        {
            icmp4 = true;
        }
        // ICMPV6
        else if (arg == "--icmp6" && icmp6 == false)
        {
            icmp6 = true;
        }
        // NDP
        else if (arg == "--ndp" && ndp == false)
        {
            ndp = true;
        }
        // IGMP
        else if (arg == "--igmp" && igmp == false)
        {
            igmp = true;
        }
        // MLD
        else if (arg == "--mld" && mld == false)
        {
            mld = true;
        }
        else if(arg == "-help" && argc == 2)
        {
            print_help();
            exit(0);
        }
        // Unknown argument
        else
        {
            if(arg == "-help")
            {
                std::cerr << "Error: Parameter help has to be alone" << std::endl;
                exit(EXIT_FAILURE);
            }
            else
            {
                std::cerr << "Error: Unknown parameter " << arg << std::endl;
                exit(EXIT_FAILURE);
            }
        }
    }
}