/*
 * Program: Packet Sniffer
 * Description: Main.c, main file where the program starts.
 * Author: Matúš Janek
 * Date: 15.04.2024
 */


#include "parse_arguments.hpp"
#include "sniffer.hpp"

// Function for capturing ctrl+c
void sigint_handle(int pid)
{
    (void)pid;
    exit(0);
}

// Function to handle segmentation fault
void segfault_handle(int sig)
{
    (void)sig;
    std::cerr << "Unexpected error occured" << std::endl;
    exit(EXIT_FAILURE);
}

// Function for printing available interfaces if interface specification was not passed through command line.
void print_available_interfaces()
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    // Get all available interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }
    pcap_if_t *dev;
    int i = 0;
    // Loop trough list of interfaces
    for (dev = alldevs; dev != nullptr; dev = dev->next)
    {
        std::cout << ++i << ": " << dev->name;
        if (dev->description)
        {
            std::cout << " (" << dev->description << ")";
        }
        std::cout << std::endl;
    }
    // Dealloc memory
    pcap_freealldevs(alldevs);
}

// Main function
int main(int argc, char *argv[])
{
    // Structure for ctrl+c
    signal(SIGINT, sigint_handle);

    // Set up signal handler for SIGSEGV
    struct sigaction sa;
    sa.sa_handler = segfault_handle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, nullptr);

    // Create object at parse arguments
    Argument_parser parser;
    parser.parse(argc, argv);
    // Check for interface
    if (parser.interface == "")
    {
        print_available_interfaces();
        exit(0);
    }
    else
    {
        // Run sniffer
        Sniffer::run_sniffer(parser);
    }
    exit(0);
}