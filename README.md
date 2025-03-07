# Network sniffer - ZETA

**Meno a priezvisko:** Matúš Janek

**Login:** 237464

## Obsah

1. [Úvod](#úvod)
2. [Vstupné argumenty](#Vstupné-argumenty)
3. [Implementácia](#Implementácia)
    1. [Spracovanie vstupných argumentov](#Spracovanie-vstupných-argumentov)
    2. [Vytvorenie a spustenie filtru](#Vytvorenie-a-spustenie-filtru)
    3. [Výpis zachytených pakiet](#Výpis-zachytených-pakiet)
4. [Ilustrovaná funkcionalita](#Ilustrovaná-funkcionalita)
5. [Testovanie](#Testovanie)
6. [Bibliografia](#Bibliografia)

## Úvod

Táto dokumentácia slúži ako podrobný manuál k projektu ZETA, ktorý sa zameriava na implementáciu sieťového analyzátora. Projekt ZETA umožňuje zachytávanie a filtrovanie sieťových paketov na základe rôznych kritérií, čo umožňuje lepšie porozumenie komunikácie v sieti.

Dokumentácia obsahuje technické detaily implementácie, spôsoby použitia aplikácie a jej funkcionalít, ako aj postupy testovania a validácie implementovaných funkcií. Okrem toho sa tu nachádzajú aj informácie o doplnkových funkciách a prípadne zdroje, ktoré boli využité pri vytváraní projektu. Informácie o zadaní projektu viz. [2].

## Vstupné argumenty <a name="Vstupné-argumenty"></a>

Program je spúšťaný z príkazového riadka s nasledujúcimi parametrami:

`./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}`

Význam jednotlivých vstupných argumentov je špecifikovaný v zadaní viz. [2].

Tento program taktiež podporuje `-help` ktorý vypíše nápovedu, tento argument nesmenie byť zadaný s akýmkoľvek iným vstupným argumentom.

## Implementácia <a name="Implementácia"></a>

Tento program obsahuje súbory `parse_argument.cpp/hpp` v ktorej je implementovaná trieda `Argument_parser` ktorá obsahuje atribúty zodpovedajúce jednotlivých vstupných argumentom a metódy a ich spracovanie, `sniffer.cpp/hpp` obsahuje triedu `Sniffer` ktorá obsahuje metódy na vytvorenie filtra a súbor `sniffed_packets.cpp/hpp` obahuje triedu `PacketProcessing` ktorá obsauje statické metódy pre výpis jednotlivých zachytených paketov. Program začína v súbore `main.c`. Súčasčtou programu je aj súbor `Makefile` ktorý preloží daný súbor pomocou príkazu `make` cez terminál.

### Spracovanie vstupných argumentov <a name="Spracovanie-vstupných-argumentov"></a>

Vo funkcii main sa vytvorí inštancia triedy `Argument_parser` ktorá obsahuje potrebné metódy na parsovanie vstupných argumentov. Následne sa zavolá jej metóda `parser.parse(argc, argv)` ktorá berieme ako parametre pole argumentov a ich počet. V metóde `parser.parse(argc, argv)` sa následne volajú ďalšie pomocné metódy triedy `Argument_parser`. Vstupné argumenty sa následne ukladajú do atribútov inštačnej metódy `parser`.

### Vytvorenie a spustenie filtru <a name="Vytvorenie-a-spustenie-filtru"></a>

Po úspešnom spracovaní vstupných argumentov sa volá statická metóda `Sniffer::run_sniffer(parser)` , ktorá berie ako parameter inštačnú triedu `parser`. Následne sa inicializuje snifer pomocou metódy `pcap_t* Sniffer::init_sniffer(Argument_parser &parser)` ktorá zahŕňa otvorenie sieťového rozhrania pomocou funkcie `pcap_open_live`. Po inicializácii sniffera sa volá metóda `Sniffer::build_filter(parser, handle)`, ktorá slúži na vytvorenie a nastavenie filtru pre zachytávanie špecifických sieťových paketov. Program na základe zadaných parametrov a aplikuje ho na otvorený `sniffer` handle pomocou funkcií `pcap_compile` a `pcap_setfilter`. Po úspešnej inicializácii a nastavení filtra sa spúšťa zachytávanie sieťových paketov volaním metódy `Sniffer::capture_packets(parser, handle)`. Táto metóda používa funkciu `pcap_loop`, ktorá kontinuálne zachytáva pakety na základe definovaných parametrov, ako je počet paketov na zachytenie a funkcia na spracovanie zachytených paketov. Pre viacej popísaný význam jednotlivých funkcií filteru viz. [3].

### Výpis zachytených pakiet <a name="Výpis-zachytených-pakiet"></a>

Funkcia `PacketProcessing::parse_frame` je volaná v cykle, ktorý kontinuálne zachytáva pakety na základe nastavených parametrov sniffera.  Najprv sa z hlavičky paketu získa časová značka, ktorá označuje čas, keď bol paket zachytený. Nasleduje spracovanie MAC adries, kde sa zisťujú zdrojová a cieľová MAC adresa paketu a vypisujú sa pomocou metódy `static void print_mac_addresses(const u_char *frame)`, Na základe typu ethernetového rámca sa rozhoduje, ako ďalej spracovať IP adresy a porty v metóde `static void print_ip_and_ports(const u_char *frame,const struct pcap_pkthdr *header)`.  Ak je typ rámca IPv4, vykoná sa spracovanie tejto časti paketu podľa `static void process_v4(const u_char *frame,const struct pcap_pkthdr *header)`. Podobne pre IPv4 v metóde `static void process_v6(const u_char *frame,const struct pcap_pkthdr *header)`. Pre ARP pakety sa vypíšu informácie o MAC a IP adresách. Nakoniec sa vypíše obsah paketu v hexadecimálnom a ASCII formáte spolu s bajtovým offsetom.

## Ilustrovaná funkcionalita <a name="Ilustrovaná-funkcionalita"></a>

**Vytvorenie filteru**

```
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
    if (pcap_compile(handle, &bpf_prog, filter.c_str(), 0, mask) == PCAP_ERROR)
    {
        std::cerr << "Error: Filter compiling: " << pcap_geterr(handle) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &bpf_prog) == PCAP_ERROR)
    {
        std::cerr << "Error: Setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&bpf_prog); // Dealloc pcap_compile
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&bpf_prog); // // Dealloc pcap_compile
}
```

**Táto funkcia zobrazuje postupnosť volania funkcií pri vypisavaní paketov na výstup**

```
void PacketProcessing::parse_frame(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    (void)user;

    // Print timestamp
    print_timestamp(header);

    // Parse and print IP addresses and ports if available
    print_ip_and_ports(frame,header);

    // Print byte offset, hexa, and ASCII
    print_byte_offset_hexa_ascii(frame, header->len);
}
```

## Testovanie <a name="Testovanie"></a>

**Program bol úspešne testovaný pomocou posielanie paketov príkazom ping cez terminál.**

**Program bol spustený následujúcim príkazom:** `sudo ./ipk-sniffer -i eth0`

**Testovacie prostredie:** WSL.

**Dôvod testovania:** Overenie funkcionality.

**Výstup:**

```
timestamp: 2024-04-22T14:11:00+02:00
src MAC: 01:00:5E:7F:FF:FA
dst MAC: 00:15:5D:53:5D:66
frame length: 216 bytes
src IP: 172.18.208.1
dst IP: 239.255.255.250
src port: 55227
dst port: 1900

0x0000: 01 00 5e 7f ff fa 00 15  5d 53 5d 66 08 00 45 00   ..^..... ]S]f..E.
0x0010: 00 ca 83 5b 00 00 01 11  c9 b9 ac 12 d0 01 ef ff   ...[.... ........
0x0020: ff fa d7 bb 07 6c 00 b6  b1 99 4d 2d 53 45 41 52   .....l.. ..M-SEAR
0x0030: 43 48 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48   CH * HTT P/1.1..H
0x0040: 4f 53 54 3a 20 32 33 39  2e 32 35 35 2e 32 35 35   OST: 239 .255.255
0x0050: 2e 32 35 30 3a 31 39 30  30 0d 0a 4d 41 4e 3a 20   .250:190 0..MAN: 
0x0060: 22 73 73 64 70 3a 64 69  73 63 6f 76 65 72 22 0d   "ssdp:di scover".
0x0070: 0a 4d 58 3a 20 31 0d 0a  53 54 3a 20 75 72 6e 3a   .MX: 1.. ST: urn:
0x0080: 64 69 61 6c 2d 6d 75 6c  74 69 73 63 72 65 65 6e   dial-mul tiscreen
0x0090: 2d 6f 72 67 3a 73 65 72  76 69 63 65 3a 64 69 61   -org:ser vice:dia
0x00a0: 6c 3a 31 0d 0a 55 53 45  52 2d 41 47 45 4e 54 3a   l:1..USE R-AGENT:
0x00b0: 20 47 6f 6f 67 6c 65 20  43 68 72 6f 6d 65 2f 31    Google  Chrome/1
0x00c0: 32 34 2e 30 2e 36 33 36  37 2e 36 31 20 57 69 6e   24.0.636 7.61 Win
0x00d0: 64 6f 77 73 0d 0a 0d 0a                            dows....

```

**Porovanie výstupu:**  Výstup bol zhodný s očakávaným výstupom.


## Bibliografia <a name="Bibliografia"></a>

[1]: NESFIT . (2024). Documentation Instructions , IPK Projects 2024 [online]. Publisher: Brno University of Technology. Retrieved March 31, 2024, [cit. 2024-04-15] Available at: https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024#documentation-instructions

[2]: Vladimir Vesely . (2024). Project 2 Zeta , IPK Projects 2024 [online]. Publisher: Brno University of Technology. Retrieved March 31, 2024, [cit. 2024-04-15] Available at: https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%202/zeta

[3]: ENGRSALMANSHAIKH . (DECEMBER 9, 2014). NETWORK PACKET SNIFFER C++ [online]. Publisher: UNCATEGORIZED . Retrieved April 31, 2024, [cit. 2024-04-15] Available at: https://engrsalmanshaikh.wordpress.com/2014/12/09/network-packet-sniffer-c/