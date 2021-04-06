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


int main(int argc, const char *argv[]) {
    char dev[IFNAMSIZ];
    char our_m_str[MACSLEN], target_m_str[MACSLEN], host_m_str[MACSLEN], reply_m_str[MACSLEN];    
    char our_ip_str[IPSLEN], host_str[IPSLEN], target_str[IPSLEN], reply_str[IPSLEN];
    struct ifreq ifreq_i, ifreq_c, ifreq_ip;
    uint8_t our_ip[IP_ALEN], host_ip[IP_ALEN], target_ip[IP_ALEN];
    int sock; 
    unsigned char our_mac[ETH_ALEN], target_mac[ETH_ALEN], host_mac[ETH_ALEN];
    int num_packets = NPACKS;

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
    if (argc < 4) {
        printf("Usage: ./arp_spoof <interface> <target-sufix> <host-sufix>");
        exit(2);
    }
    if (argc > 4) {
        num_packets = atoi(argv[4]);
    }
    if (strlen(argv[2]) > 3 || strlen(argv[3]) > 3) {
        printf("Sufix too long! Max length 3\n");
        exit(3);
    }
    
    // get device
    strncpy(dev, argv[1], IFNAMSIZ);
    dev[strlen(argv[1])] = 0;

    // get interface info
    if(get_if_info(sock, dev, &ifreq_i, &ifreq_c, &ifreq_ip) == -1) {
        printf("Failed to get info for interface %s (you probably chose the worng one, try ifconfig or google)\n", dev);
        exit(3);
    }

    // print/save interface info 
    memcpy(our_mac, (unsigned char *)(ifreq_c.ifr_hwaddr.sa_data), ETH_ALEN);
    mac_to_str(our_m_str, our_mac); 
    memcpy(our_ip, (void *)&(((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr), IP_ALEN);
    ip_to_str(our_ip_str, our_ip);

    // parse and check target/host
    uint8_t h_sufix, t_sufix;

    if ((t_sufix = atoi(argv[2])) > 0xff) {
        fprintf(stderr, "Error : target sufix %d to large\n", t_sufix);
        exit(1);
    }
    if ((h_sufix = atoi(argv[3])) > 0xff) {
        fprintf(stderr, "Error : host sufix %d to large\n", h_sufix);
        exit(1);
    }
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
    send_arp(sock, ifreq_i.ifr_ifindex, our_mac,
            broadcast, 
            our_mac, 
            empty, 
            our_ip, 
            host_ip,
            ARPOP_REQUEST);

    // get host MAC from reply
    memcpy(host_mac, recv_arp(sock, ARPOP_REPLY, host_ip)->arp_sha, ETH_ALEN);
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
    memcpy(target_mac, recv_arp(sock, ARPOP_REPLY, target_ip)->arp_sha, ETH_ALEN);
    mac_to_str(target_m_str, target_mac);

    // cure host
    printf("Antidote...\n");
    for (int i = num_packets; i > 0; --i) {
        send_arp(sock, ifreq_i.ifr_ifindex, 
                target_mac,
                host_mac, 
                target_mac, 
                host_mac, 
                target_ip, 
                host_ip,
                ARPOP_REPLY);

        sleep(1);
        printf("H:(%s) ---> T:(%s)\n", host_m_str, target_m_str);
    }

    // cure target 
    printf("Antidote...\n");
    for (int i = num_packets; i > 0; --i) {
        send_arp(sock, ifreq_i.ifr_ifindex, 
                host_mac,
                target_mac,
                host_mac,
                target_mac,
                host_ip,
                target_ip,
                ARPOP_REPLY);
        
        sleep(1);
        printf("H:(%s) <--- T:(%s)\n", target_m_str, host_m_str);
    }
    exit(0);
}


