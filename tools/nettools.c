/*
 * =====================================================================================
 *
 *       Filename:  nettools.c
 *
 *    Description:  Utils for arp spoofing
 *
 *        Version:  1.0
 *        Created:  06/04/21 15:52:47
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Ali (mn), 
 *        Company:  FH Südwestfalen, Iserlohn
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <time.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include "nettools.h"


uint8_t broadcast[] = "\xff\xff\xff\xff\xff\xff";
uint8_t empty[]     = "\x00\x00\x00\x00\x00\x00";

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

void mac_to_str(char mac_str[MACSLEN], uint8_t mac[ETH_ALEN]) {
    snprintf(mac_str, MACSLEN, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", 
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]);
}

void ip_to_str(char ip_str[IPSLEN], uint8_t ip[IP_ALEN]) {
    snprintf(ip_str, IPSLEN, "%d.%d.%d.%d", 
            ip[0],
            ip[1],
            ip[2],
            ip[3]);
}

int get_default_interface (char dev[IFNAMSIZ]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;

    char failfo[] = "Error : could not default interface, please enter one (with option -i)";

    // get default interface
    if (pcap_findalldevs(&devs, errbuf) == FAIL) {
        fprintf(stderr, "%s\n", failfo); 
        return FAIL;

    }
    if (devs == NULL) {
        fprintf(stderr, "%s\n", failfo);
        return FAIL;
    }
    int len = strlen(devs->name);

    if (len > IFNAMSIZ) {
        fprintf(stderr, "Error : Default interface name %s too long\n",
                devs->name);
        return FAIL;
    }
    strncpy(dev, devs->name, IFNAMSIZ);
    dev[len] = 0;
    return 0;
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
                ip_mac_pairs = add_ip_mac(ip_mac_pairs, 
                                          arp->arp_spa, 
                                          arp->arp_sha);
            }
        }
        start = time(NULL);
    }
    return ip_mac_pairs;
}

void destroy_pairs(struct ip_mac *head) {
    if (head == NULL) {
        return;
    }
    destroy_pairs(head->next);
    free(head);
}

int send_arp(int sock, int if_idx, uint8_t s_mac[ETH_ALEN], 
                                   uint8_t d_mac[ETH_ALEN], 
                                   uint8_t arp_s_mac[ETH_ALEN], 
                                   uint8_t arp_t_mac[ETH_ALEN], 
                                   uint8_t arp_s_ip[IP_ALEN], 
                                   uint8_t arp_t_ip[IP_ALEN], 
                                   unsigned short opcode) {
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

struct ether_arp *recv_arp(int sock, unsigned short op_code, 
                                     uint8_t s_ip[IP_ALEN]) {
    uint8_t *buf;
    
    if ((buf = malloc(ARPSIZ)) == NULL) {
        fprintf(stderr, "could not malloc buf in %s\n", __FUNCTION__);
        return NULL;
    }

    while (read(sock, buf, ARPSIZ) > 0) {

        // check is arp
        if (ntohs(((struct ethhdr*)(buf))->h_proto) == ETH_P_ARP) {
            struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr ));

            // check is correct type & IP 
            if (ntohs(arp->ea_hdr.ar_op) == op_code && memcmp(arp->arp_spa, s_ip, 4) == 0) {
                return arp;
            }
        }
    }
    fprintf(stderr, "Error : sock read failed in %s\n", __FUNCTION__); 
    return NULL;
}

int is_valid_ip(char *ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &sa);
    return result > 0;
}

