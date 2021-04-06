/*
 * =====================================================================================
 *
 *       Filename:  nettools.h
 *
 *    Description:  Utils for arp spoofing 
 *
 *        Version:  1.0
 *        Created:  06/04/21 15:43:54
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Ali (mn), 
 *        Company:  FH Südwestfalen, Iserlohn
 *
 * =====================================================================================
 */
#ifndef __NETTOOLS__
#define __NETTOOLS__
#include <net/ethernet.h>
#include <net/if.h>

#define FAIL     -1
#define ARPSIZ   42 
#define IPSLEN   20
#define IP_ALEN  4
#define MACSLEN  25
#define NPACKS   20
#define SDELAY   500
#define STIMEOUT 7 
#define TCPBUFZ  68800

extern uint8_t broadcast[], empty[];

struct ip_mac {
    uint8_t ip[IP_ALEN];
    uint8_t mac[ETH_ALEN];
    struct ip_mac *next;
};

void mac_to_str(char[], uint8_t[]);
void ip_to_str(char[], uint8_t[]);
void destroy_pairs(struct ip_mac *);
int is_valid_ip(char *);
int get_default_interface(char[]);
int get_if_info(int, char[], struct ifreq *,
                             struct ifreq *,
                             struct ifreq *);
struct ip_mac *ip_sweep(int, int, uint8_t[],
                                  uint8_t[]);
struct ether_arp *recv_arp(int sock, unsigned short op_code, 
                                     uint8_t s_ip[IP_ALEN]);
int send_arp(int sock, int if_idx, uint8_t[], 
                                   uint8_t[], 
                                   uint8_t[], 
                                   uint8_t[], 
                                   uint8_t[], 
                                   uint8_t[], 
                                   unsigned short);
#endif
