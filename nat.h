#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <arpa/inet.h>

#include <netinet/ip.h>		// required by "struct iph"
#include <netinet/tcp.h>	// required by "struct tcph"
#include <netinet/udp.h>	// required by "struct udph"
#include <netinet/ip_icmp.h>	// required by "struct icmphdr"

#include <sys/types.h>		// required by "inet_ntop()"
#include <sys/socket.h>		// required by "inet_ntop()"
#include <arpa/inet.h>		// required by "inet_ntop()"

#include "list.h" 

#define BUF_SIZE 1024

#ifndef BUILD
#include <errno.h>
#define printe(fmt, arg ...) \
    fprintf(stderr, "[1;32m[%ld][0m [1;42m[%s: %10s(): %3d][0m " fmt, \
            time(NULL), __FILE__, __FUNCTION__, __LINE__, ##arg)
#else
#define printe(fmt, ...) (0)
#endif

struct nat_list {
    int sockfd;

    int state;

    u_int16_t nat_port; 

    u_int32_t src_addr;  
    u_int16_t src_port; 

//    u_int32_t dest_addr;
//    u_int16_t dest_port; 

    struct list_head list;  
}; 

/* nat_list.c */ 
struct nat_list *nat_add(int sockfd, u_int16_t nat_port, u_int32_t src_addr, u_int32_t src_port);
struct nat_list *nat_search_port(u_int16_t nat_port);
struct nat_list *nat_search_src(u_int32_t src_addr, u_int16_t src_port);
void nat_del(struct nat_list *tmp); 

/* utility.c */
void print_tcp(struct iphdr *ip, struct tcphdr *tcp);

/* ck.c */ 
unsigned short ip_checksum(unsigned char *iphdr);
unsigned short tcp_checksum(unsigned char *input); 
void show_checksum(unsigned char *data, int len); 

/* nat.c */ 
void out(int ret); 
