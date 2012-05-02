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

#define BUF_SIZE 1024

#ifndef BUILD
#include <errno.h>
#define printe(fmt, arg ...) \
    fprintf(stderr, "[1;32m[%ld][0m [1;42m[%s: %10s(): %3d][0m " fmt, \
            time(NULL), __FILE__, __FUNCTION__, __LINE__, ##arg)
#else
#define printe(fmt, ...) (0)
#endif

/* utility.c */
void print_tcp(struct iphdr *ip, struct tcphdr *tcp);

/* ck.c */ 
unsigned short tcp_checksum(unsigned char *input); 
void show_checksum(unsigned char *data, int len); 

/* nat.c */ 
void out(int ret); 
