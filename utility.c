#include "nat.h"

/****
	Function: print_tcp

	Argument #1: struct iphdr *ip
		The pointer that points to the start of the IP header.

	Argument #2: struct tcphdr *tcp
		The pointer that points to the start of the TCP header.

	Description:
		A **helper function** of the do_your_job() function.
		It is for printing the content of the TCP header.
 */

void print_tcp(struct iphdr *ip, struct tcphdr *tcp)
{
	struct in_addr sip, dip;
	char sip_str[INET_ADDRSTRLEN+1], dip_str[INET_ADDRSTRLEN+1];

	sip.s_addr = ip->saddr;
	dip.s_addr = ip->daddr;

	if(!inet_ntop(AF_INET, &sip, sip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in source IP\n");
		out(0);
	}

	if(!inet_ntop(AF_INET, &dip, dip_str, INET_ADDRSTRLEN))
	{
		printf("Impossible: error in destination IP\n");
		out(0);
	}

  /**** IP ADDRESSES and PORT NUMBER *****/

	printf("TCP;\tSource: %s (%d)\tDestination: %s (%d)\n", 
		sip_str, ntohs(tcp->source),
		dip_str, ntohs(tcp->dest) );

  /**** TCP Flags *****/

	printf("\tTCP flags: ");
	fflush(stdout);

	if(tcp->urg)
		putchar('U');
	else
		putchar('_');

	if(tcp->ack)
		putchar('A');
	else
		putchar('_');

	if(tcp->psh)
		putchar('P');
	else
		putchar('_');

	if(tcp->rst)
		putchar('R');
	else
		putchar('_');

	if(tcp->syn)
		putchar('S');
	else
		putchar('_');

	if(tcp->fin)
		putchar('F');
	else
		putchar('_');

  /**** SEQ and ACK Number *****/

	printf("\tSEQ: %lu\tACK: %lu\n",
		(unsigned long) ntohl(tcp->seq),
		(unsigned long) ntohl(tcp->ack_seq));
	fflush(stdout);

}  // end print_tcp()
