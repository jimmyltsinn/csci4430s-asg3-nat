/****

  The purpose of this program is to randomly drop any packets

  For your reference, the structure ipq_packet_msg is given as follows:

---------------------------------------------------------------------------

struct ipq_packet_msg {
        unsigned long packet_id;        // ID of queued packet
        unsigned long mark;             // Netfilter mark value
        long timestamp_sec;             // Packet arrival time (seconds)
        long timestamp_usec;            // Packet arrvial time (+useconds)
        unsigned int hook;              // Netfilter hook we rode in on
        char indev_name[IFNAMSIZ];      // Name of incoming interface
        char outdev_name[IFNAMSIZ];     // Name of outgoing interface
        __be16 hw_protocol;             // Hardware protocol (network order)
        unsigned short hw_type;         // Hardware type
        unsigned char hw_addrlen;       // Hardware address length
        unsigned char hw_addr[8];       // Hardware address
        size_t data_len;                // Length of packet data
        unsigned char payload[0];       // Optional packet data
} ipq_packet_msg_t;

---------------------------------------------------------------------------

 ****/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>		// required by "netfilter.h"
#include <linux/netfilter.h>	// required by NF_ACCEPT, NF_DROP, etc...
#include <libipq.h>		// required by ipq_* functions
#include <arpa/inet.h>		// required by ntoh[s|l]()
#include <signal.h>		// required by SIGINT
#include <string.h>		// required by strerror()

#include <netinet/ip.h>		// required by "struct iph"
#include <netinet/tcp.h>	// required by "struct tcph"
#include <netinet/udp.h>	// required by "struct udph"
#include <netinet/ip_icmp.h>	// required by "struct icmphdr"

#include <sys/types.h>		// required by "inet_ntop()"
#include <sys/socket.h>		// required by "inet_ntop()"
#include <arpa/inet.h>		// required by "inet_ntop()"

#include <time.h>		// required by "time()"

#define BUF_SIZE	2048


/************************************************************************\

                           Global Variables

\************************************************************************/

struct ipq_handle *ipq_handle = NULL;

unsigned int pkt_count = 0, drop_count = 0;

/************************************************************************\

                           Function Prototypes

\************************************************************************/

void byebye(char *msg);

void sig_handler(int sig);

int do_your_job(unsigned char *ip_pkt, double drop_prob);

/************************************************************************\

                           Function Definitions

\************************************************************************/

/****
	Function: byebye

	Argument #1: char *msg
		The message that will be displayed as a part of the 
		error message.

		if msg == NULL, then there will be no error message 
		printed.

	Description:
		1) destroy the IPQ handle;
		2) Flush the iptables to free all the queued packets;
		3) print the error message (if any).
 */

void byebye(char *msg)
{
	if(ipq_handle)
		ipq_destroy_handle(ipq_handle);

	system("/sbin/iptables -F");
	printf("\n  iptables flushed.\n");

	if(msg != NULL)		// I have something to say.
	{
		printf("Number of processed packets: %u\n", pkt_count);
		ipq_perror(msg);
		exit(1);
	}
	else			// I have nothing to say.
	{
		printf("  Number of processed packets: %u\n", pkt_count);
		printf("  Number of dropped packets:   %u\n", drop_count);
		puts("  Goodbye.");
		exit(0);
	}
}




/****
	Function: sig_handler

	Argument #1:
		the numerical representation of the incoming signal.

	Description:
		To termination the program through the "byebye" function.
 */

void sig_handler(int sig)
{
	if(sig == SIGINT)
		byebye(NULL);
}




/****
	Function: do_your_job

	Argument #1: unsigned char *ipq_pkt;
		The pointer that points to the start of the IPQ packet 
		structure;

	Description:
		In this example, we print all the details about the 
		queued packet.
 */

int do_your_job(unsigned char *ip_pkt, double drop_prob)
{
	struct iphdr *ip;

	pkt_count++;

	ip = (struct iphdr *) ip_pkt;

	if(rand() / ((double) RAND_MAX) < drop_prob)
	{
		drop_count++;
		return 1;
	}
	else
		return 0;

} // end do_your_job()




/************************************************************************\

                           Main Function

\************************************************************************/

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	ipq_packet_msg_t *msg;
	double drop_prob;		// the dropping probability
	char *temp_ptr;			// for strtod()

  /**** Check input parameter ****/

	if(argc != 2)
	{
		fprintf(stderr, "Usage: %s [dropping probability]\n",
			argv[0]);
		exit(1);
	}

    /* I don't use atof() because it can't detect errors */

	drop_prob = strtod(argv[1], &temp_ptr);
	if(*temp_ptr != '\0')
	{
		fprintf(stderr,
			"Error: \"%s\" is not a floating point number.\n",
			argv[1]);
		exit(1);
	}

	if(drop_prob < 0 || drop_prob > 1)	// valid range?
	{
		fprintf(stderr,
			"Error: drop prob. must be between 0 and 1.\n");
		exit(1);
	}

  /**** Create the ipq_handle ****/

	if( (ipq_handle = ipq_create_handle(0, PF_INET)) == NULL)
	{
		byebye("ipq_create_handle");	// exit(1) included.
	}

  /**** ipq_set_mode: I want the entire packet ****/

	if(ipq_set_mode(ipq_handle, IPQ_COPY_PACKET, BUF_SIZE) == -1)
	{
		byebye("ipq_set_mode");	// exit(1) included.
	}

	signal(SIGINT, sig_handler);	// Handle Ctrl + C

	srand(time(NULL));		// send RNG seed.

	printf("Program: %s is ready\n", argv[0]);

	do
	{
	  /**** Read the packet from the QUEUE ****/

		if(ipq_read(ipq_handle, buf, BUF_SIZE, 0) == -1)
			byebye("ipq_read");	// exit(1) included

	  /**** Check whether it is an error or not ****/

		if(ipq_message_type(buf) == NLMSG_ERROR)
		{
			fprintf(stderr,
				"Error - ipq_message_type(): %s (errno = %d).\n",
				strerror(ipq_get_msgerr(buf)),
				ipq_get_msgerr(buf));
			exit(1);
		}

	  /**** This is the way to read the packet content ****/

		msg = ipq_get_packet(buf);

		if(do_your_job(msg->payload, drop_prob))
		{
			if(ipq_set_verdict(	ipq_handle,
						msg->packet_id,
						NF_DROP,
						0,
						NULL) == -1)
			{
				byebye("ipq_set_verdict");
				// exit(1) included.
			}
		}
		else
		{
			if(ipq_set_verdict(	ipq_handle,
						msg->packet_id,
						NF_ACCEPT,
						0,
						NULL) == -1)
			{
				byebye("ipq_set_verdict");
				// exit(1) included.
			}
		}

	} while(1);

	return 0;

} // end main()
