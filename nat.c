#include "nat.h"

struct ipq_handle *ipq_handle = NULL; 
unsigned int pkt_count = 0; 

void out(int ret) {
    if (ipq_handle)
        ipq_destroy_handle(ipq_handle);

    system("/sbin/iptables -F");
    printe("iptables flush\n"); 

    printf("Number of packet processed = %d\n", pkt_count); 

    printf("Bye =]\n"); 

    exit(0); 
}

void sig_handler(int sig) {
    printe("Receive SIGINT\n");
    out(1); 
}

void nat_main(unsigned char *ip_pkt) {
    struct iphdr *ip = (struct iphdr *) ip_pkt; 

    if (ip -> protocol != IPPROTO_TCP)
        return; 

    pkt_count++; 

    printe("Start process ... \n"); 
    print_tcp(ip, (struct tcphdr *) (((unsigned char *) ip) + ip -> ihl * 4));

    printe("Finish NAT =]\n"); 
}


int main(int argc, char **argv) {
   
    if (geteuid() != 0) {
        printf("\n");
        printf("iptables command require root privilege\n"); 
        printf("Please run with root privilege. You may try\n");
        printf("\tsudo %s\n\n", argv[0]);
        return 1;
    }
    
    ipq_handle = ipq_create_handle(0, PF_INET);
    if (!ipq_handle) {
        int err = errno; 
        printe("ipq_create_handle() (%d): %s\n", err, strerror(err));
        out(err); 
    }

    if (ipq_set_mode(ipq_handle, IPQ_COPY_PACKET, BUF_SIZE) < 0) {
        int err = errno; 
        printe("ipq_set_mode() (%d): %s\n", err, strerror(err));
        out(err); 
    }

    signal(SIGINT, sig_handler); 
    
    printf("Start NAT ...\n"); 

    do {
        unsigned char buf[BUF_SIZE]; 
        ipq_packet_msg_t *msg;

        printe("Waiting for packet ...\n");
        if (ipq_read(ipq_handle, buf, BUF_SIZE, 0) < 0) {
            int err = errno; 
            printe("ipq_set_mode() (%d): %s\n", err, strerror(err));
            out(err); 
        }

        if (ipq_message_type(buf) == NLMSG_ERROR) {
            printe("Error packet (%d): %s\n", 
                ipq_get_msgerr(buf), strerror(ipq_get_msgerr(buf))); 
            out(1); 
        }

        msg = ipq_get_packet(buf); 

        nat_main(msg -> payload); 

        if (ipq_set_verdict(ipq_handle, msg -> packet_id, NF_ACCEPT, 0, NULL) < 0) {
            int err = errno; 
            printe("ipq_set_verdict() (%d): %s\n", err, strerror(err));
            out(err); 
        }

    } while (1); 

    out(0); 
}
