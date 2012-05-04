#include "nat.h"

struct ipq_handle *ipq_handle = NULL; 
unsigned int pkt_count = 0; 

u_int32_t public, internal; 
u_int32_t netmask; 

void out(int ret) {
    if (ipq_handle)
        ipq_destroy_handle(ipq_handle);

    system("/sbin/iptables -F -t filter");
    system("/sbin/iptables -F -t nat");
    system("/sbin/iptables -F -t mangle");
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
    struct tcphdr *tcp; 
    struct nat_list *tmp = NULL; 

    u_int32_t dest_addr, src_addr; 
    u_int16_t dest_port, src_port;

    if (ip -> protocol != IPPROTO_TCP)
        return; 

    pkt_count++; 

    tcp = (struct tcphdr *) (((unsigned char *) ip) + ip -> ihl * 4); 

    dest_addr = ip -> daddr; 
    dest_port = tcp -> dest; 
    
    src_addr = ip -> saddr; 
    src_port = tcp -> source; 

    printe("Start process ... \n"); 

    printe("Netmask  = 0x%8x\n", netmask);
    printe("src_addr = 0x%8x [0x%8x]\n", src_addr, src_addr & netmask);
    printe("internal = 0x%8x [0x%8x]\n", internal, internal & netmask);  

    if ((src_addr & netmask) == (internal & netmask)) {
        /* Out-bound packet */ 
        printe("Out-bound packet. \n"); 
        
        tmp = nat_search_src(src_addr, src_port); 

        if (!tmp) {
            if (tcp -> syn) {
                /* Create entry */ 
                unsigned short port; 
                int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
                struct sockaddr_in addr; 

                printe("New record! \n"); 

                addr.sin_family = AF_INET; 
                addr.sin_addr.s_addr = INADDR_ANY; 

                for (port = 55000; port <= 56000; ++port) {
                    addr.sin_port = port; 
                    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == 0)
                        break; 
                }

                if (port > 56000) {
                    printf("No more port avaliable for new connection ... \n"); 
                    return;
                }

                printe("NAT Port = %d\n", port);

                tmp = nat_add(sockfd, htons(port), src_addr, src_port); 
            } else {
                return; 
            }
        }

        if (tcp -> fin)
            tmp -> state = (tmp -> state == 2) ? 3 : 1; 

        if (tmp -> state >= 3)
            if (tcp -> ack)
                tmp -> state = (tmp -> state == 5) ? 6 : 4; 

        printe("Change source address \n"); 

        src_addr = public; 
        src_port = tmp -> nat_port;
    }

    if (dest_addr == public) {
        /* In-bound packet */ 

        printe("Inbound packet. \n"); 
        tmp = nat_search_port(dest_port); 
        
        if (!tmp) 
            return; 

        printe("Changing destination address. \n"); 
        dest_addr = tmp -> src_addr; 
        dest_port = tmp -> src_port; 

        if (tcp -> fin)
            tmp -> state = (tmp -> state == 1) ? 3 : 2; 

        if (tmp -> state >= 3)
            if (tcp -> ack)
                tmp -> state = (tmp -> state == 4) ? 6 : 5; 
    }

    if (!tmp)
        return;

    if (tcp -> rst) {
        printe("Reset! \n"); 
        tmp -> state = 6;
    }

    if (tmp -> state == 6) {
        printe("Delete entry\n");
        nat_del(tmp); 
    }

    /* Update the headers */ 
    printe("Real update .. \n");
    ip -> saddr = src_addr; 
    ip -> daddr = dest_addr;
    
    tcp -> source = src_port; 
    tcp -> dest = dest_port; 

    /* IP header checksum */ 
    ip -> check = 0x00;
    ip -> check = ip_checksum((unsigned char *) ip_pkt);

    /* TCP checksum */ 
    tcp -> check = 0x00; 
    tcp -> check = tcp_checksum((unsigned char *) ip_pkt);

    printe("Finish NAT =]\n"); 
}

int main(int argc, char **argv) {
    struct in_addr tmp_addr; 

    /* Check for root access */   
    if (geteuid() != 0) {
        printf("\n");
        printf("iptables command require root privilege\n"); 
        printf("Please run with root privilege. You may try\n");
        printf("\tsudo %s\n\n", argv[0]);
        return 1;
    }
    
    /* Check argument */ 
    if (argc != 4) {
        printf("Usage: %s [Public IP] [Internal IP] [Netmask]\n", argv[0]); 
        return 1; 
    }

    inet_aton(argv[1], &tmp_addr); 
    public = tmp_addr.s_addr; 

    inet_aton(argv[2], &tmp_addr); 
    internal = tmp_addr.s_addr; 

    netmask = htonl(0xFFFFFFFF << (32 - atoi(argv[3])));

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

        printe("Packet received. \n"); 

        if (ipq_message_type(buf) == NLMSG_ERROR) {
            printe("Error packet (%d): %s\n", 
                ipq_get_msgerr(buf), strerror(ipq_get_msgerr(buf))); 
            out(1); 
        }

        msg = ipq_get_packet(buf); 

        nat_main(msg -> payload); 

#ifndef BUILD
        print_tcp((struct iphdr *) msg -> payload, (struct tcphdr *) (((unsigned char *) msg -> payload) + ((struct iphdr *) (msg -> payload)) -> ihl * 4));
        show_checksum(msg -> payload, msg -> data_len); 
#endif

        if (ipq_set_verdict(ipq_handle, msg -> packet_id, NF_ACCEPT, msg -> data_len, msg -> payload) < 0) {
            int err = errno; 
            printe("ipq_set_verdict() (%d): %s\n", err, strerror(err));
            out(err); 
        }

    } while (1); 

    out(0); 

    return 0;
}
