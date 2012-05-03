#include "nat.h"

struct ipq_handle *ipq_handle = NULL; 
unsigned int pkt_count = 0; 

u_int32_t public, internal; 
u_int32_t netmask; 

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
    print_tcp(ip, tcp);

    if ((src_addr & netmask) == (internal & netmask)) {
        /* Out-bound packet */ 
        if (tcp -> syn) {
            /* Create entry */ 
            int port; 
            int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
            struct sockaddr_in addr; 

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

            tmp = nat_add(sockfd, port, src_addr, src_port); 
        } else {
            tmp = nat_search_src(src_addr, src_port); 
        }
        
        if (!tmp)
            return; 

        if (tcp -> fin) 
            tmp -> state = (tmp -> state == 2) ? 3 : 1; 

        src_addr = public; 
        src_addr = tmp -> nat_port; 
    }

    if (dest_addr == public) {
        /* In-bound packet */ 
        tmp = nat_search_port(dest_port); 
        
        if (!tmp) 
            return; 

        dest_addr = tmp -> src_addr; 
        dest_port = tmp -> src_port; 

        if (tcp -> fin)
            tmp -> state = (tmp -> state == 1) ? 3 : 2; 
    }

    if (tcp -> rst)
        tmp -> state = 4;

    if (tmp -> state == 4)
        if (!tcp -> fin)
            nat_del(tmp); 

    /* IP header checksum */ 
    ip -> check = 0x00;
    ip -> check = ip_checksum((unsigned char *) ip);

    /* TCP checksum */ 
    tcp -> check = 0x00; 
    tcp -> check = tcp_checksum((unsigned char *) tcp);

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

    netmask = 0xFFFFFFFF << (32 - atoi(argv[3]));

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

    return 0;
}
