#include "list.h"
#include "nat.h"

static struct nat_list *nat_head(void) {
    static struct nat_list *head = NULL; 
    if (!head) {
        head = malloc(sizeof(struct nat_list));
        head -> sockfd = -1; 
        head -> nat_port = 0;
        head -> src_addr = 0; 
        head -> src_port = 0; 
        head -> state = -1; 
        INIT_LIST_HEAD(&head -> list); 
    } 
    return head; 
}

struct nat_list *nat_add(int sockfd, u_int16_t nat_port, u_int32_t src_addr, u_int32_t src_port) {
    struct nat_list *tmp; 

    tmp = malloc(sizeof(struct nat_list)); 
    tmp -> sockfd = sockfd; 
    tmp -> nat_port = nat_port; 
    tmp -> src_addr = src_addr;
    tmp -> src_port = src_port; 
    tmp -> state = 0; 
    list_add(&tmp -> list, &nat_head() -> list);
    
    return tmp; 
}

struct nat_list *nat_search_port(u_int16_t nat_port) {
    struct nat_list *tmp; 

    list_for_each_entry(tmp, &(nat_head() -> list), list) { 
        if (tmp -> nat_port == nat_port)
            return tmp; 
    }

    return NULL; 
}

struct nat_list *nat_search_src(u_int32_t src_addr, u_int16_t src_port) {
    struct nat_list *tmp; 

    list_for_each_entry(tmp, &nat_head() -> list, list) {
        if (tmp -> src_addr == src_addr)
            if (tmp -> src_port == src_port)
                return tmp; 
    }

    return NULL; 
}

void nat_del(struct nat_list *tmp) {
    close(tmp -> sockfd); 
    tmp -> sockfd = -1; 
    tmp -> nat_port = 0; 
    tmp -> src_addr = 0; 
    tmp -> src_port = 0; 
    list_del(&tmp -> list); 
    free(tmp); 
}


