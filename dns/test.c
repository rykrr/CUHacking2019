#include <stdio.h>
#include "dns_packet.h"
#include "dns_server.h"
#include "dns_lookup.h"
#include "dns_table.h"

int main() {
    int sock = dns_server_init(5353);
    
    sqlite3 *cache = new_dns_cache();
    
    sqlite3 *db;
    sqlite3_open("dee-ns.db", &db);
    
    if(sock < 1) {
        puts("Failed to bind socket");
        return 1;
    }
    
    struct sockaddr_in sender;
    socklen_t sender_size;
    
    for(;;) {
        dns_packet *packet = dns_server_recv(sock, &sender, &sender_size);
        
        if(!packet->header.qdcount)
            continue;
        
        uint32_t sender_addr = sender.sin_addr.s_addr;
        
        uint16_t length = 0;
        char *domain = from_dns_name(packet->questions->qname, &length);
        
        printf("Domain %s\n", domain);
        
        /*
        int check = dns_check(db, sender_addr, domain);
        
        if(!check) {
            dns_persist(db, sender_addr, domain, 0);
            continue;
        }
        */
        
        uint32_t address = dns_lookup(cache, domain);
        //dns_persist(db, sender_addr, domain, !!address);
        
        printf("Address %08X\n", address);
        
        dns_header header = { packet->header.id, 0x8100, 1, 1, 0, 0 };
        
        free_dns_packet(packet);
        packet = new_dns_packet(header);
        
        packet->questions->qname  = to_dns_name(domain);
        packet->questions->qtype  = 1;
        packet->questions->qclass = 1;
        
        packet->answers->name = to_dns_name(domain);
        packet->answers->ttl  = 2048;
        dns_set_answer_address(packet->answers, address);
        
        printf("Sending Data\n");
        dns_server_send(sock, packet, &sender, sender_size);
    }
    
    close(sock);
}
