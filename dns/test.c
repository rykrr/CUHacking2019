#include <stdio.h>
#include "dns_packet.h"
#include "dns_server.h"
#include "dns_client.h"

int main() {
    int sock = dns_server_init(5353);
    
    if(sock < 1)
        return 1;
    
    struct sockaddr_in sender;
    socklen_t sender_size;
    
    uint32_t address = dns_forward_lookup(0x08080808, "google.ca");
    
    printf("%08X\n", address);
    
    //dns_packet *packet = dns_server_recv(sock, &sender, &sender_size);
    
    //dns_lookup(db, dns_packet);
    //dns_persist(db, sender, dns_packet);
    
    //dns_server_send(sock, packet, &sender, sender_size);
    
    close(sock);
}
