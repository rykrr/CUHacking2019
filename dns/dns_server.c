#include "dns_server.h"
#include "dns_packet.h"

int dns_server_init(uint16_t port) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = {htonl(INADDR_ANY)},
        .sin_port   = htons(port)
    };
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    //setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int));
    
    if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)))
        return 0;
    
    return sock;
}


dns_packet *dns_recv(int sock, struct sockaddr_in *sender, socklen_t *sender_size) {
    if(!sock)
        return;
    
    sender_size = sizeof(sender);
    
    char buf[513];
    ssize_t read = recvfrom(sock, buf, 512, 0, (struct sockaddr*) &sender, &sender_size);
    
    if(read < 0)
        return NULL;
    
    buf[read] = 0;
    
    return bytes_to_packet(buf);
}


void dns_send(int sock, dns_packet *packet, struct sockaddr_in *sender, socklen_t sender_size) {
    uint16_t length = 0;
    uint8_t *bytes  = packet_to_bytes(packet, &length);
    
    sendto(sock, bytes, length, 0, (struct sockaddr*) sender, sender_size);
    
    free_dns_packet(packet);
    free(bytes);
}
