#include "dns_client.h"

uint32_t dns_forward_lookup(uint32_t address, const char *domain) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = {htonl(INADDR_ANY)},
        .sin_port   = htons(5357)
    };
    
    struct sockaddr_in upstream = {
        .sin_family = AF_INET,
        .sin_addr   = {htonl(0x08080808)},
        .sin_port   = htons(53)
    };
    
    socklen_t socklen = sizeof(upstream);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    int enable = 1;
    struct timeval timeout = {
        .tv_sec  = 2,
        .tv_usec = 0
    };
    
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)))
        return 0;
    perror(strerror(errno));
    
    dns_header header  = { 5353, 0x0100, 1, 0, 0, 0 };
    dns_packet *packet = new_dns_packet(header);
    
    packet->questions->qname  = to_dns_name(domain);
    packet->questions->qtype  = 1;
    packet->questions->qclass = 1;
    
    uint16_t length = 0;
    uint8_t *bytes = packet_to_bytes(packet, &length);
    
    sendto(sock, (const void*) bytes, length, 0, (struct sockaddr*) &upstream, socklen);
    perror(strerror(errno));
    
    free_dns_packet(packet);
    free(bytes);
    
    char buf[513];
    ssize_t read = recvfrom(sock, buf, 512, 0, (struct sockaddr*) &upstream, &socklen);
    close(sock);
    
    if(!read)
        return 0;
    
    packet = bytes_to_packet(buf);
    
    address = 0;
    if(packet->header.ancount && packet->answers->type == 1)
        address = *((uint32_t*) packet->answers->rdata);
    
    printf("Records %4X\n", packet->header.ancount);
    for(int i = 0 ; i < packet->header.ancount ; i++) {
        for(int j = 0 ; j < 4 ; j ++)
            printf("%d ", packet->answers[i].rdata[j]);
        puts("");
    }
    
    free_dns_packet(packet);
    return address;
}
