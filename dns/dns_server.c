#include "dns_server.h"
#include "dns_packet.h"

int init() {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = htonl(INADDR_ANY),
        .sin_port   = htons(5353)
    };
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    //setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int));
    
    if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)))
        return -1;
    
    return sock;
}


void loop(int sock) {
    if(!sock)
        return;
    
    uint8_t buf[1025];
    struct sockaddr_in sender;
    socklen_t sender_size;
    ssize_t read = 0;
    
    read = recvfrom(sock, buf, 1024, 0, (struct sockaddr*) &sender, &sender_size);
    
    if(read) {
        buf[read] = 0;
        
        dns_packet *packet = bytes_to_packet(buf);
        dns_header header  = packet->header;
        
        printf("ID? %04X\n", header.id);
        printf("Flags? %04X\n", header.code);
        printf("Question? %d\n", header.qdcount);
        
        header.code |= 1;
        header.qdcount = 1;
        header.ancount = 1;
        
        printf("Name: %s\n", packet->questions->qname);
        char *domain = from_dns_name(packet->questions->qname, NULL);
        printf("Domain: %s\n", domain);
        
        free_dns_packet(packet);
        
        packet = new_dns_packet(header);
        dns_set_answer_address(packet->answers, 0x7F000001);
        
        packet->answers->name = to_dns_name(domain);
        packet->questions->qname = to_dns_name(domain);
        
        uint16_t length = 0;
        uint8_t *bytes  = packet_to_bytes(packet, &length);
        
        //for(int i = 0; i < length; i ++)
        //    printf("%02X\n", bytes[i]);
        
        puts("Send");
        ssize_t sent = sendto(sock, bytes, length, 0, (struct sockaddr*) &sender, &sender_size);
        printf("Sent? %d\n", sent);
        perror(strerror(errno));
        
        free_dns_packet(packet);
        free(domain);
    }
}
