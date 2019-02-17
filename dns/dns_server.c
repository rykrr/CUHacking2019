#include "dns_server.h"
#include "dns_packet.h"

int init() {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = {htonl(INADDR_ANY)},
        .sin_port   = htons(5353)
    };
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    //setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int));
    
    if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)))
        return 0;
    
    return sock;
}


void loop(int sock) {
   if(!sock)
       return;
    
    char buf[256];
    struct sockaddr_in sender;
    socklen_t sender_size = sizeof(sender);
    ssize_t read = 0;
    
    read = recvfrom(sock, buf, 255, 0, (struct sockaddr*) &sender, &sender_size);
    
    printf("Read %d\n", read);
    printf("SS %d\n", sender_size);
    
    if(read) {
        buf[read] = 0;
        
        dns_packet *packet = bytes_to_packet(buf);
        dns_header input   = packet->header;
        dns_header header  = { packet->header.id, 0x8180, 1, 1, 0, 0 };
        
        printf("ID? %04X\n", header.id);
        printf("Flags? %04X\n", input.code);
        printf("Question? %d\n", input.qdcount);
        
        printf("Name: %s\n", packet->questions->qname);
        
        char *domain = from_dns_name(packet->questions->qname, NULL);
        
        printf("Domain: %s\n", domain);
        
        free_dns_packet(packet);
        
        packet = new_dns_packet(header);
        
        dns_set_answer_address(packet->answers, 0x12345678);
        
        packet->questions->qname  = to_dns_name(domain);
        packet->questions->qtype  = 1;
        packet->questions->qclass = 1;
        
        packet->answers->name     = to_dns_name(domain);
        packet->answers->ttl      = 3141;
        printf("RDL: %d\n", packet->answers->rdlength);
        
        uint16_t length = 0;
        uint8_t *bytes  = packet_to_bytes(packet, &length);
        
        for(int i = 0; i < length; i ++);
            //printf("%02X\n", bytes[i]);
        
        ssize_t sent = sendto(sock, bytes, length, 0, (struct sockaddr*) &sender, sender_size);
        
        free_dns_packet(packet);
        free(domain);
    }
}
