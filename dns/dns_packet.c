#include "dns_packet.h"


dns_packet *new_dns_packet(dns_header header) {
    dns_packet *packet = malloc(sizeof(dns_packet));
    packet->header    = header;
    packet->questions = NULL;
    packet->answers   = NULL;
    
    if(header.qdcount)
        packet->questions = (dns_question*) malloc(sizeof(dns_question) * header.qdcount);
    
    if(header.ancount)
        packet->answers   = (dns_answer*) malloc(sizeof(dns_answer) * header.ancount);
}


void free_dns_packet(dns_packet *packet) {
    if(!packet)
        return;
    
    if(packet->questions)
        free(packet->questions);
    
    if(packet->answers)
        free(packet->answers);
    
    free(packet);
}


char *from_dns_name(uint8_t *bytes, uint16_t *length) {
    *length = strlen((char*) bytes);
    char *name = (char*) malloc(sizeof(char) * *length);
    
    uint16_t dot = 0; // add dot
    for(uint16_t i = 0; i < *length; i++) {
        if(i)
            name[i-1] = (i == dot)? '.' : bytes[i];
        
        if(!i || i == dot)
            dot += bytes[i]+1;
    }
    
    return name;
}


uint8_t *to_dns_name(const char *name) {
    uint16_t length = strlen(name) + 1;
    uint8_t *bytes = (uint8_t*) malloc(sizeof(uint8_t) * length);
    
    for(uint16_t i = 0; i < length; i++) {
        if(!i || name[i-1] == '.') {
            bytes[i] = 0;
            for(char *c = name+i; *c && *c != '.'; c++)
                bytes[i] ++;
        }
        else {
            bytes[i] = name[i-1];
        }
    }
    
    return bytes;
}


uint8_t *packet_to_bytes(dns_packet *packet) {
    return NULL;
}


dns_packet *bytes_to_packet(uint8_t *bytes) {
    return NULL;
}
