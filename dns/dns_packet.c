#include "dns_packet.h"


dns_packet *new_dns_packet(dns_header header) {
    dns_packet *packet = malloc(sizeof(dns_packet));
    packet->header    = header;
    packet->questions = NULL;
    packet->answers   = NULL;
    
    if(header.qdcount) {
        packet->questions = (dns_question*) malloc(sizeof(dns_question) * header.qdcount);
        
        for(int i = 0; i < header.qdcount; i++)
            packet->questions[i] = (dns_question) { NULL, 0, 0 };
    }
    
    if(header.ancount) {
        packet->answers = (dns_answer*) malloc(sizeof(dns_answer) * header.ancount);
        
        for(int i = 0; i < header.ancount; i++)
            packet->answers[i] = (dns_answer) { NULL, 0, 0, 0, 0, NULL };
    }
    
    return packet;
}


void free_dns_packet(dns_packet *packet) {
    if(!packet)
        return;
    
    if(packet->questions) {
        for(int i = 0; i < packet->header.qdcount; i++)
            if(packet->questions[i].qname)
                free(packet->questions[i].qname);
        free(packet->questions);
    }
    
    if(packet->answers) {
        for(int i = 0; i < packet->header.ancount; i++) {
            if(packet->answers[i].name) {
                free(packet->answers[i].name);
                free(packet->answers[i].rdata);
            }
        }
        free(packet->answers);
    }
    
    free(packet);
}


void dns_set_answer_address(dns_answer *answer, uint32_t address) {
    if(!answer)
        return;
    
    answer->type     = 1;
    answer->class    = 1;
    answer->rdlength = 4;
    
    answer->rdata  = (uint8_t*) malloc(sizeof(uint32_t));
    *(uint32_t*) answer->rdata = htonl(address);
}


char *from_dns_name(uint8_t *bytes, uint16_t *length) {
    uint16_t _length = strlen((char*) bytes);
    if(length) *length = _length;
    
    char *name = (char*) malloc(sizeof(char) * _length);
    
    uint16_t dot = 0; // add dot
    for(uint16_t i = 0; i < _length; i++) {
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
    
    bytes[length] = 0;
    return bytes;
}


uint16_t packet_len(dns_packet *packet) {
    uint16_t length = 12;
    
    for(uint16_t i = 0; i < packet->header.qdcount; i++)
        length += strlen(packet->questions[i].qname) + 5;
    
    for(uint16_t i = 0; i < packet->header.ancount; i++)
        length += strlen(packet->answers[i].name) + 11 + packet->answers[i].rdlength;
    
    return length;
}


uint8_t *packet_to_bytes(dns_packet *packet, uint16_t *length) {
    uint16_t _packet_len = packet_len(packet);
    if(length) *length = _packet_len;
    printf("Expected Length: %d\n", _packet_len);
    
    uint8_t *bytes = (uint8_t*) malloc(sizeof(uint8_t) * _packet_len);
    *(uint16_t*)(bytes + 0)  = htons(packet->header.id);
    *(uint16_t*)(bytes + 2)  = htons(packet->header.code);
    *(uint16_t*)(bytes + 4)  = htons(packet->header.qdcount);
    *(uint16_t*)(bytes + 6)  = htons(packet->header.ancount);
    *(uint16_t*)(bytes + 8)  = htons(packet->header.nscount);
    *(uint16_t*)(bytes + 10) = htons(packet->header.arcount);
    
    uint16_t len = 12;
    
    for(uint16_t i = 0; i < packet->header.qdcount; i++) {
        int name_len = strlen(packet->questions[i].qname) + 1;
        for(int j = 0; j < name_len; j++)
            *(bytes + len++) = packet->questions[i].qname[j];
        
        *(uint16_t*)(bytes + len) = htons(packet->questions[i].qtype);
        len += 2;
        
        *(uint16_t*)(bytes + len) = htons(packet->questions[i].qclass);
        len += 2;
    }
    
    for(uint16_t i = 0; i < packet->header.ancount; i++) {
        int name_len = strlen(packet->answers[i].name) + 1;
        for(int j = 0; j < name_len; j++)
            *(bytes + len++) = packet->answers[i].name[j];
        
        *(uint16_t*)(bytes + len) = htons(packet->answers[i].type);
        len += 2;
        
        *(uint16_t*)(bytes + len) = htons(packet->answers[i].class);
        len += 2;
        
        *(uint32_t*)(bytes + len) = htonl(packet->answers[i].ttl);
        len += 4;
        
        *(uint16_t*)(bytes + len) = htons(packet->answers[i].rdlength);
        len += 2;
        
        for(int j = 0; j < packet->answers[i].rdlength; j++)
            *(bytes + len++) = packet->answers[i].rdata[j];
    }
    
    printf("Actual Length: %d\n", len);
    return bytes;
}


dns_packet *bytes_to_packet(uint8_t *bytes) {
    dns_header header = {
        ntohs(*((uint16_t*) bytes + 0)),
        ntohs(*((uint16_t*) bytes + 1)),
        ntohs(*((uint16_t*) bytes + 2)),
        ntohs(*((uint16_t*) bytes + 3)),
        ntohs(*((uint16_t*) bytes + 4)),
        ntohs(*((uint16_t*) bytes + 5))
    };
    
    uint16_t len = 12;
    dns_packet *packet = new_dns_packet(header);
    
    for(uint16_t i = 0; i < packet->header.qdcount; i++) {
        uint16_t name_len = strlen(bytes+len)+1;
        packet->questions[i].qname = malloc(sizeof(uint8_t) * name_len);
        
        for(int j = 0; j < name_len; j++)
            packet->questions[i].qname[j] = *(bytes+len++);
        
        packet->questions[i].qtype = ntohs(*(uint16_t*)(bytes + len));
        len += 2;
        
        packet->questions[i].qclass = ntohs(*(uint16_t*)(bytes + len));
        len += 2;
    }
    
    for(uint16_t i = 0; i < packet->header.ancount; i++) {
        uint16_t name_len = 0;
        if(!(*(bytes+len) & 0xC0))
            name_len = strlen(bytes+len)+1;
        
        packet->answers[i].name = malloc(sizeof(uint8_t) * name_len);
        
        if(name_len)
            for(uint8_t *ptr = packet->answers[i].name; *ptr; ptr++)
                *ptr = *(bytes+len++);
        else
            len += 2;
        
        printf("Name: %s\n", packet->answers[i].name);
        
        packet->answers[i].type = ntohs(*(uint16_t*)(bytes + len));
        len += 2;
        printf("Type: %d\n", packet->answers[i].type);
        
        packet->answers[i].class = ntohs(*(uint16_t*)(bytes + len));
        len += 2;
        printf("Class: %d\n", packet->answers[i].class);
        
        packet->answers[i].ttl = ntohl(*(uint32_t*)(bytes + len));
        len += 4;
        printf("TTL: %d\n", packet->answers[i].ttl);
        
        packet->answers[i].rdlength = ntohs(*(uint16_t*)(bytes + len));
        len += 2;
        
        switch(packet->answers[i].type) {
            case 1:
                packet->answers[i].rdata  = malloc(sizeof(uint32_t));
                *((uint32_t*) packet->answers[i].rdata) = ntohl(*(uint32_t*)(bytes + len));
                len += packet->answers[i].rdata;
                break;
                
            default:
                packet->answers[i].rdata = NULL;
                break;
        }
    }
    
    return packet;
}
