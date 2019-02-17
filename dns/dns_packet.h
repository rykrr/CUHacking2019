#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>


typedef struct {
    uint16_t id;
    uint16_t code;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount; // TODO
    uint16_t arcount; // TODO
} dns_header;


typedef struct {
    uint8_t *qname;
    uint16_t qtype;
    uint16_t qclass;
} dns_question;


typedef struct {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
} dns_answer;


// TODO: Add additional fields


typedef struct {
    dns_header    header;
    dns_question *questions;
    dns_answer   *answers;
} dns_packet;


dns_packet *new_dns_packet(dns_header);
void        free_dns_packet(dns_packet*);

void dns_set_answer_address(dns_answer*, uint32_t);

char    *from_dns_name(uint8_t*, uint16_t*);
uint8_t *to_dns_name(const char*);

uint16_t packet_len(dns_packet*);

uint8_t    *packet_to_bytes(dns_packet*, uint16_t*);
dns_packet *bytes_to_packet(uint8_t*);


#define dns_set_authorative(header, set) (header->code = (header->code & ~0x10) | set? 0x10 : 0)
#define dns_get_authorative(header)      (header->code & 0x10)
