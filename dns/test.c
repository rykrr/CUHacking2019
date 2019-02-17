#include <stdio.h>
#include "dns_packet.h"


int main() {
    dns_header header = (dns_header) {
        .id      = 1,
        .code    = 1,
        .qdcount = 1,
        .ancount = 1,
    };
    
    dns_packet *packet = new_dns_packet(header);
    
    uint16_t length = 0;
    uint8_t *input = (uint8_t*) "\x03" "www" "\x06" "google" "\x03" "com" "\x00";
    char *google = from_dns_name(input, &length);
    uint8_t *output = to_dns_name(google);
    
    printf(input);
    puts("");
    printf(google);
    puts("");
    printf(output);
    puts("");
    
    free_dns_packet(packet);
}
