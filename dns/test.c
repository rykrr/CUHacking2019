#include <stdio.h>
#include "dns_packet.h"
#include "dns_server.h"


int main() {
    int sock = init();
    
    if(sock < 1)
        return 1;
    
    loop(sock);
    close(sock);
}
