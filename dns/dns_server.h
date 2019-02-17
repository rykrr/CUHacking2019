#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "dns_packet.h"

int         dns_server_init(uint16_t);

dns_packet *dns_server_recv(int, struct sockaddr_in*, socklen_t*);
void        dns_server_send(int, dns_packet*, struct sockaddr_in*, socklen_t);
