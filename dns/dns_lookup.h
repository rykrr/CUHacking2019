#pragma once
#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include "dns_packet.h"

int      dns_check(sqlite3*, uint32_t, const char*);
uint32_t dns_lookup(sqlite3*, const char*);
void     dns_persist(sqlite3*, uint32_t, const char*, int);
