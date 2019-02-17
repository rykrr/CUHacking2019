#include "dns_table.h"

sqlite3 *new_dns_cache() {
    sqlite3 *db;
    sqlite3_open_v2(":memory:", &db);
    
    // TODO: Error handling lol
    
    return db;
}

