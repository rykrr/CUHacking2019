#include "dns_table.h"

sqlite3 *new_dns_cache() {
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    
    const char *create = "create table cache (domain text primary key, address int)";
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, create, strlen(create), &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return db;
}

