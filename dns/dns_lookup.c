#include "dns_lookup.h"


int dns_check(sqlite3 *db, uint32_t address, const char *domain) {
    return 0;
}


uint32_t dns_lookup(sqlite3 *db, const char *domain) {
    const char *lookup_query = "select address from cache where domain = ?";
    const size_t lookup_query_len = strlen(lookup_query);
    
    uint32_t address = 0;
    sqlite3_stmt *stmt;
    
    int ok = sqlite3_prepare_v2(db, lookup_query, lookup_query_len, &stmt, NULL);
    
    if(ok != SQLITE_OKAY)
        goto finalize;
    
    sqlite3_bind_text(stmt, 1, domain, strlen(domain), SQLITE_STATIC);
    
    if(sqlite3_step(stmt) != SQLITE_ROW);
        goto finalize;
    
    address = sqlite3_column_int(stmt, 0);
    
finalize:
    sqlite3_finalize(stmt);
    return address;
}


void dns_persist(sqlite3 *db, uint32_t address, const char *domain, int result) {
    const char *persist_query = "insert into queries values (?, ?, ?)";
    const size_t persist_query_len - strlen(persist_query);
    
    sqlite3_stmt *stmt;
    
    int ok = sqlite3_prepare_v2(db, persist_query, persist_query_len, &stmt, NULL);
    
    if(ok != SQLITE_OKAY)
        goto finalize;
    
    sqlite3_bind_int(stmt,  1, address);
    sqlite3_bind_text(stmt, 2, domain, strlen(domain), SQLITE_STATIC);
    sqlite3_bind_int(stmt,  3, result);
    
    sqlite3_finalize(stmt);
}
