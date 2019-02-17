#include "dns_lookup.h"


int dns_check(sqlite3 *db, uint32_t address, const char *domain) {
    const char *whitelist_query = "select * from 'config.Whitelist' where Device = (select DeviceID from 'config.Devices' where IPAddress = ?) and DomainName = ?";
    const size_t whitelist_query_len = strlen(whitelist_query);
    
    int allow = 0;
    int wlset = 0;
    
    sqlite3_stmt *stmt;
    
    int r = sqlite3_prepare_v2(db, whitelist_query, whitelist_query_len, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, address); 
    sqlite3_bind_text(stmt, 2, domain, strlen(domain), SQLITE_STATIC); 
    
    while((r = sqlite3_step(stmt)) == SQLITE_ROW) {
        wlset = 1;
        
        if(!strcmp(domain, sqlite3_column_text(stmt, 0))) {
            allow = 1;
            goto finalize;
        }
    }
    
    if(wlset)
        goto finalize;
    
    sqlite3_finalize(stmt);
    
    const char *blacklist_query = "select exists(select * from 'config.Blacklist' where DomainName = ?)";
    const size_t blacklist_query_len = strlen(blacklist_query);
    sqlite3_prepare_v2(db, blacklist_query, blacklist_query_len, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, domain, strlen(domain), SQLITE_STATIC);
    
    allow = !sqlite3_column_int(stmt, 0);
    
finalize:
    sqlite3_finalize(stmt);
    return allow;
}


uint32_t dns_lookup(sqlite3 *db, const char *domain) {
    const char *lookup_query = "select address from cache where domain = ?";
    const size_t lookup_query_len = strlen(lookup_query);
    
    const char *lookup_ins = "insert into cache (?, ?)";
    const size_t lookup_ins_len = strlen(lookup_ins);
    
    uint32_t address = 0;
    sqlite3_stmt *stmt;
    
    int ok = sqlite3_prepare_v2(db, lookup_query, lookup_query_len, &stmt, NULL);
    ok = sqlite3_step(stmt);
    
    if(ok == SQLITE_DONE) {
        printf("Forwarding Request\n");
        sqlite3_finalize(stmt);
        address = dns_forward_lookup(0x08080808, domain);
        
        sqlite3_prepare_v2(db, lookup_ins, lookup_ins_len, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, address);
        sqlite3_bind_text(stmt, 2, domain, strlen(domain), SQLITE_STATIC);
        sqlite3_step(stmt);
        printf("Request Cached\n");
        goto finalize;
    }
    
    if(ok != SQLITE_OK)
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
    const char *persist_query = "insert into Queuries (Client, Domain, Fullfilled) values (?, ?, ?)"; // s.i.c.
    const size_t persist_query_len = strlen(persist_query);
    
    sqlite3_stmt *stmt;
    
    int ok = sqlite3_prepare_v2(db, persist_query, persist_query_len, &stmt, NULL);
    
    if(ok == SQLITE_OK) {
        sqlite3_bind_int(stmt,  1, address);
        sqlite3_bind_text(stmt, 2, domain, strlen(domain), SQLITE_STATIC);
        sqlite3_bind_int(stmt,  3, result);
        sqlite3_step(stmt);
    }
    
finalize:
    sqlite3_finalize(stmt);
}
