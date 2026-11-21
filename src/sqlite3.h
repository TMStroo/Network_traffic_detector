#ifndef NTA_SQLITE3_H
#define NTA_SQLITE3_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef long long sqlite3_int64;
typedef unsigned long long sqlite3_uint64;
typedef void (*sqlite3_destructor_type)(void*);

#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_DONE 101
#define SQLITE_TRANSIENT ((sqlite3_destructor_type)-1)

#define SQLITE_INTEGER 1
#define SQLITE_FLOAT 2
#define SQLITE_TEXT 3
#define SQLITE_BLOB 4
#define SQLITE_NULL 5

int sqlite3_open(const char* filename, sqlite3** ppDb);
int sqlite3_close(sqlite3* db);
int sqlite3_exec(sqlite3* db, const char* sql,
                 int (*callback)(void*, int, char**, char**),
                 void* arg, char** errmsg);
int sqlite3_prepare_v2(sqlite3* db, const char* zSql, int nByte,
                       sqlite3_stmt** ppStmt, const char** pzTail);
int sqlite3_step(sqlite3_stmt* stmt);
int sqlite3_finalize(sqlite3_stmt* stmt);
int sqlite3_bind_text(sqlite3_stmt* stmt, int idx, const char* value,
                      int n, sqlite3_destructor_type dtor);
int sqlite3_bind_int64(sqlite3_stmt* stmt, int idx, sqlite3_int64 value);
int sqlite3_bind_double(sqlite3_stmt* stmt, int idx, double value);
int sqlite3_bind_null(sqlite3_stmt* stmt, int idx);
const unsigned char* sqlite3_column_text(sqlite3_stmt* stmt, int col);
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt* stmt, int col);
double sqlite3_column_double(sqlite3_stmt* stmt, int col);
int sqlite3_column_type(sqlite3_stmt* stmt, int col);
const char* sqlite3_errmsg(sqlite3* db);
int sqlite3_changes(sqlite3* db);
sqlite3_int64 sqlite3_last_insert_rowid(sqlite3* db);
const char* sqlite3_libversion(void);

#ifdef __cplusplus
}
#endif

#endif
