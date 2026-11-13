/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded-memory inventory of original, signed official CVD/CLD transports.
 * This deliberately does not claim to replace complete native validation.
 */
#define _GNU_SOURCE
#include "prepare.h"
#include "profile_names.h"
#ifndef CI_PREPARE_TEST
#include <clamav.h>
#else
/* Unit fixtures exercise archive/ledger handling without trusted CVDs or a
 * libclamav build. No executable entry point can use this test-only mode. */
#ifdef CI_PREPARE_MAIN
#error "Unsigned unit fixtures cannot be built as a preparation executable"
#endif
struct cl_cvd { unsigned version, stime; };
#endif
#include <json-c/json.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <zlib.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CI_DEFAULT_LINE_LIMIT 32768u
#define CI_ARCHIVE_ENTRIES 65536u
#define CI_SCHEMA "1"

struct ci_preparation {
    sqlite3 *db;
    sqlite3_stmt *member, *record, *name, *protect;
    uint64_t records, members, protected_names, source_bytes;
    unsigned families;
    char *line;
    size_t line_limit;
    int sqlite_length_limit;
    char error[256];
};

struct ci_decision {
    const char *format;
    char *name;
    int eligible;
    const char *reason;
};

static int ci_error(struct ci_preparation *p, const char *message)
{
    if (!p->error[0]) snprintf(p->error, sizeof(p->error), "%s", message);
    return -1;
}

static int ci_sql(struct ci_preparation *p, const char *sql)
{
    if (sqlite3_exec(p->db, sql, NULL, NULL, NULL) != SQLITE_OK)
        return ci_error(p, "profile ledger operation failed");
    return 0;
}

static int ci_line_budget(struct ci_preparation *p, uint64_t limit)
{
    if (!limit || limit >= SIZE_MAX || limit > (uint64_t)INT_MAX / 2)
        return ci_error(p, "configured signature line budget exceeds native limits");
    /* Keep fixed SQL/schema records possible even for a deliberately tiny line
     * cap. Signature text itself is still bounded by exactly the requested cap. */
    uint64_t sqlite_limit = 2 * limit;
    if (sqlite_limit < 4096) sqlite_limit = 4096;
    p->line = malloc((size_t)limit + 1);
    if (!p->line) return ci_error(p, "configured signature line buffer does not fit the process budget");
    p->line_limit = (size_t)limit;
    p->sqlite_length_limit = (int)sqlite_limit;
    return 0;
}

static int ci_ascii_name(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; ++s)
        if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e) return 0;
    return 1;
}

static const char *ci_format(const char *member)
{
    const char *dot = strrchr(member, '.');
    return dot ? dot + 1 : "";
}

static int ci_known_format(const char *member)
{
    static const char *const formats[] = {
        "info", "cfg", "ign", "ign2", "ftm", "hdb", "hdu", "hsb", "hsu",
        "mdb", "mdu", "msb", "msu", "imp", "ndb", "ndu", "ldb", "ldu",
        "idb", "fp", "sfp", "pdb", "wdb", "crb", "cdb", "cbc", "db",
        "sdb", "zmd", "rmd", "pwdb", "cat", "yara", "yar", NULL};
    const char *format = ci_format(member);
    if (!strcmp(member, "COPYING")) return 1;
    for (size_t i = 0; formats[i]; ++i)
        if (!strcmp(format, formats[i])) return 1;
    return 0;
}

/* Conservative selection only. Native grammar validation is a separate gate.
 * All occurrences in one native callback namespace are grouped on disk. */
static int ci_classify(const char *format, char *line, struct ci_decision *d)
{
    char *fields[7] = {0};
    size_t count = 0;
    int has_dollar = strchr(line, '$') != NULL;
    memset(d, 0, sizeof(*d));
    d->format = !strcmp(format, "ndu") ? "ndb" : !strcmp(format, "ldu") ? "ldb" : format;
    d->reason = "generic-other-effect-or-uncertain-retained";
    if (!*line || line[0] == '#') return 0;
    if (strcmp(d->format, "ndb") && strcmp(d->format, "ldb")) return 0;
    char separator = !strcmp(d->format, "ndb") ? ':' : ';';
    fields[count++] = line;
    for (char *s = line; *s && count < 7; ++s) {
        if (*s == separator) {
            *s = 0;
            fields[count++] = s + 1;
            if (separator == ';' && count == 4) break;
        }
    }
    if (!ci_ascii_name(fields[0])) return -1;
    d->name = fields[0];
    if (separator == ':') {
        if (count < 4 || count > 6) return -1;
        d->eligible = !strcmp(fields[1], "1") && !has_dollar;
        if (d->eligible) d->reason = "plain-terminal-PE-pattern-candidate";
        return 1;
    }
    if (count != 4) return -1;
    static const char *const keys[] = {"Engine", "Target", "FileSize", "EntryPoint",
        "NumberOfSections", "Container", "Intermediates", "IconGroup1", "IconGroup2", NULL};
    unsigned seen = 0;
    size_t attributes_length = strlen(fields[1]);
    int terminal = !has_dollar && attributes_length && fields[1][0] != ',' &&
        fields[1][attributes_length - 1] != ',' && !strstr(fields[1], ",,");
    int target_one = 0;
    char *save = NULL;
    for (char *attr = strtok_r(fields[1], ",", &save); attr; attr = strtok_r(NULL, ",", &save)) {
        char *colon = strchr(attr, ':');
        if (!colon) { terminal = 0; continue; }
        *colon++ = 0;
        size_t key;
        for (key = 0; keys[key] && strcmp(keys[key], attr); ++key) {}
        if (!keys[key] || (seen & (1u << key))) { terminal = 0; continue; }
        seen |= 1u << key;
        if (!strcmp(attr, "Target")) target_one = !strcmp(colon, "1");
        if (!*colon || strchr(colon, ':')) terminal = 0;
    }
    /* Empty attributes and empty comma segments are not a native-validation
     * shortcut: they remain retained and require the external validation gate. */
    d->eligible = terminal && target_one;
    if (d->eligible) d->reason = "plain-terminal-PE-logical-candidate";
    return 1;
}

static int ci_statement(struct ci_preparation *p, sqlite3_stmt *s)
{
    int rc = sqlite3_step(s);
    sqlite3_reset(s);
    sqlite3_clear_bindings(s);
    return rc == SQLITE_DONE ? 0 : ci_error(p, "profile ledger insert failed");
}

static int ci_add_record(struct ci_preparation *p, const char *database,
                         const char *member, uint64_t number, char *line)
{
    const char *format = ci_format(member);
    if (!strcmp(format, "cbc")) {
        /* Native parseLSig accepts an empty/nonlogical second line for hooks.
         * Protect any name conservatively, and preserve every CBC itself. */
        if (number != 2) return 0;
        char *end = strchr(line, ';');
        if (end) *end = 0;
        if (*line) {
            if (!ci_ascii_name(line)) return ci_error(p, "unresolved bytecode logical dependency");
            sqlite3_bind_text(p->protect, 1, line, -1, SQLITE_TRANSIENT);
            if (ci_statement(p, p->protect)) return -1;
            ++p->protected_names;
        } else if (end) return ci_error(p, "empty bytecode logical dependency");
        return 0;
    }
    struct ci_decision d;
    int result = ci_classify(format, line, &d);
    if (result < 0) return ci_error(p, "unresolved NDB/LDB callback identity");
    if (!result) return 0;
    sqlite3_bind_text(p->record, 1, database, -1, SQLITE_STATIC);
    sqlite3_bind_text(p->record, 2, member, -1, SQLITE_STATIC);
    sqlite3_bind_int64(p->record, 3, (sqlite3_int64)number);
    sqlite3_bind_text(p->record, 4, d.format, -1, SQLITE_STATIC);
    sqlite3_bind_text(p->record, 5, d.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(p->record, 6, d.eligible);
    if (ci_statement(p, p->record)) return -1;
    sqlite3_bind_text(p->name, 1, d.format, -1, SQLITE_STATIC);
    sqlite3_bind_text(p->name, 2, d.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(p->name, 3, d.eligible);
    sqlite3_bind_text(p->name, 4, d.reason, -1, SQLITE_STATIC);
    if (ci_statement(p, p->name)) return -1;
    ++p->records;
    return 0;
}

static int ci_read_exact(gzFile archive, void *buffer, size_t size)
{
    unsigned char *out = buffer;
    while (size) {
        unsigned wanted = size > 65536 ? 65536 : (unsigned)size;
        int count = gzread(archive, out, wanted);
        if (count <= 0) return -1;
        out += count;
        size -= (size_t)count;
    }
    return 0;
}

/* CVD writers omit POSIX tar zero trailers. Native ClamAV accepts clean EOF
 * after the final member's complete padding, but never a partial header. */
static int ci_read_header(gzFile archive, unsigned char header[512])
{
    size_t used = 0;
    while (used < 512) {
        int count = gzread(archive, header + used, (unsigned)(512 - used));
        if (count < 0) return -1;
        if (!count) return used ? -1 : 1;
        used += (size_t)count;
    }
    return 0;
}

static int ci_zero(const unsigned char *data, size_t length)
{
    for (size_t i = 0; i < length; ++i) if (data[i]) return 0;
    return 1;
}

static int ci_octal(const unsigned char *field, size_t length, uint64_t *value)
{
    size_t i = 0;
    uint64_t result = 0;
    while (i < length && field[i] == ' ') ++i;
    int found = 0;
    for (; i < length && field[i] >= '0' && field[i] <= '7'; ++i) {
        if (result > (UINT64_MAX - 7) / 8) return -1;
        result = result * 8 + field[i] - '0';
        found = 1;
    }
    for (; i < length; ++i) if (field[i] != 0 && field[i] != ' ') return -1;
    if (!found) return -1;
    *value = result;
    return 0;
}

static int ci_member_data(struct ci_preparation *p, gzFile archive,
                           const char *database, const char *member, uint64_t length)
{
    unsigned char buffer[65536];
    char *line = p->line;
    size_t used = 0;
    uint64_t number = 0, remaining = length;
    const char *format = ci_format(member);
    int lines = !strcmp(format, "ndb") || !strcmp(format, "ndu") ||
                !strcmp(format, "ldb") || !strcmp(format, "ldu") || !strcmp(format, "cbc");
    while (remaining) {
        size_t wanted = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
        if (ci_read_exact(archive, buffer, wanted)) return ci_error(p, "truncated database member");
        remaining -= wanted;
        if (!lines) continue;
        for (size_t i = 0; i < wanted; ++i) {
            if (buffer[i] == '\n') {
                while (used && line[used - 1] == '\r') --used;
                line[used] = 0;
                if (ci_add_record(p, database, member, ++number, line)) return -1;
                used = 0;
            } else {
                if (!buffer[i]) return ci_error(p, "NUL in signature text");
                if (used == p->line_limit) return ci_error(p, "signature line exceeds configured inventory limit");
                line[used++] = (char)buffer[i];
            }
            /* CBC bodies are not selection input. Consume only two lines. */
            if (!strcmp(format, "cbc") && number >= 2) { lines = 0; break; }
        }
    }
    if (lines && used) {
        while (used && line[used - 1] == '\r') --used;
        line[used] = 0;
        if (ci_add_record(p, database, member, ++number, line)) return -1;
    }
    if (!strcmp(format, "cbc") && number < 2) return ci_error(p, "truncated bytecode header");
    size_t padding = (size_t)((512 - length % 512) % 512);
    if (padding && (ci_read_exact(archive, buffer, padding) || !ci_zero(buffer, padding)))
        return ci_error(p, "invalid tar member padding");
    return 0;
}

static int ci_archive(struct ci_preparation *p, int fd, const char *database)
{
    if (lseek(fd, 512, SEEK_SET) != 512) return ci_error(p, "cannot read signed database payload");
    int copy = dup(fd);
    if (copy < 0) return ci_error(p, "cannot open archive reader");
    gzFile archive = gzdopen(copy, "rb");
    if (!archive) { close(copy); return ci_error(p, "cannot initialize archive reader"); }
    unsigned char header[512];
    unsigned count = 0;
    int status = -1;
    for (;;) {
        int header_status = ci_read_header(archive, header);
        if (header_status < 0 || (header_status > 0 && !count)) { ci_error(p, "truncated tar header"); break; }
        if (header_status > 0) { status = 0; break; }
        if (ci_zero(header, sizeof(header))) {
            int got;
            while ((got = gzread(archive, header, sizeof(header))) > 0)
                if (!ci_zero(header, (size_t)got)) { ci_error(p, "unexpected data after tar end"); goto done; }
            if (got < 0) { ci_error(p, "invalid compressed database trailer"); break; }
            status = 0;
            break;
        }
        uint64_t length, checksum;
        if (ci_octal(header + 124, 12, &length) || ci_octal(header + 148, 8, &checksum) || length > INT64_MAX) {
            ci_error(p, "invalid tar numeric field"); break;
        }
        uint64_t computed = 0;
        for (size_t i = 0; i < sizeof(header); ++i) computed += i >= 148 && i < 156 ? ' ' : header[i];
        if (computed != checksum || (header[156] != 0 && header[156] != '0') ||
            !ci_zero(header + 345, 155) || ++count > CI_ARCHIVE_ENTRIES) {
            ci_error(p, "unsupported or malformed tar member"); break;
        }
        char member[101];
        memcpy(member, header, 100); member[100] = 0;
        if (!ci_ascii_name(member) || !strcmp(member, ".") || !strcmp(member, "..") ||
            strchr(member, '/') || strchr(member, '\\') || !ci_known_format(member)) {
            ci_error(p, "unknown or unsafe database member"); break;
        }
        sqlite3_bind_text(p->member, 1, database, -1, SQLITE_STATIC);
        sqlite3_bind_text(p->member, 2, member, -1, SQLITE_STATIC);
        sqlite3_bind_int64(p->member, 3, (sqlite3_int64)length);
        if (ci_statement(p, p->member)) break;
        ++p->members;
        const char *format = ci_format(member);
        if (!strcmp(format, "mdb")) p->families |= 1;
        if (!strcmp(format, "msb")) p->families |= 2;
        if (!strcmp(format, "imp")) p->families |= 4;
        if (ci_member_data(p, archive, database, member, length)) break;
    }
done:
    if (gzclose(archive) != Z_OK && !status) return ci_error(p, "invalid compressed archive termination");
    return status;
}

static int ci_digest(int fd, char output[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[65536], digest[32];
    unsigned length = 0;
    off_t at = 0;
    int status = -1;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        ssize_t count = pread(fd, buffer, sizeof(buffer), at);
        if (count < 0) { if (errno == EINTR) continue; goto done; }
        if (!count) break;
        if (EVP_DigestUpdate(ctx, buffer, (size_t)count) != 1) goto done;
        at += count;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != sizeof(digest)) goto done;
    for (unsigned i = 0; i < length; ++i) snprintf(output + 2 * i, 3, "%02x", digest[i]);
    status = 0;
done:
    EVP_MD_CTX_free(ctx);
    return status;
}

static int ci_source(struct ci_preparation *p, int dirfd, int verification_dirfd, const char *name,
                      const char *certs, json_object *sources)
{
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat before, after;
    char hash[65], after_hash[65], path[96], descriptor[64];
    int status = -1;
    int verification_link = 0;
#ifndef CI_PREPARE_TEST
    int signature_fd=-1,signature_link=0;char signature_name[64]={0},signature_hash[65]={0};
    struct stat signature_before,signature_after;
#endif
    struct cl_cvd *head = NULL;
    if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 512 || ci_digest(fd, hash)) {
        ci_error(p, "invalid official database input"); goto done;
    }
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
#ifndef CI_PREPARE_TEST
    /* cl_cvdverify_ex chooses CVD/CLD verification by pathname suffix. A private
     * temporary link retains that suffix while fixing the actual opened inode. */
    if (symlinkat(descriptor, verification_dirfd, name)) { ci_error(p, "cannot pin official verification input"); goto done; }
    verification_link = 1;
    head = cl_cvdhead(descriptor);
    if (!head) { ci_error(p, "invalid official database header"); goto done; }
    const char *dot=strchr(name,'.');
    if(!dot||snprintf(signature_name,sizeof(signature_name),"%.*s-%u.cvd.sign",(int)(dot-name),name,head->version)>=(int)sizeof(signature_name)) {
        ci_error(p,"invalid detached signature identity");goto done;
    }
    signature_fd=openat(dirfd,signature_name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(signature_fd>=0) {
        if(fstat(signature_fd,&signature_before)||!S_ISREG(signature_before.st_mode)||ci_digest(signature_fd,signature_hash)) {
            ci_error(p,"invalid detached signature input");goto done;
        }
        char signature_descriptor[64];snprintf(signature_descriptor,sizeof(signature_descriptor),"/proc/self/fd/%d",signature_fd);
        if(symlinkat(signature_descriptor,verification_dirfd,signature_name)) {ci_error(p,"cannot pin detached signature input");goto done;}
        signature_link=1;
    } else if(errno!=ENOENT) {ci_error(p,"cannot inspect detached signature input");goto done;}
    snprintf(path, sizeof(path), "/proc/self/fd/%d/%s", verification_dirfd, name);
    if (cl_cvdverify_ex(path, certs, 0) != CL_SUCCESS) { ci_error(p, "official database signature verification failed"); goto done; }
    if(signature_fd>=0) {
        char after_signature_hash[65];
        if(fstat(signature_fd,&signature_after)||ci_digest(signature_fd,after_signature_hash)||strcmp(signature_hash,after_signature_hash)
           ||signature_before.st_size!=signature_after.st_size||signature_before.st_mtim.tv_sec!=signature_after.st_mtim.tv_sec
           ||signature_before.st_mtim.tv_nsec!=signature_after.st_mtim.tv_nsec||signature_before.st_ctim.tv_sec!=signature_after.st_ctim.tv_sec
           ||signature_before.st_ctim.tv_nsec!=signature_after.st_ctim.tv_nsec) {ci_error(p,"detached signature changed during verification");goto done;}
    }
#else
    (void)certs;
    (void)path;
#endif
    if (ci_archive(p, fd, name)) goto done;
    if (fstat(fd, &after) || ci_digest(fd, after_hash) || strcmp(hash, after_hash) ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) { ci_error(p, "official database changed during preparation"); goto done; }
    json_object *source = json_object_new_object();
    json_object_object_add(source, "name", json_object_new_string(name));
    json_object_object_add(source, "sha256", json_object_new_string(hash));
    json_object_object_add(source, "size", json_object_new_int64(before.st_size));
    json_object_object_add(source, "signature_verified", json_object_new_boolean(head != NULL));
    if (head) {
        json_object_object_add(source, "version", json_object_new_int64(head->version));
        json_object_object_add(source, "created_at", json_object_new_int64(head->stime));
#ifndef CI_PREPARE_TEST
        if(signature_fd>=0) {
            json_object *detached=json_object_new_object();
            json_object_object_add(detached,"name",json_object_new_string(signature_name));
            json_object_object_add(detached,"sha256",json_object_new_string(signature_hash));
            json_object_object_add(detached,"size",json_object_new_int64(signature_before.st_size));
            json_object_object_add(source,"detached_signature",detached);
        }
#endif
    }
    json_object_array_add(sources, source);
    p->source_bytes += (uint64_t)before.st_size;
    status = 0;
done:
#ifndef CI_PREPARE_TEST
    if(signature_link&&unlinkat(verification_dirfd,signature_name,0)) {ci_error(p,"cannot remove private detached signature");status=-1;}
    if(signature_fd>=0)close(signature_fd);
    if (head) cl_cvdfree(head);
#endif
    if (verification_link && unlinkat(verification_dirfd, name, 0)) {
        ci_error(p, "cannot remove private verification input");
        status = -1;
    }
    if (fd >= 0) close(fd);
    return status;
}

static int ci_open_ledger(struct ci_preparation *p, const char *path)
{
    if (!p->line && ci_line_budget(p, CI_DEFAULT_LINE_LIMIT)) return -1;
    if (sqlite3_open_v2(path, &p->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
        return ci_error(p, "cannot create profile ledger");
    sqlite3_limit(p->db, SQLITE_LIMIT_LENGTH, p->sqlite_length_limit);
    if (sqlite3_limit(p->db, SQLITE_LIMIT_LENGTH, -1) < p->sqlite_length_limit)
        return ci_error(p, "configured line budget exceeds this SQLite build's record limit");
    if (ci_sql(p, "PRAGMA cache_size=-4096; PRAGMA temp_store=FILE; PRAGMA journal_mode=DELETE;"
                  "PRAGMA synchronous=FULL; BEGIN IMMEDIATE;"
                  "CREATE TABLE members(database_name TEXT NOT NULL,member TEXT NOT NULL,size INTEGER NOT NULL,"
                  "PRIMARY KEY(database_name,member)) WITHOUT ROWID;"
                  "CREATE TABLE records(database_name TEXT NOT NULL,member TEXT NOT NULL,line INTEGER NOT NULL,"
                  "format TEXT NOT NULL,name TEXT COLLATE BINARY NOT NULL,eligible INTEGER NOT NULL,"
                  "PRIMARY KEY(database_name,member,line)) WITHOUT ROWID;"
                  "CREATE TABLE names(format TEXT NOT NULL,name TEXT COLLATE BINARY NOT NULL,eligible INTEGER NOT NULL,"
                  "occurrences INTEGER NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(format,name)) WITHOUT ROWID;"
                  "CREATE TABLE protected_names(name TEXT COLLATE BINARY PRIMARY KEY) WITHOUT ROWID;")) return -1;
    const char *queries[] = {
        "INSERT INTO members VALUES(?1,?2,?3)",
        "INSERT INTO records VALUES(?1,?2,?3,?4,?5,?6)",
        "INSERT INTO names VALUES(?1,?2,?3,1,?4) ON CONFLICT(format,name) DO UPDATE SET "
        "eligible=min(eligible,excluded.eligible),occurrences=occurrences+1,"
        "reason=CASE WHEN excluded.eligible=0 THEN excluded.reason ELSE reason END",
        "INSERT OR IGNORE INTO protected_names VALUES(?1)"};
    sqlite3_stmt **statements[] = {&p->member, &p->record, &p->name, &p->protect};
    for (unsigned i = 0; i < 4; ++i)
        if (sqlite3_prepare_v2(p->db, queries[i], -1, statements[i], NULL) != SQLITE_OK)
            return ci_error(p, "cannot initialize profile ledger");
    return 0;
}

static void ci_close_ledger(struct ci_preparation *p)
{
    sqlite3_finalize(p->member); sqlite3_finalize(p->record);
    sqlite3_finalize(p->name); sqlite3_finalize(p->protect);
    p->member = p->record = p->name = p->protect = NULL;
    if (p->db) sqlite3_close(p->db);
    p->db = NULL;
    free(p->line);
    p->line = NULL;
}

static int ci_write_skips(struct ci_preparation *p, const char *path, uint64_t *excluded)
{
    if (ci_sql(p, "UPDATE names SET eligible=0,reason='bytecode-dependency-retained' "
                  "WHERE format='ldb' AND name IN(SELECT name FROM protected_names);"
                  "CREATE TABLE family_exclusions(format TEXT PRIMARY KEY) WITHOUT ROWID;")) return -1;
    const char *families[] = {"mdb", "msb", "imp"};
    for (unsigned i = 0; i < 3; ++i) {
        if (p->families & (1u << i)) {
            char sql[96];
            snprintf(sql, sizeof(sql), "INSERT INTO family_exclusions VALUES('%s')", families[i]);
            if (ci_sql(p, sql)) return -1;
        }
    }
    sqlite3_stmt *query = NULL;
    if (sqlite3_prepare_v2(p->db, "SELECT format,name FROM names WHERE eligible=1 "
        "UNION ALL SELECT format,'*' FROM family_exclusions ORDER BY 1 COLLATE BINARY,2 COLLATE BINARY",
        -1, &query, NULL) != SQLITE_OK) return ci_error(p, "cannot enumerate profile exclusions");
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *out = fd < 0 ? NULL : fdopen(fd, "w");
    if (!out) { if (fd >= 0) close(fd); sqlite3_finalize(query); return ci_error(p, "cannot create profile exclusions"); }
    int rc;
    *excluded = 0;
    while ((rc = sqlite3_step(query)) == SQLITE_ROW) {
        const char *format = (const char *)sqlite3_column_text(query, 0);
        const char *name = (const char *)sqlite3_column_text(query, 1);
        if (fprintf(out, "%s\t%s\n", format, name) < 0) break;
        ++*excluded;
    }
    sqlite3_finalize(query);
    int failed = rc != SQLITE_DONE || fflush(out) || fsync(fd) || fchmod(fd, 0400);
    if (fclose(out)) failed = 1;
    return failed ? ci_error(p, "cannot commit profile exclusions") : 0;
}

static int ci_write_json(struct ci_preparation *p, const char *path, json_object *report)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return ci_error(p, "cannot create preparation report");
    FILE *out = fdopen(fd, "w");
    if (!out) { close(fd); return ci_error(p, "cannot open preparation report"); }
    int failed = fprintf(out, "%s\n", json_object_to_json_string_ext(report, JSON_C_TO_STRING_PRETTY)) < 0;
    if (fflush(out) || fsync(fd) || fchmod(fd, 0400)) failed = 1;
    if (fclose(out)) failed = 1;
    return failed ? ci_error(p, "cannot commit preparation report") : 0;
}

int ci_prepare_generation_with_line_limit(const char *generation, const char *certs,
                                         uint64_t max_line_bytes)
{
    struct ci_preparation p = {0};
    int root = -1, databases = -1, staging = -1, result = 2;
    char temporary[PATH_MAX] = {0}, path[PATH_MAX], profile[PATH_MAX];
    char source_names[3][32] = {{0}};
    json_object *report = json_object_new_object(), *sources = json_object_new_array();
    json_object_object_add(report, "protocol", json_object_new_int(1));
    json_object_object_add(report, "kind", json_object_new_string("preparation"));
    json_object_object_add(report, "coverage_qualified", json_object_new_boolean(0));
    json_object_object_add(report, "profile_qualified", json_object_new_boolean(0));
    json_object_object_add(report, "native_syntax_validation", json_object_new_string("not-performed"));
    json_object_object_add(report, "sources", sources);
    json_object_object_add(report, "max_line_bytes", json_object_new_uint64(max_line_bytes));
    if (ci_line_budget(&p, max_line_bytes)) goto done;
#ifndef CI_PREPARE_TEST
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) { ci_error(&p, "cannot initialize native database verification"); goto done; }
#endif
    root = open(generation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { ci_error(&p, "cannot open generation directory"); goto done; }
    databases = openat(root, "databases", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (databases < 0) { ci_error(&p, "cannot open generation databases"); goto done; }
    DIR *entries = fdopendir(dup(databases));
    if (!entries) { ci_error(&p, "cannot inventory database directory"); goto done; }
    struct dirent *entry;
    int bad = 0;
    while ((entry = readdir(entries))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if(ci_official_signature_name(entry->d_name)) {
            struct stat signature;
            if(fstatat(databases,entry->d_name,&signature,AT_SYMLINK_NOFOLLOW)||!S_ISREG(signature.st_mode)) {bad=1;break;}
            continue;
        }
        int group = -1;
        static const char *const names[] = {"main", "daily", "bytecode"};
        for (int i = 0; i < 3; ++i) {
            char cvd[32], cld[32];
            snprintf(cvd, sizeof(cvd), "%s.cvd", names[i]);
            snprintf(cld, sizeof(cld), "%s.cld", names[i]);
            if (!strcmp(entry->d_name, cvd) || !strcmp(entry->d_name, cld)) group = i;
        }
        if (group < 0 || source_names[group][0]) { bad = 1; break; }
        memcpy(source_names[group], entry->d_name, strlen(entry->d_name) + 1);
    }
    closedir(entries);
    if (bad || !source_names[0][0] || !source_names[1][0] || !source_names[2][0]) {
        ci_error(&p, "require exactly one signed main, daily and bytecode CVD/CLD; custom inputs are not supported"); goto done;
    }
    if (snprintf(profile, sizeof(profile), "%s/profile", generation) >= (int)sizeof(profile) ||
        snprintf(temporary, sizeof(temporary), "%s/.profile-XXXXXX", generation) >= (int)sizeof(temporary)) {
        temporary[0] = 0; ci_error(&p, "generation path is too long"); goto done;
    }
    struct stat exists;
    if (!fstatat(root, "profile", &exists, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) {
        temporary[0] = 0; ci_error(&p, "profile already exists or cannot be inspected"); goto done;
    }
    if (!mkdtemp(temporary)) { temporary[0] = 0; ci_error(&p, "cannot create profile staging directory"); goto done; }
    staging = open(temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (staging < 0) { ci_error(&p, "cannot open profile staging directory"); goto done; }
    if (snprintf(path, sizeof(path), "%s/ledger.sqlite", temporary) >= (int)sizeof(path) || ci_open_ledger(&p, path)) goto done;
    /* Stable order agrees with directory source ordering and retains every
     * original transport; selection does not rewrite or unsigned-repackage it. */
    const unsigned order[] = {2, 1, 0};
    for (unsigned i = 0; i < 3; ++i)
        if (ci_source(&p, databases, staging, source_names[order[i]], certs, sources)) goto done;
    uint64_t excluded = 0;
    if (snprintf(path, sizeof(path), "%s/skip.tsv", temporary) >= (int)sizeof(path) || ci_write_skips(&p, path, &excluded)) goto done;
    if (ci_sql(&p, "COMMIT")) goto done;
    ci_close_ledger(&p);
    int ledger = openat(staging, "ledger.sqlite", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (ledger < 0 || fchmod(ledger, 0400) || fsync(ledger)) {
        if (ledger >= 0) close(ledger);
        ci_error(&p, "cannot commit profile ledger"); goto done;
    }
    close(ledger);
    json_object_object_add(report, "status", json_object_new_string("prepared"));
    json_object_object_add(report, "inventory_status", json_object_new_string("passed"));
    json_object_object_add(report, "schema_version", json_object_new_int(atoi(CI_SCHEMA)));
    json_object_object_add(report, "members", json_object_new_int64((int64_t)p.members));
    json_object_object_add(report, "classified_records", json_object_new_int64((int64_t)p.records));
    json_object_object_add(report, "excluded_callback_keys", json_object_new_int64((int64_t)excluded));
    json_object_object_add(report, "protected_bytecode_names", json_object_new_int64((int64_t)p.protected_names));
    json_object_object_add(report, "custom_signatures", json_object_new_string("unsupported; no external inputs accepted"));
    json_object *requirements = json_object_new_array();
    json_object_array_add(requirements, json_object_new_string("complete-native-validation"));
    json_object_array_add(requirements, json_object_new_string("guard-and-ordering-qualification"));
    json_object_object_add(report, "required_qualification_evidence", requirements);
    json_object_object_add(report, "qualification_authority", json_object_new_string("bound-generation-manifest-and-compiled-qualification"));
    if (snprintf(path, sizeof(path), "%s/validation.json", temporary) >= (int)sizeof(path) || ci_write_json(&p, path, report) || fsync(staging)) goto done;
    if (rename(temporary, profile) || fsync(root)) { ci_error(&p, "cannot publish prepared profile"); goto done; }
    temporary[0] = 0;
    result = 0;
done:
    ci_close_ledger(&p);
    if (staging >= 0) close(staging);
    if (temporary[0]) {
        static const char *const files[] = {"skip.tsv", "ledger.sqlite", "ledger.sqlite-journal", "validation.json", NULL};
        for (unsigned i = 0; files[i]; ++i) {
            if (snprintf(path, sizeof(path), "%s/%s", temporary, files[i]) < (int)sizeof(path)) unlink(path);
        }
        rmdir(temporary);
    }
    if (databases >= 0) close(databases);
    if (root >= 0) close(root);
    if (result) {
        json_object_object_add(report, "status", json_object_new_string("failed"));
        json_object_object_add(report, "reason", json_object_new_string(p.error[0] ? p.error : "preparation failed"));
    }
    puts(json_object_to_json_string_ext(report, JSON_C_TO_STRING_PLAIN));
    json_object_put(report);
    return result;
}

/* Compatibility for unit fixtures and older diagnostic callers. Production
 * orchestration supplies its calculated line budget through the explicit API. */
int ci_prepare_generation(const char *generation, const char *certs)
{
    return ci_prepare_generation_with_line_limit(generation, certs, CI_DEFAULT_LINE_LIMIT);
}

#ifdef CI_PREPARE_MAIN
int main(int argc, char **argv)
{
    const char *generation = NULL, *certs = NULL;
    uint64_t line_limit = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--generation") && i + 1 < argc && !generation) generation = argv[++i];
        else if (!strcmp(argv[i], "--certs") && i + 1 < argc && !certs) certs = argv[++i];
        else if (!strcmp(argv[i], "--line-bytes") && i + 1 < argc && !line_limit) {
            char *end = NULL;
            const char *value = argv[++i];
            errno = 0;
            unsigned long long parsed = strtoull(value, &end, 10);
            if (errno || !*value || *value == '-' || !end || *end || !parsed) return 2;
            line_limit = (uint64_t)parsed;
        } else { fprintf(stderr, "usage: ci-prepare --generation DIR --certs DIR --line-bytes N\n"); return 2; }
    }
    if (!generation || !certs || !line_limit) { fprintf(stderr, "usage: ci-prepare --generation DIR --certs DIR --line-bytes N\n"); return 2; }
    return ci_prepare_generation_with_line_limit(generation, certs, line_limit);
}
#endif
