/* SPDX-License-Identifier: GPL-2.0-only
 * One-shot official FreshClam updates. No daemon, shell or implicit workload caps.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <clamav.h>
#include <libfreshclam.h>
#include <openssl/evp.h>
#include <json-c/json.h>
#include "qualification.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

struct options {
    const char *state, *scanner, *certs, *runtime_id, *options_id, *database, *lock_fd, *program_id, *expected_current;
    uint64_t as_bytes, cpu_seconds, wall_seconds, file_bytes, line_bytes;
    uint64_t connect_seconds, low_speed_seconds, attempts, age_seconds, reserve_bytes;
};
static struct options opt;
static char executable[PATH_MAX];
static const char *failure = "unspecified";
static volatile sig_atomic_t interrupted;
static int job_lock = -1;
static double job_deadline;
static uint64_t retry_after;
static double child_cpu_used;
static int last_child_status = -1;
static int bounded_validation;
static const char *last_stage = "preflight";
static char inherited_program[69];
static char last_log[PATH_MAX];
static int hash_text(const char *value);
static void stop(int sig) { (void)sig; interrupted = 1; }
static void expired(int sig) {
    (void)sig;
    static const char record[]="{\"protocol\":1,\"status\":\"failed\",\"reason\":\"job_wall_limit\",\"next_attempt_after\":null}\n";
    (void)write(STDOUT_FILENO,record,sizeof(record)-1);
    _exit(124);
}
static int error(const char *reason) { failure = reason; return -1; }
static int path(char *out, const char *root, const char *name) {
    return snprintf(out, PATH_MAX, "%s/%s", root, name) >= PATH_MAX ? error("path_too_long") : 0;
}
static int regular(const char *name, struct stat *st) {
    return lstat(name, st) == 0 && S_ISREG(st->st_mode) && st->st_uid == geteuid() && st->st_nlink == 1;
}
static int private_dir(const char *name) {
    struct stat st;
    if (mkdir(name, 0700) && errno != EEXIST) return error("create_private_directory");
    if (lstat(name, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077))
        return error("private_directory_permissions");
    return 0;
}
static int sync_dir(const char *name) {
    int fd = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return error("open_directory_for_sync");
    int rc = fsync(fd); close(fd);
    return rc ? error("directory_sync") : 0;
}
static int space(const char *root, uint64_t extra) {
    struct statvfs fs;
    if (statvfs(root, &fs)) return error("disk_space_unknown");
    if (fs.f_frsize && (uint64_t)fs.f_bavail > UINT64_MAX / fs.f_frsize) return error("disk_space_overflow");
    uint64_t available = (uint64_t)fs.f_bavail * fs.f_frsize;
    if (extra > UINT64_MAX - opt.reserve_bytes || available < extra + opt.reserve_bytes)
        return error("disk_reserve");
    return 0;
}
static int write_all(int fd, const void *data, size_t size) {
    const unsigned char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; size -= (size_t)n;
    }
    return 0;
}
static int copy_file(const char *source, const char *destination, const char *root) {
    int in = -1, out = -1, rc = -1;
    struct stat st; unsigned char buffer[65536];
    in = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0 || fstat(in, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        st.st_size < 0 || (uint64_t)st.st_size > opt.file_bytes) { error("copy_source_invalid"); goto done; }
    if (space(root, (uint64_t)st.st_size)) goto done;
    out = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    if (out < 0) { error("copy_destination"); goto done; }
    uint64_t copied = 0;
    for (;;) {
        ssize_t n = read(in, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || (n > 0 && write_all(out, buffer, (size_t)n))) { error("copy_io"); goto done; }
        if (!n) break;
        copied += (uint64_t)n;
        if (copied > (uint64_t)st.st_size || interrupted || space(root, 0)) goto done;
    }
    if (copied != (uint64_t)st.st_size || fsync(out)) { error("copy_integrity"); goto done; }
    rc = 0;
done:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    return rc;
}
static int sha_file(const char *name, unsigned char digest[32]) {
    unsigned char buffer[65536]; unsigned int length = 0;
    int fd = open(name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); int rc = -1;
    if (fd < 0 || !ctx || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || (n && EVP_DigestUpdate(ctx, buffer, (size_t)n) != 1)) goto done;
        if (!n) break;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32) rc = 0;
done:
    if (fd >= 0) close(fd);
    EVP_MD_CTX_free(ctx);
    return rc ? error("hash_file") : 0;
}
static void hex(const unsigned char *bytes, char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { output[2*i] = digits[bytes[i] >> 4]; output[2*i+1] = digits[bytes[i] & 15]; }
    output[64] = 0;
}
static int set_limit(int resource, uint64_t value) {
    struct rlimit current;
    if (getrlimit(resource, &current)) return -1;
    rlim_t requested = (rlim_t)value;
    if ((uint64_t)requested != value || requested == RLIM_INFINITY) return -1;
    if (current.rlim_max != RLIM_INFINITY && requested > current.rlim_max) requested = current.rlim_max;
    struct rlimit next = {requested, requested};
    return setrlimit(resource, &next);
}
static int child_limits(void) {
    if (set_limit(RLIMIT_AS, opt.as_bytes) || set_limit(RLIMIT_CPU, opt.cpu_seconds) || set_limit(RLIMIT_FSIZE, opt.file_bytes))
        return -1;
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return -1;
#ifdef __linux__
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL)) return -1;
    if (getppid() == 1) return -1;
#endif
    char line[32]; snprintf(line, sizeof(line), "%" PRIu64, opt.line_bytes);
    return setenv("CLAMAV_UPDATE_MAX_LINE_BYTES", line, 1);
}
static double monotonic(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}
static double driver_cpu(void) {
    struct rusage used;
    if(getrusage(RUSAGE_SELF,&used))return (double)opt.cpu_seconds;
    return (double)used.ru_utime.tv_sec+(double)used.ru_stime.tv_sec+
           ((double)used.ru_utime.tv_usec+(double)used.ru_stime.tv_usec)/1e6;
}
static int run(char *const argv[], const char *log, const char *root, int share_lock) {
    last_stage=argv[1];
    last_child_status=-1;
    if(snprintf(last_log,sizeof(last_log),"%s",log)>=(int)sizeof(last_log))return error("stage_log_path");
    if(child_cpu_used+driver_cpu()>=(double)opt.cpu_seconds)return error("job_cpu_limit");
    uint64_t remaining_cpu=(uint64_t)((double)opt.cpu_seconds-child_cpu_used-driver_cpu());
    if(!remaining_cpu)return error("job_cpu_limit");
    if (space(root, 0)) return -1;
    int fd = open(log, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return error("stage_log");
    double start = monotonic();
    if (start < 0) { close(fd); return error("monotonic_clock"); }
    pid_t child = fork();
    if (!child) {
        (void)setpgid(0, 0);
        opt.cpu_seconds=remaining_cpu;
        if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0 || child_limits()) _exit(125);
        close(fd);
        if (share_lock && fcntl(job_lock, F_SETFD, 0)) _exit(125);
        execv(argv[0], argv); _exit(126);
    }
    close(fd);
    if (child < 0) return error("fork");
    (void)setpgid(child, child);
    int status; struct rusage usage;
    memset(&usage,0,sizeof(usage));
    for (;;) {
        pid_t finished = wait4(child, &status, WNOHANG, &usage);
        if (finished == child) break;
        if (finished < 0 && errno != EINTR) return error("wait_child");
        double now = monotonic();
        if (interrupted || now < 0 || (now - start >= (double)opt.wall_seconds || (job_deadline > 0 && now >= job_deadline)) || space(root, 0)) {
            kill(-child, SIGKILL); kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            return error(interrupted ? "interrupted" : (now - start >= (double)opt.wall_seconds || (job_deadline > 0 && now >= job_deadline)) ? "stage_wall_limit" : "disk_reserve");
        }
        struct timespec pause = {0, 100000000}; nanosleep(&pause, NULL);
    }
    child_cpu_used+=(double)usage.ru_utime.tv_sec+(double)usage.ru_stime.tv_sec+
                    ((double)usage.ru_utime.tv_usec+(double)usage.ru_stime.tv_usec)/1e6;
    if(child_cpu_used+driver_cpu()>(double)opt.cpu_seconds)return error("job_cpu_limit");
    last_child_status=WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return last_child_status == 0 ? 0 : error("stage_failed");
}
static int valid_sign_name(const char *name) {
    const char *p = NULL;
    if (!strncmp(name, "main-", 5)) p = name + 5;
    else if (!strncmp(name, "daily-", 6)) p = name + 6;
    else if (!strncmp(name, "bytecode-", 9)) p = name + 9;
    if (!p || *p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') p++;
    return !strcmp(p, ".cvd.sign");
}
static int database_name(const char *directory, const char *stem, char selected[64]) {
    char name[64], full[PATH_MAX]; struct stat st; int found = 0;
    for (int cld = 0; cld < 2; cld++) {
        snprintf(name, sizeof(name), "%s.%s", stem, cld ? "cld" : "cvd");
        if (path(full, directory, name)) return -1;
        if (lstat(full, &st)) { if (errno != ENOENT) return error("database_stat"); continue; }
        if (!regular(full, &st) || ++found != 1) return error("duplicate_or_invalid_database");
        strcpy(selected, name);
    }
    return found == 1 ? 0 : error("database_missing");
}
static int cache_safe(const char *cache) {
    DIR *dir=opendir(cache);
    if(!dir)return error("cache_directory");
    struct dirent *entry; int rc=0;
    while((entry=readdir(dir))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,".."))continue;
        char name[PATH_MAX]; struct stat st;
        if(path(name,cache,entry->d_name) || !regular(name,&st) || (st.st_mode&022)) {
            rc=error("cache_member_invalid");break;
        }
    }
    closedir(dir);
    return rc;
}
static int fresh_fetch(void) {
    char cache[PATH_MAX], temp[PATH_MAX];
    if (path(cache, opt.state, "cache") || path(temp, opt.state, "freshclam-tmp")) return 2;
    fc_config config = {0};
    config.msgFlags = FC_CONFIG_MSG_QUIET;
    config.maxAttempts = (uint32_t)opt.attempts;
    config.connectTimeout = (uint32_t)opt.connect_seconds;
    config.requestTimeout = (uint32_t)opt.low_speed_seconds;
    config.bCompressLocalDatabase = 1;
    config.databaseDirectory = cache; config.tempDirectory = temp; config.certsDirectory = opt.certs;
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS || fc_initialize(&config) != FC_SUCCESS) return 2;
    /* Authentication remains upstream's normal policy; grammar tests run in fresh
     * processes after fetching. This cache preserves freshclam.dat and cooldown. */
    fc_set_fccb_download_complete(NULL);
    char *dns = NULL, *new_version = NULL;
    (void)fc_dns_query_update_info("current.cvd.clamav.net", &dns, &new_version);
    char *databases[] = {"main", "daily", "bytecode"};
    char *servers[] = {"https://database.clamav.net"};
    uint32_t updated = 0;
    fc_error_t result = fc_update_databases(databases, 3, servers, 1, 0, dns, 1, NULL, &updated);
    free(dns); free(new_version); fc_cleanup();
    return result == FC_SUCCESS || result == FC_UPTODATE ? 0 : 2;
}
static int test_database(void) {
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) return 2;
    if (cl_cvdverify_ex(opt.database, opt.certs, 0) != CL_SUCCESS) return 2;
    struct cl_cvd *header = cl_cvdhead(opt.database);
    if (!header) return 2;
    int valid = header->fl <= cl_retflevel();
    cl_cvdfree(header);
    if (!valid) return 2;
    fc_error_t tested=fc_test_database_ex(opt.database, 1, (char *)opt.certs);
    return tested==FC_SUCCESS ? 0 : tested==FC_EMEM ? 75 : 2;
}
static int inherited_lock(void) {
    char lockpath[PATH_MAX]; struct stat expected, received;
    if (!opt.state || !opt.lock_fd || path(lockpath, opt.state, "job.lock")) return error("inherited_lock_missing");
    char *end; errno = 0; long fd = strtol(opt.lock_fd, &end, 10);
    if (errno || *end || fd < 0 || fd > INT_MAX || !regular(lockpath, &expected) || fstat((int)fd, &received) ||
        expected.st_dev != received.st_dev || expected.st_ino != received.st_ino ||
        flock((int)fd, LOCK_EX | LOCK_NB)) return error("inherited_lock_invalid");
    job_lock = (int)fd;
    return 0;
}
static void json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}
static int add_manifest_file(FILE *out, const char *stage, const char *relative, EVP_MD_CTX *tuple, int *comma) {
    char full[PATH_MAX], encoded[65]; unsigned char digest[32]; struct stat st;
    if (path(full, stage, relative) || !regular(full, &st) || sha_file(full, digest)) return error("manifest_member");
    hex(digest, encoded);
    EVP_DigestUpdate(tuple, relative, strlen(relative) + 1); EVP_DigestUpdate(tuple, digest, sizeof(digest));
    if ((*comma)++) fputc(',', out);
    json_string(out, relative);
    fprintf(out, ":{\"sha256\":\"%s\",\"size\":%" PRIu64 "}", encoded, (uint64_t)st.st_size);
    return ferror(out) ? error("manifest_write") : 0;
}
static int manifest_write(const char *stage, char selected[3][64], uint64_t database_time, char id[69]) {
    char output[PATH_MAX], dbdir[PATH_MAX];
    if (path(output, stage, "manifest.json") || path(dbdir, stage, "databases")) return -1;
    int fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return error("manifest_create");
    FILE *out = fdopen(fd, "w");
    if (!out) { close(fd); return error("manifest_stream"); }
    EVP_MD_CTX *tuple = EVP_MD_CTX_new();
    if (!tuple || EVP_DigestInit_ex(tuple, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(tuple); fclose(out); return error("tuple_hash");
    }
    EVP_DigestUpdate(tuple, opt.runtime_id, strlen(opt.runtime_id));
    EVP_DigestUpdate(tuple, opt.options_id, strlen(opt.options_id));
    if(opt.program_id)EVP_DigestUpdate(tuple,opt.program_id,strlen(opt.program_id));
    /* Write files first so generation_id can hash the tuple without hashing itself. */
    fputs("{\"protocol\":1,\"files\":{", out);
    int comma = 0, rc = -1;
    for (int i = 0; i < 3; i++) {
        char member[PATH_MAX];
        if (path(member, "databases", selected[i]) || add_manifest_file(out, stage, member, tuple, &comma)) goto done;
    }
    /* Detached signatures are immutable generation members too. */
    DIR *directory = opendir(dbdir);
    if (!directory) { error("manifest_directory"); goto done; }
    struct dirent *entry; int failed = 0;
    while ((entry = readdir(directory))) if (valid_sign_name(entry->d_name)) {
        char member[PATH_MAX];
        if (path(member, "databases", entry->d_name) || add_manifest_file(out, stage, member, tuple, &comma)) { failed = 1; break; }
    }
    closedir(directory);
    if (failed) goto done;
    const char *members[] = {"profile/skip.tsv", "profile/validation.json", "profile/ledger.sqlite"};
    for (size_t i = 0; i < sizeof(members)/sizeof(members[0]); i++)
        if (add_manifest_file(out, stage, members[i], tuple, &comma)) goto done;
    if(bounded_validation) {
        const char *receipts[]={"profile/bounded-batches.jsonl","profile/bounded-validation.json"};
        for(size_t i=0;i<sizeof(receipts)/sizeof(receipts[0]);i++)
            if(add_manifest_file(out,stage,receipts[i],tuple,&comma))goto done;
    }
    unsigned char digest[32]; unsigned int n; char encoded[65];
    if (EVP_DigestFinal_ex(tuple, digest, &n) != 1 || n != 32) { error("tuple_hash"); goto done; }
    hex(digest, encoded); strcpy(id, "gen-"); strcat(id, encoded);
    fprintf(out, "},\"generation_id\":\"%s\",\"created_at\":%" PRIu64 ",\"database_created_at\":%" PRIu64
                 ",\"engine_sha256\":\"%s\",\"scan_options_sha256\":\"%s\",\"engine_version\":",
            encoded, (uint64_t)time(NULL), database_time, opt.runtime_id, opt.options_id);
    json_string(out, cl_retver());
    fprintf(out,",\"profile\":\"pdf-jpeg-png-pe-exclusions\","
          "\"qualification\":{\"coverage_qualified\":%s,\"deployment_qualified\":%s,"
          "\"guard_version\":\"%s\",\"ordering_version\":\"%s\"},"
          "\"validation\":{\"mode\":\"%s\",\"status\":\"passed\"}}\n",
          CI_REDUCED_COVERAGE_QUALIFIED?"true":"false",CI_DEPLOYMENT_QUALIFIED?"true":"false",
          CI_GUARD_VERSION,CI_ORDERING_VERSION,bounded_validation?"bounded-native-records":"stock-per-database");
    if (fflush(out) || ferror(out) || fsync(fd)) { error("manifest_write"); goto done; }
    rc = 0;
done:
    EVP_MD_CTX_free(tuple);
    if (fclose(out) && !rc) rc = error("manifest_close");
    return rc;
}
static int read_all(int fd, void *bytes, size_t size) {
    unsigned char *p = bytes;
    while (size) {
        ssize_t n = read(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; size -= (size_t)n;
    }
    return 0;
}
static int cached_cooldown(void) {
    /* Pinned libfreshclam v1 on-disk ABI, not a guessed retry interval. Refuse
     * unknown/corrupt state instead of deleting it and evading upstream limits. */
    struct state_v1 { uint32_t version; char uuid[37]; time_t retry_after; } state;
    char filename[PATH_MAX], cache[PATH_MAX], magic[13]; struct stat st;
    if (path(cache,opt.state,"cache") || path(filename,cache,"freshclam.dat")) return -1;
    int fd = open(filename,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : error("freshclam_state_open");
    int valid = !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
        !read_all(fd,magic,sizeof(magic)) && !memcmp(magic,"FreshClamData",13) &&
        !read_all(fd,&state,sizeof(state)) && state.version == 1 && state.retry_after >= 0;
    close(fd);
    if (!valid) return error("freshclam_state_invalid");
    retry_after = (uint64_t)state.retry_after;
    time_t now = time(NULL);
    if (now < 0) return error("clock_invalid");
    return retry_after > (uint64_t)now ? 1 : 0;
}
static int deferred_cooldown(void) {
    printf("{\"protocol\":1,\"status\":\"deferred\",\"reason\":\"freshclam_cooldown\",\"next_attempt_after\":%" PRIu64 "}\n",retry_after);
    return 0;
}
static struct json_object *current_pointer(const char *state) {
    char name[PATH_MAX]; struct stat st;
    if(path(name,state,"current.json"))return NULL;
    int fd=open(name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0){if(errno!=ENOENT)error("current_pointer_open");return NULL;}
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 ||
       st.st_size<=0 || (uint64_t)st.st_size>opt.file_bytes || st.st_size>INT_MAX) {
        close(fd);error("current_pointer_invalid");return NULL;
    }
    struct json_tokener *parser=json_tokener_new();
    struct json_object *result=NULL; char buffer[4096]; off_t seen=0;
    if(!parser){close(fd);error("current_pointer_memory");return NULL;}
    json_tokener_set_flags(parser,JSON_TOKENER_STRICT);
    enum json_tokener_error parse_error=json_tokener_continue;
    while(seen<st.st_size) {
        ssize_t n=read(fd,buffer,sizeof(buffer));
        if(n<0 && errno==EINTR)continue;
        if(n<=0)break;
        seen+=n;
        if(parse_error==json_tokener_success) {
            for(ssize_t i=0;i<n;i++)if(buffer[i]!=' ' && buffer[i]!='\n' && buffer[i]!='\r' && buffer[i]!='\t')
                parse_error=json_tokener_error_parse_unexpected;
            continue;
        }
        result=json_tokener_parse_ex(parser,buffer,(int)n);
        parse_error=json_tokener_get_error(parser);
        if(parse_error!=json_tokener_continue && parse_error!=json_tokener_success)break;
    }
    json_tokener_free(parser);close(fd);
    struct json_object *version=NULL,*generation=NULL,*program=NULL;
    if(seen!=st.st_size || parse_error!=json_tokener_success || !result ||
       !json_object_is_type(result,json_type_object) ||
       !json_object_object_get_ex(result,"protocol",&version) || !json_object_is_type(version,json_type_int) ||
       json_object_get_int(version)!=1 || !json_object_object_get_ex(result,"generation",&generation) ||
       !json_object_is_type(generation,json_type_string) ||
       strncmp(json_object_get_string(generation),"gen-",4) || !hash_text(json_object_get_string(generation)+4)) {
        json_object_put(result);error("current_pointer_invalid");return NULL;
    }
    if(json_object_object_get_ex(result,"program",&program) &&
       (!json_object_is_type(program,json_type_string) || strncmp(json_object_get_string(program),"pkg-",4) ||
        !hash_text(json_object_get_string(program)+4))) {
        json_object_put(result);error("current_program_invalid");return NULL;
    }
    return result;
}
static int expected_pointer(void) {
    char name[PATH_MAX],encoded[65]; struct stat st; unsigned char digest[32];
    if(path(name,opt.state,"current.json"))return -1;
    if(lstat(name,&st)) {
        if(errno==ENOENT)return !strcmp(opt.expected_current,"absent") ? 0 : error("current_pointer_changed");
        return error("current_pointer_stat");
    }
    if(!strcmp(opt.expected_current,"absent"))return error("current_pointer_changed");
    if(!regular(name,&st) || st.st_size<=0 || (uint64_t)st.st_size>opt.file_bytes || sha_file(name,digest))
        return error("current_pointer_invalid");
    hex(digest,encoded);
    return strcmp(encoded,opt.expected_current) ? error("current_pointer_changed") : 0;
}
static int inherit_program(void) {
    struct json_object *current=current_pointer(opt.state),*program=NULL;
    if(!current) {
        char name[PATH_MAX];struct stat st;
        if(path(name,opt.state,"current.json") || !lstat(name,&st) || errno!=ENOENT)return -1;
        return 0;
    }
    if(!opt.program_id && json_object_object_get_ex(current,"program",&program)) {
        strcpy(inherited_program,json_object_get_string(program));
        opt.program_id=inherited_program;
    }
    json_object_put(current);
    return 0;
}
static int atomic_record(const char *state,const char *name,const struct json_object *object) {
    char template[PATH_MAX],target[PATH_MAX];
    if(path(template,state,".pointer-next-XXXXXX") || path(target,state,name))return -1;
    int fd=mkstemp(template);
    if(fd<0)return error("pointer_create");
    const char *text=json_object_to_json_string_ext((struct json_object *)object,JSON_C_TO_STRING_PLAIN);
    int rc=write_all(fd,text,strlen(text)) || write_all(fd,"\n",1) || fsync(fd);
    close(fd);
    if(rc || rename(template,target) || sync_dir(state)){unlink(template);return error("pointer_publish");}
    return 0;
}
static int pointer_write(const char *state,const char *generation) {
    struct json_object *current=current_pointer(state),*value=NULL;
    char name[PATH_MAX];struct stat st;
    if(!current && (path(name,state,"current.json") || !lstat(name,&st) || errno!=ENOENT))return -1;
    if(current && json_object_object_get_ex(current,"generation",&value) &&
       !strcmp(json_object_get_string(value),generation)) {
        struct json_object *old_program=NULL;
        int has=json_object_object_get_ex(current,"program",&old_program);
        if((!has && !opt.program_id) || (has && opt.program_id && !strcmp(json_object_get_string(old_program),opt.program_id))) {
            json_object_put(current);return 0;
        }
    }
    if(current && atomic_record(state,"previous.json",current)){json_object_put(current);return -1;}
    json_object_put(current);
    struct json_object *next=json_object_new_object();
    json_object_object_add(next,"protocol",json_object_new_int(1));
    json_object_object_add(next,"generation",json_object_new_string(generation));
    if(opt.program_id)json_object_object_add(next,"program",json_object_new_string(opt.program_id));
    int rc=atomic_record(state,"current.json",next);
    json_object_put(next);return rc;
}
/* Only orchestration scratch is removed, never accepted uploads or a published generation. */
static int remove_scratch(const char *name) {
    struct stat st;
    if(lstat(name,&st)) return errno==ENOENT ? 0 : -1;
    if(!S_ISDIR(st.st_mode)) return unlink(name);
    if(chmod(name,0700)) return -1;
    DIR *dir=opendir(name); if(!dir)return -1;
    struct dirent *entry; int rc=0;
    while((entry=readdir(dir))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,".."))continue;
        char child[PATH_MAX];
        if(path(child,name,entry->d_name) || remove_scratch(child)){rc=-1;break;}
    }
    closedir(dir);
    return rc ? rc : rmdir(name);
}
static int temporary_name(const char *name,const char *prefix) {
    size_t n=strlen(prefix);
    if(strncmp(name,prefix,n) || strlen(name)!=n+6)return 0;
    for(const char *p=name+n;*p;p++)
        if(!((*p>='0'&&*p<='9')||(*p>='A'&&*p<='Z')||(*p>='a'&&*p<='z')))return 0;
    return 1;
}
static int recover_scratch(const char *directory,const char *prefix) {
    DIR *dir=opendir(directory);
    if(!dir)return error("scratch_directory");
    struct dirent *entry;int rc=0;
    while((entry=readdir(dir))) {
        if(!temporary_name(entry->d_name,prefix))continue;
        char name[PATH_MAX];struct stat st;
        if(path(name,directory,entry->d_name) || lstat(name,&st) || st.st_uid!=geteuid() ||
           remove_scratch(name)){rc=error("scratch_recovery");break;}
    }
    closedir(dir);return rc;
}
static int freeze(const char *name) {
    DIR *dir=opendir(name); if(!dir)return error("generation_open");
    struct dirent *entry; int rc=0;
    while((entry=readdir(dir))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,".."))continue;
        char child[PATH_MAX]; struct stat st;
        if(path(child,name,entry->d_name) || lstat(child,&st) || st.st_uid!=geteuid()){rc=-1;break;}
        if(S_ISDIR(st.st_mode)) { if(freeze(child)){rc=-1;break;} }
        else {
            if(!S_ISREG(st.st_mode) || st.st_nlink!=1){rc=-1;break;}
            int fd=open(child,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            if(fd<0){rc=-1;break;}
            int failed=fsync(fd) || fchmod(fd,0400); close(fd);
            if(failed){rc=-1;break;}
        }
    }
    closedir(dir);
    if(rc || sync_dir(name) || chmod(name,0500))return error("generation_sync_or_freeze");
    return 0;
}
static int update(void) {
    char cache[PATH_MAX], temp[PATH_MAX], generations[PATH_MAX], stage[PATH_MAX]={0}, dbdir[PATH_MAX], log[PATH_MAX], lockpath[PATH_MAX];
    if (private_dir(opt.state) || path(cache, opt.state, "cache") || private_dir(cache) ||
        path(temp, opt.state, "freshclam-tmp") || private_dir(temp) ||
        path(generations, opt.state, "generations") || private_dir(generations) || path(lockpath, opt.state, "job.lock")) return -1;
    job_lock = open(lockpath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat st;
    if (job_lock < 0 || fstat(job_lock, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1)
        return error("job_lock_invalid");
    if (flock(job_lock, LOCK_EX | LOCK_NB)) { close(job_lock); return error("job_busy"); }
    int rc = -1;
    if(expected_pointer()){close(job_lock);return -1;}
    if(recover_scratch(generations,".stage-") || recover_scratch(opt.state,".pointer-next-")) {
        close(job_lock);return -1;
    }
    double started=monotonic();
    if(started<0){close(job_lock);return error("monotonic_clock");}
    job_deadline=started+(double)opt.wall_seconds;
    if(cache_safe(cache)){close(job_lock);return -1;}
    if(inherit_program()){close(job_lock);return -1;}
    int cooldown=cached_cooldown();
    if(cooldown){close(job_lock);return cooldown>0 ? deferred_cooldown() : -1;}
    if (space(opt.state, 0) || path(stage, generations, ".stage-XXXXXX") || !mkdtemp(stage) ||
        path(dbdir, stage, "databases") || private_dir(dbdir) || path(log, stage, "fetch.log")) goto done;
    char lock_string[32]; snprintf(lock_string, sizeof(lock_string), "%d", job_lock);
    char *fetch_argv[] = {executable, "fetch", "--state", (char *)opt.state, "--certs", (char *)opt.certs,
                          "--lock-fd", lock_string, NULL};
    int fetched=run(fetch_argv, log, opt.state, 1);
    if(cache_safe(cache))goto done;
    cooldown=cached_cooldown();
    if(cooldown>0){rc=deferred_cooldown();goto done;}
    if(fetched || cooldown<0)goto done;
    const char *stems[] = {"main", "daily", "bytecode"};
    char selected[3][64];
    for (int i = 0; i < 3; i++) {
        char source[PATH_MAX], destination[PATH_MAX];
        if (database_name(cache, stems[i], selected[i]) || path(source, cache, selected[i]) || path(destination, dbdir, selected[i]) ||
            copy_file(source, destination, opt.state)) { goto done; }
    }
    DIR *directory = opendir(cache);
    if (!directory) { error("cache_directory"); goto done; }
    struct dirent *entry; int copy_error = 0;
    while ((entry = readdir(directory))) {
        if (!valid_sign_name(entry->d_name)) continue;
        char source[PATH_MAX], destination[PATH_MAX];
        if (path(source, cache, entry->d_name) || path(destination, dbdir, entry->d_name) || copy_file(source, destination, opt.state)) { copy_error = 1; break; }
    }
    closedir(directory);
    if (copy_error) { goto done; }
    for (int i = 0; i < 3; i++) {
        char database[PATH_MAX], phase[80];
        snprintf(phase, sizeof(phase), "validate-%s.log", stems[i]);
        if (path(database, dbdir, selected[i]) || path(log, stage, phase)) { goto done; }
        char *args[] = {executable, "test-db", "--database", database, "--certs", (char *)opt.certs,
                        "--state", (char *)opt.state, "--lock-fd", lock_string, NULL};
        if (run(args, log, opt.state, 1)) {
            if(last_child_status==75)bounded_validation=1;
            else goto done;
        }
    }
    char daily[PATH_MAX];
    if (path(daily, dbdir, selected[1])) { goto done; }
    struct cl_cvd *header = cl_cvdhead(daily);
    time_t now = time(NULL);
    if (!header || now < 0 || header->stime > (unsigned long)now || (uint64_t)now - header->stime > opt.age_seconds) {
        if (header) cl_cvdfree(header);
        error("database_freshness"); goto done;
    }
    uint64_t database_time = header->stime;
    cl_cvdfree(header);
    char as_string[32], cpu_string[32], wall_string[32], file_string[32], line_string[32], age_string[32];
    snprintf(as_string,sizeof(as_string),"%" PRIu64,opt.as_bytes);
    snprintf(cpu_string,sizeof(cpu_string),"%" PRIu64,opt.cpu_seconds);
    snprintf(wall_string,sizeof(wall_string),"%" PRIu64,opt.wall_seconds);
    snprintf(file_string,sizeof(file_string),"%" PRIu64,opt.file_bytes);
    snprintf(line_string,sizeof(line_string),"%" PRIu64,opt.line_bytes);
    snprintf(age_string,sizeof(age_string),"%" PRIu64,opt.age_seconds);
    if (path(log, stage, "prepare.log")) { goto done; }
    char *prepare[] = {(char *)opt.scanner, "prepare", "--generation", stage, "--certs", (char *)opt.certs,
                      "--state", (char *)opt.state, "--lock-fd", lock_string,
                      "--as-bytes",as_string,"--cpu-seconds",cpu_string,"--wall-seconds",wall_string,"--file-bytes",file_string,"--line-bytes",line_string,"--max-age-seconds",age_string,NULL};
    if (run(prepare, log, opt.state, 1)) { goto done; }
    if(bounded_validation) {
        if(path(log,stage,"bounded-validation.log"))goto done;
        char *bounded[]={(char*)opt.scanner,"validate-bounded","--generation",stage,"--certs",(char*)opt.certs,
                         "--state",(char*)opt.state,"--lock-fd",lock_string,"--as-bytes",as_string,
                         "--cpu-seconds",cpu_string,"--wall-seconds",wall_string,"--file-bytes",file_string,
                         "--line-bytes",line_string,"--max-age-seconds",age_string,NULL};
        if(run(bounded,log,opt.state,1))goto done;
    }
    if(path(log,stage,"self-test.log"))goto done;
    char id[69];
    if (manifest_write(stage, selected, database_time, id)) goto done;
    char *test[] = {(char *)opt.scanner, "self-test", "--profile", "pdf-jpeg-png-pe-exclusions", "--generation", stage, "--certs", (char *)opt.certs,
                   "--state", (char *)opt.state, "--lock-fd", lock_string,
                   "--as-bytes",as_string,"--cpu-seconds",cpu_string,"--wall-seconds",wall_string,"--file-bytes",file_string,"--line-bytes",line_string,"--max-age-seconds",age_string,NULL};
    if (run(test, log, opt.state, 1)) { goto done; }
    char destination[PATH_MAX];
    if (path(destination, generations, id) || sync_dir(dbdir) || sync_dir(stage)) goto done;
    int existed=lstat(destination,&st)==0;
    if(existed) {
        if(!S_ISDIR(st.st_mode) || st.st_uid!=geteuid()){error("generation_destination");goto done;}
        if(path(log,stage,"existing-self-test.log"))goto done;
        char *existing[]={(char*)opt.scanner,"self-test","--profile","pdf-jpeg-png-pe-exclusions","--generation",destination,"--certs",(char*)opt.certs,
                          "--state",(char*)opt.state,"--lock-fd",lock_string,"--as-bytes",as_string,
                          "--cpu-seconds",cpu_string,"--wall-seconds",wall_string,"--file-bytes",file_string,"--line-bytes",line_string,"--max-age-seconds",age_string,NULL};
        if(run(existing,log,opt.state,1))goto done;
    } else if(errno!=ENOENT || freeze(stage) || rename(stage,destination)){error("generation_publish");goto done;}
    if(child_cpu_used+driver_cpu()>(double)opt.cpu_seconds){error("job_cpu_limit");goto done;}
    if(sync_dir(generations) || pointer_write(opt.state,id))goto done;
    if(existed)(void)remove_scratch(stage);
    printf("{\"protocol\":1,\"status\":\"%s\",\"generation\":\"%s\",\"next_attempt_after\":null,\"child_cpu_seconds\":%.6f}\n",existed?"up_to_date":"updated",id,child_cpu_used);
    rc = 0;
done:
    if(rc && last_log[0]) {
        char retained[PATH_MAX];struct stat diagnostic;
        if(!path(retained,opt.state,"last-update.log") && regular(last_log,&diagnostic)) {
            (void)rename(last_log,retained);(void)sync_dir(opt.state);
        }
    }
    if(stage[0])(void)remove_scratch(stage);
    close(job_lock);
    return rc;
}
static uint64_t number(const char *value) {
    if (!value || !*value) return 0;
    uint64_t result = 0;
    for (; *value; value++) {
        if (*value < '0' || *value > '9' || result > (UINT64_MAX - (*value - '0')) / 10) return 0;
        result = result * 10 + (unsigned)(*value - '0');
    }
    return result;
}
static int hash_text(const char *value) {
    if(!value || strlen(value)!=64)return 0;
    for(const char *p=value;*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')))return 0;
    return 1;
}
static int parse(int argc, char **argv) {
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return error("missing_option_value");
        const char *name = argv[i], *value = argv[i+1];
#define STR(flag, field) if (!strcmp(name, flag)) { if (opt.field) return error("duplicate_option"); opt.field=value; continue; }
#define NUM(flag, field) if (!strcmp(name, flag)) { if (opt.field || !(opt.field=number(value))) return error("invalid_numeric_option"); continue; }
        STR("--state", state) STR("--scanner", scanner) STR("--certs", certs) STR("--runtime-id", runtime_id) STR("--engine-sha256", runtime_id) STR("--options-sha256", options_id) STR("--database", database) STR("--lock-fd", lock_fd) STR("--program-id", program_id) STR("--expected-current-sha256", expected_current)
        NUM("--as-bytes", as_bytes) NUM("--cpu-seconds", cpu_seconds) NUM("--wall-seconds", wall_seconds)
        NUM("--file-bytes", file_bytes) NUM("--max-line-bytes", line_bytes) NUM("--connect-seconds", connect_seconds)
        NUM("--low-speed-seconds", low_speed_seconds) NUM("--max-attempts", attempts) NUM("--max-age-seconds", age_seconds)
        NUM("--disk-reserve-bytes", reserve_bytes)
#undef STR
#undef NUM
        return error("unknown_option");
    }
    return 0;
}
static int import_internal(void) {
#define ENV(field) opt.field=number(getenv("COMPACT_UPDATE_" #field));
    ENV(as_bytes) ENV(cpu_seconds) ENV(wall_seconds) ENV(file_bytes) ENV(line_bytes)
    ENV(connect_seconds) ENV(low_speed_seconds) ENV(attempts) ENV(age_seconds) ENV(reserve_bytes)
#undef ENV
    return opt.as_bytes && opt.cpu_seconds && opt.wall_seconds && opt.file_bytes && opt.line_bytes && opt.connect_seconds && opt.low_speed_seconds && opt.attempts && opt.age_seconds && opt.reserve_bytes ? 0 : error("internal_policy_missing");
}
static int export_internal(void) {
    char value[32];
#define ENV(field) snprintf(value,sizeof(value),"%" PRIu64,opt.field); if(setenv("COMPACT_UPDATE_" #field,value,1))return -1;
    ENV(as_bytes) ENV(cpu_seconds) ENV(wall_seconds) ENV(file_bytes) ENV(line_bytes)
    ENV(connect_seconds) ENV(low_speed_seconds) ENV(attempts) ENV(age_seconds) ENV(reserve_bytes)
#undef ENV
    return 0;
}
int main(int argc, char **argv) {
    umask(0077); signal(SIGTERM, stop); signal(SIGINT, stop);
    if (argc < 2 || parse(argc, argv) || !opt.certs || opt.certs[0] != '/') goto failed;
    if (!strcmp(argv[1], "fetch") || !strcmp(argv[1], "test-db")) {
        if (import_internal() || opt.wall_seconds>UINT_MAX || inherited_lock() || child_limits()) goto failed;
        signal(SIGALRM,expired); alarm((unsigned)opt.wall_seconds);
        if (!strcmp(argv[1], "fetch")) return opt.state ? fresh_fetch() : 2;
        return opt.database ? test_database() : 2;
    }
    if (strcmp(argv[1], "update") || !opt.state || !opt.scanner || !opt.runtime_id || !opt.options_id || opt.state[0] != '/' || opt.scanner[0] != '/' ||
        !opt.as_bytes || !opt.cpu_seconds || !opt.wall_seconds || !opt.file_bytes || !opt.line_bytes || !opt.connect_seconds ||
        !opt.low_speed_seconds || !opt.attempts || !opt.age_seconds || !opt.reserve_bytes ||
        opt.wall_seconds > UINT_MAX || opt.connect_seconds > UINT32_MAX || opt.low_speed_seconds > UINT32_MAX || opt.attempts > UINT32_MAX ||
        !hash_text(opt.runtime_id) || !hash_text(opt.options_id) ||
        !opt.expected_current || (strcmp(opt.expected_current,"absent") && !hash_text(opt.expected_current)) ||
        (opt.program_id && (strncmp(opt.program_id,"pkg-",4) || !hash_text(opt.program_id+4))) || export_internal()) { error("required_policy_missing"); goto failed; }
    if (!realpath(argv[0], executable)) { error("executable_path"); goto failed; }
    signal(SIGALRM,expired); alarm((unsigned)opt.wall_seconds);
    if (child_limits() || cl_init(CL_INIT_DEFAULT) != CL_SUCCESS || update()) goto failed;
    alarm(0);
    return 0;
failed:
    fprintf(stdout, "{\"protocol\":1,\"status\":\"%s\",\"reason\":\"%s\",\"phase\":\"%s\",\"next_attempt_after\":null}\n",
            !strcmp(failure,"job_busy") || !strcmp(failure,"disk_reserve") || !strcmp(failure,"current_pointer_changed") ? "deferred" : "failed",failure,last_stage);
    return 2;
}
