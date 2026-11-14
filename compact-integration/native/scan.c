/* SPDX-License-Identifier: GPL-2.0-only
 * One-shot, bounded-scanner adapter. Official inputs remain unchanged.
 * A reduced generation cannot enable its own coverage qualification.
 */
#define _GNU_SOURCE
#include "clamav.h"
#include "prepare.h"
#include "limits.h"
#include "qualification.h"
#include "profile_names.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <dlfcn.h>
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
#include <sys/file.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define CI_PROFILE "pdf-jpeg-png-pe-exclusions"
#define CI_MAX_FILE (100ULL * 1024 * 1024)
#define CI_MAX_SCAN (400ULL * 1024 * 1024)
#define CI_MAX_MANIFEST (1024 * 1024)

struct context {
    json_object *findings;
    json_object *reasons;
    unsigned guard;
    bool incomplete;
    bool bad_callback;
};
struct skips { char *bytes; char **keys; size_t count; };
struct generation {
    json_object *manifest;
    char manifest_sha256[65];
    int dirfd;
    char id[65];
    bool validation_passed;
    bool manifest_qualification;
};
static char error_reason[256] = "invalid-invocation";
static void set_error(const char *s) { snprintf(error_reason, sizeof(error_reason), "%s", s); }
static void add_s(json_object *o, const char *k, const char *s) {
    json_object_object_add(o, k, s ? json_object_new_string(s) : NULL);
}
static void add_b(json_object *o, const char *k, bool b) {
    json_object_object_add(o, k, json_object_new_boolean(b));
}
static void add_n(json_object *o, const char *k, int64_t n) {
    json_object_object_add(o, k, json_object_new_int64(n));
}
static const char *get_s(json_object *o, const char *key) {
    json_object *v = NULL;
    return json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_string)
        ? json_object_get_string(v) : NULL;
}
static bool get_b(json_object *o, const char *key) {
    json_object *v = NULL;
    return json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_boolean)
        && json_object_get_boolean(v);
}
static bool get_i(json_object *o, const char *key, int64_t *value) {
    json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_int)) return false;
    *value = json_object_get_int64(v); return true;
}
static bool is_hash(const char *s) {
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static void reason(struct context *ctx, const char *s) {
    for (size_t i = 0; i < json_object_array_length(ctx->reasons); i++)
        if (!strcmp(json_object_get_string(json_object_array_get_idx(ctx->reasons, i)), s)) return;
    json_object_array_add(ctx->reasons, json_object_new_string(s));
}
static bool digest_fd(int fd, char out[65], uint64_t *size) {
    unsigned char bytes[65536], digest[32]; unsigned len = 0; off_t offset = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(ctx); return false; }
    for (;;) {
        ssize_t n = pread(fd, bytes, sizeof(bytes), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { EVP_MD_CTX_free(ctx); return false; }
        if (!n) break;
        if (EVP_DigestUpdate(ctx, bytes, (size_t)n) != 1) { EVP_MD_CTX_free(ctx); return false; }
        offset += n;
    }
    bool ok = EVP_DigestFinal_ex(ctx, digest, &len) == 1 && len == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) return false;
    for (unsigned i = 0; i < len; i++) snprintf(out + 2*i, 3, "%02x", digest[i]);
    *size = (uint64_t)offset;
    return true;
}
static bool engine_identity(char hash[65]) {
    Dl_info info;
    if (!dladdr((void *)cl_init, &info) || !info.dli_fname) return false;
    char canonical[PATH_MAX];
    if (!realpath(info.dli_fname, canonical)) return false;
    int fd = open(canonical, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    uint64_t size = 0;
    if (fd < 0) return false;
    bool ok = digest_fd(fd, hash, &size); close(fd); return ok;
}
/* Module loading in upstream uses explicit search directories rather than the
 * scanner executable RUNPATH. Resolve only directories belonging to this pinned
 * runtime, preload the UnRAR dependency, then let cl_init verify the interface. */
static bool bootstrap_modules(void) {
    Dl_info info;char library[PATH_MAX],parent[PATH_MAX];
    if(!dladdr((void*)cl_init,&info)||!info.dli_fname||!realpath(info.dli_fname,library))return false;
    char *slash=strrchr(library,'/');if(!slash)return false;*slash=0;
    snprintf(parent,sizeof(parent),"%s",library);slash=strrchr(parent,'/');if(!slash)return false;*slash=0;
    char dirs[3][PATH_MAX];snprintf(dirs[0],sizeof(dirs[0]),"%s",library);
    if(snprintf(dirs[1],sizeof(dirs[1]),"%s/libclamunrar",parent)>=(int)sizeof(dirs[1])
       ||snprintf(dirs[2],sizeof(dirs[2]),"%s/libclamunrar_iface",parent)>=(int)sizeof(dirs[2]))return false;
    char search[3*PATH_MAX];
    if(snprintf(search,sizeof(search),"%s:%s:%s",dirs[0],dirs[1],dirs[2])>=(int)sizeof(search)
       ||setenv("LD_LIBRARY_PATH",search,1))return false;
    const char *names[]={"libclamunrar.so","libclamunrar.so.14"};
    void *dependency=NULL;
    for(size_t i=0;i<3&&!dependency;i++)for(size_t j=0;j<2&&!dependency;j++) {
        char candidate[PATH_MAX];
        if(snprintf(candidate,sizeof(candidate),"%s/%s",dirs[i],names[j])>=(int)sizeof(candidate))continue;
        dependency=dlopen(candidate,RTLD_NOW|RTLD_GLOBAL);
    }
    return dependency!=NULL;
}
static const char option_spec[] =
    "protocol=1;db=CL_DB_STDOPT;allmatch=1;heuristics=1;metadata=1;parse=all;"
    "limits=1;encrypted=1;broken=1;broken-media=1;cache=0;"
    "max-file=104857600;max-scan=419430400;max-files=10000;recursion=17;max-ms=90000";
static void options_hash(char out[65]) {
    unsigned char digest[32]; unsigned len = 0;
    EVP_Digest(option_spec, sizeof(option_spec)-1, digest, &len, EVP_sha256(), NULL);
    for (unsigned i = 0; i < len; i++) snprintf(out + 2*i, 3, "%02x", digest[i]);
}
/* Open every component beneath the already opened immutable generation. */
static int open_relative(int root, const char *path) {
    if (!path || !*path || path[0] == '/' || strlen(path) >= PATH_MAX) return -1;
    char *copy = strdup(path); if (!copy) return -1;
    int parent = dup(root), result = -1; char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..") || !*part) goto done;
        for (const unsigned char *p = (unsigned char *)part; *p; p++) if (*p < 32 || *p == 127) goto done;
        bool last = !save || !*save;
        int next = openat(parent, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (last ? 0 : O_DIRECTORY));
        if (next < 0) goto done;
        close(parent); parent = next;
        if (last) { result = parent; parent = -1; }
    }
done:
    if (parent >= 0) close(parent);
    free(copy); return result;
}
static json_object *read_json_fd(int fd, size_t max) {
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 2 || (uint64_t)st.st_size > max) return NULL;
    size_t len = (size_t)st.st_size; char *s = calloc(len + 1, 1);
    if (!s) return NULL;
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, s + done, len-done, (off_t)done);
        if (n <= 0) { free(s); return NULL; } done += (size_t)n;
    }
    struct json_tokener *tok = json_tokener_new();
    if (!tok) { free(s); return NULL; }
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    json_object *v = json_tokener_parse_ex(tok, s, (int)len);
    bool ok = json_tokener_get_error(tok) == json_tokener_success;
    size_t end = json_tokener_get_parse_end(tok);
    while (end < len && (s[end] == ' ' || s[end] == '\t' || s[end] == '\r' || s[end] == '\n')) end++;
    ok = ok && end == len && v && json_object_is_type(v, json_type_object);
    json_tokener_free(tok); free(s);
    if (!ok && v) json_object_put(v);
    return ok ? v : NULL;
}
static bool ci_bounded_fingerprint(int root,char output[65]);
static bool verify_generation(struct generation *g, const char *path, const char *engine_hash, uint64_t max_age) {
    char expected_options[65]; options_hash(expected_options);
    g->dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (g->dirfd < 0) { set_error("generation-open-failed"); return false; }
    int fd = open_relative(g->dirfd, "manifest.json");
    if (fd < 0) { set_error("manifest-missing"); return false; }
    uint64_t manifest_size=0;
    if(!digest_fd(fd,g->manifest_sha256,&manifest_size)){close(fd);set_error("manifest-hash-failed");return false;}
    g->manifest = read_json_fd(fd, CI_MAX_MANIFEST); close(fd);
    if (!g->manifest) { set_error("manifest-invalid-json"); return false; }
    int64_t n = 0, created = 0, database_created = 0;
    const char *id = get_s(g->manifest, "generation_id");
    if (!get_i(g->manifest, "protocol", &n) || n != 1 || !is_hash(id)
        || !get_i(g->manifest, "created_at", &created) || !get_i(g->manifest, "database_created_at", &database_created)
        || !get_s(g->manifest, "engine_version") || strcmp(get_s(g->manifest, "engine_version"), cl_retver())
        || !get_s(g->manifest, "engine_sha256") || strcmp(get_s(g->manifest, "engine_sha256"), engine_hash)
        || !get_s(g->manifest, "scan_options_sha256") || strcmp(get_s(g->manifest, "scan_options_sha256"), expected_options)) {
        set_error("manifest-identity-mismatch"); return false;
    }
    snprintf(g->id, sizeof(g->id), "%s", id);
    time_t now = time(NULL);
    if (created < 1 || created > (int64_t)now + 300 || database_created < 1
        || database_created > (int64_t)now + 300 || ((int64_t)now>database_created&&(uint64_t)((int64_t)now-database_created)>max_age)) {
        set_error("database-stale-or-future"); return false;
    }
    json_object *files = NULL, *validation = NULL, *qualification = NULL;
    if (!json_object_object_get_ex(g->manifest, "files", &files) || !json_object_is_type(files, json_type_object)
        || json_object_object_length(files) < 3 || json_object_object_length(files) > 256) {
        set_error("manifest-file-list-invalid"); return false;
    }
    json_object_object_foreach(files, name, spec) {
        int64_t expected_size = 0; const char *expected = get_s(spec, "sha256");
        if (!*name || !is_hash(expected) || !get_i(spec, "size", &expected_size) || expected_size < 0
            || strstr(name, "//") || name[strlen(name)-1] == '/') {
            set_error("manifest-file-entry-invalid"); return false;
        }
        fd = open_relative(g->dirfd, name); struct stat st;
        char actual[65]; uint64_t actual_size = 0;
        bool ok = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode)
            && digest_fd(fd, actual, &actual_size) && (uint64_t)expected_size == actual_size && !strcmp(expected, actual);
        if (fd >= 0) close(fd);
        if (!ok) { set_error("generation-file-changed"); return false; }
    }
    fd = open_relative(g->dirfd, "databases");
    if (fd < 0) { set_error("database-directory-missing"); return false; }
    DIR *dir = fdopendir(fd); if (!dir) { close(fd); return false; }
    unsigned main_count = 0, daily_count = 0, bytecode_count = 0; bool ok = true;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char rel[PATH_MAX]; json_object *spec = NULL;
        if (snprintf(rel, sizeof(rel), "databases/%s", entry->d_name) >= (int)sizeof(rel)
            || !json_object_object_get_ex(files, rel, &spec)) { ok = false; break; }
        if (ci_official_signature_name(entry->d_name)) continue;
        if (!strcmp(entry->d_name,"main.cvd") || !strcmp(entry->d_name,"main.cld")) main_count++;
        else if (!strcmp(entry->d_name,"daily.cvd") || !strcmp(entry->d_name,"daily.cld")) {
            daily_count++;
            char full[PATH_MAX];
            if (snprintf(full, sizeof(full), "%s/%s", path, rel) >= (int)sizeof(full)) { ok=false; break; }
            struct cl_cvd *header = cl_cvdhead(full);
            if (!header || header->stime != database_created) ok = false;
            if (header) cl_cvdfree(header);
        } else if (!strcmp(entry->d_name,"bytecode.cvd") || !strcmp(entry->d_name,"bytecode.cld")) bytecode_count++;
        else { ok = false; break; }
    }
    closedir(dir);
    if (!ok || main_count != 1 || daily_count != 1 || bytecode_count != 1) {
        set_error("database-member-set-mismatch"); return false;
    }
    if (json_object_object_get_ex(g->manifest,"validation",&validation) && json_object_is_type(validation,json_type_object)) {
        const char *status = get_s(validation,"status"), *mode = get_s(validation,"mode");
        g->validation_passed = status && mode && !strcmp(status,"passed") && !strcmp(mode,"stock-per-database");
        if(status&&mode&&!strcmp(status,"passed")&&!strcmp(mode,"bounded-native-records")){
            json_object *spec=NULL;int64_t eligible=0,validated=0,validation_options=0;char snapshot[65];
            bool listed=json_object_object_get_ex(files,"profile/bounded-validation.json",&spec)
                &&json_object_object_get_ex(files,"profile/bounded-batches.jsonl",&spec);
            int bounded=open_relative(g->dirfd,"profile/bounded-validation.json");
            json_object *receipt=bounded>=0?read_json_fd(bounded,CI_MAX_MANIFEST):NULL;
            if(bounded>=0)close(bounded);
            g->validation_passed=listed&&receipt&&get_s(receipt,"status")&&!strcmp(get_s(receipt,"status"),"passed")
                &&get_s(receipt,"mode")&&!strcmp(get_s(receipt,"mode"),"bounded-native-records")
                &&get_s(receipt,"engine_sha256")&&!strcmp(get_s(receipt,"engine_sha256"),engine_hash)
                &&get_s(receipt,"scan_options_sha256")&&!strcmp(get_s(receipt,"scan_options_sha256"),expected_options)
                &&get_i(receipt,"native_validation_db_options",&validation_options)
                &&validation_options==(CL_DB_STDOPT|CL_DB_PUA|CL_DB_ENHANCED)
                &&get_i(receipt,"eligible_occurrences",&eligible)&&get_i(receipt,"validated_occurrences",&validated)
                &&eligible>=0&&eligible==validated&&get_s(receipt,"snapshot_sha256")
                &&ci_bounded_fingerprint(g->dirfd,snapshot)&&!strcmp(get_s(receipt,"snapshot_sha256"),snapshot);
            if(receipt)json_object_put(receipt);
        }
    }
    if (!g->validation_passed) { set_error("native-database-validation-required"); return false; }
    if (json_object_object_get_ex(g->manifest,"qualification",&qualification) && json_object_is_type(qualification,json_type_object))
        g->manifest_qualification = get_b(qualification,"coverage_qualified")
            && get_s(qualification,"guard_version") && !strcmp(get_s(qualification,"guard_version"),cl_subset_guard_version())
            && get_s(qualification,"ordering_version") && !strcmp(get_s(qualification,"ordering_version"),CI_ORDERING_VERSION);
    return true;
}
static bool load_skips(struct skips *s, int root) {
    int fd = open_relative(root, "profile/skip.tsv"); struct stat st;
    if (fd < 0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > 32*1024*1024) {
        if (fd >= 0) close(fd);
        return false;
    }
    size_t n = (size_t)st.st_size; s->bytes = calloc(n+1,1);
    if (!s->bytes) { close(fd); return false; }
    size_t got = 0;
    while (got < n) { ssize_t r = read(fd,s->bytes+got,n-got); if(r<=0) { close(fd); return false; } got+=(size_t)r; }
    close(fd);
    if (n && s->bytes[n-1]!='\n') return false;
    for(size_t i=0;i<n;i++) { if(!s->bytes[i]) return false; if(s->bytes[i]=='\n') s->count++; }
    s->keys = calloc(s->count+1,sizeof(char*)); if(!s->keys) return false;
    char *start=s->bytes;size_t j=0;
    for(size_t i=0;i<n;i++) if(s->bytes[i]=='\n') {
        s->bytes[i]=0;char *tab=strchr(start,'\t');
        if(!tab||strchr(tab+1,'\t')||tab==start||!tab[1]) return false;
        s->keys[j++]=start;start=s->bytes+i+1;
    }
    for(size_t i=1;i<s->count;i++) if(strcmp(s->keys[i-1],s->keys[i])>=0) return false;
    return true;
}
static int skip_compare(const char *format,const char *name,const char *key) {
    size_t n=strlen(format);int c=strncmp(format,key,n);if(c)return c;
    if(key[n]!='\t')return -1;
    return strcmp(name,key+n+1);
}
static int sigload(const char *format,const char *name,unsigned custom,void *context) {
    struct skips *s=context;
    if(custom) return 0; /* Never apply an official name group to a custom rule. */
    if(!strcmp(format,"mdb")||!strcmp(format,"msb")||!strcmp(format,"imp"))name="*";
    else if(strcmp(format,"ndb")&&strcmp(format,"ldb"))return 0;
    size_t lo=0,hi=s->count;
    while(lo<hi){size_t mid=lo+(hi-lo)/2;int c=skip_compare(format,name,s->keys[mid]);if(!c)return 1;if(c<0)hi=mid;else lo=mid+1;}
    return 0;
}
static void guard_notify(uint32_t flags,void *p) { ((struct context*)p)->guard|=flags; }
static bool policy_name(const char *s) {
    return s && (!strncmp(s,"Heuristics.Limits.",18)||!strncmp(s,"Heuristics.Encrypted.",21)
        ||!strncmp(s,"Heuristics.Broken.",18));
}
static void virus_found(int fd,const char *name,void *p) {
    (void)fd;struct context *ctx=p;
    if(policy_name(name)){ctx->incomplete=true;reason(ctx,"scan-limit-encryption-or-parser-alert");}
    json_object *o=json_object_new_object();add_s(o,"name",name);json_object_array_add(ctx->findings,o);
}
static cl_error_t layer_event(cl_scan_layer_t *layer,void *p) {
    struct context *ctx=p;const char *type=NULL;
    if(cl_scan_layer_get_type(layer,&type)!=CL_SUCCESS||!type){ctx->bad_callback=true;return CL_SUCCESS;}
    if(!strcmp(type,"CL_TYPE_ERROR")||!strcmp(type,"CL_TYPE_ANY")||!strcmp(type,"CL_TYPE_OTHER")) {
        ctx->incomplete=true;reason(ctx,"unknown-or-unsupported-layer");
    }
    return CL_SUCCESS;
}
static void inspect_metadata(json_object *o,struct context *ctx) {
    if(!o)return;
    if(json_object_is_type(o,json_type_object)) {
        json_object_object_foreach(o,key,v) {
            if(!strcmp(key,"Encrypted")&&json_object_get_boolean(v)){ctx->incomplete=true;reason(ctx,"encrypted-content");}
            if(!strcmp(key,"ParseErrors")&&((json_object_is_type(v,json_type_array)&&json_object_array_length(v))
                ||(!json_object_is_type(v,json_type_array)&&json_object_get_boolean(v)))) {
                ctx->incomplete=true;reason(ctx,"parser-error");
            }
            inspect_metadata(v,ctx);
        }
    } else if(json_object_is_type(o,json_type_array))
        for(size_t i=0;i<json_object_array_length(o);i++)inspect_metadata(json_object_array_get_idx(o,i),ctx);
}
static int file_properties(const char *s,int status,void *p) {
    (void)status;struct context *ctx=p;json_object *o=json_tokener_parse(s);
    if(!o)ctx->bad_callback=true;else{inspect_metadata(o,ctx);json_object_put(o);}return 0;
}
static cl_error_t meta(const char *type,unsigned long container_size,const char *name,unsigned long size,
                       int encrypted,unsigned position,void *p) {
    (void)type;(void)container_size;(void)name;(void)size;(void)position;
    if(encrypted){struct context*ctx=p;ctx->incomplete=true;reason(ctx,"encrypted-content");}return CL_SUCCESS;
}
static struct cl_engine *engine_load(const char *generation,const char *certs,bool reduced,
                                     struct skips *skips) {
    char db[PATH_MAX];
    if(snprintf(db,sizeof(db),"%s/databases",generation)>=(int)sizeof(db))return NULL;
    struct cl_engine *e=cl_engine_new();if(!e)return NULL;
    if(cl_engine_set_str(e,CL_ENGINE_CVDCERTSDIR,certs)!=CL_SUCCESS
        ||cl_engine_set_num(e,CL_ENGINE_DISABLE_CACHE,1)!=CL_SUCCESS
        ||cl_engine_set_num(e,CL_ENGINE_MAX_FILESIZE,CI_MAX_FILE)!=CL_SUCCESS
        ||cl_engine_set_num(e,CL_ENGINE_MAX_SCANSIZE,CI_MAX_SCAN)!=CL_SUCCESS
        ||cl_engine_set_num(e,CL_ENGINE_MAX_FILES,10000)!=CL_SUCCESS
        ||cl_engine_set_num(e,CL_ENGINE_MAX_RECURSION,17)!=CL_SUCCESS
        ||cl_engine_set_num(e,CL_ENGINE_MAX_SCANTIME,90000)!=CL_SUCCESS)goto fail;
    if(reduced){if(cl_engine_enable_subset_guard(e,guard_notify)!=CL_SUCCESS)goto fail;cl_engine_set_clcb_sigload(e,sigload,skips);}
    unsigned count=0;
    if(cl_load(db,e,&count,CL_DB_STDOPT)!=CL_SUCCESS||!count)goto fail;
    cl_engine_set_clcb_sigload(e,NULL,NULL);
    if(cl_engine_compile(e)!=CL_SUCCESS)goto fail;
    cl_engine_set_clcb_virus_found(e,virus_found);cl_engine_set_clcb_meta(e,meta);
    cl_engine_set_clcb_file_props(e,file_properties);
    cl_engine_set_scan_callback(e,layer_event,CL_SCAN_CALLBACK_FILE_TYPE);
    return e;
fail:
    cl_engine_free(e);return NULL;
}
static json_object *result_base(const char *profile,const char *generation) {
    json_object *o=json_object_new_object();add_n(o,"protocol",1);add_s(o,"status","failed");
    add_b(o,"completed",false);add_b(o,"applicability_proven",false);add_b(o,"coverage_qualified",false);
    add_s(o,"sha256",NULL);add_n(o,"size",0);add_s(o,"engine_version",cl_retver());
    add_s(o,"generation_id",generation);add_s(o,"requested_profile",profile);add_s(o,"effective_profile",profile);
    json_object_object_add(o,"findings",json_object_new_array());json_object_object_add(o,"reason_codes",json_object_new_array());return o;
}
static void emit(json_object *o){puts(json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN));fflush(stdout);json_object_put(o);}
static void emit_startup_failure(json_object *o) {
    const char *text=json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN);
    if(text){ci_emergency_write(text,strlen(text));ci_emergency_write("\n",1);}
    json_object_put(o);
}
/* The lock may be inherited from the local updater. Matching inode plus flock
 * on the same inherited open-file description avoids recursive deadlock. */
static int acquire_lock(const char *state, const char *inherited) {
    if (!state) { set_error("state-directory-required"); return -1; }
    int root=open(state,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0){set_error("state-directory-invalid");return -1;}
    int lock=openat(root,"job.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    close(root);struct stat expected,actual;
    if(lock<0||fstat(lock,&expected)||!S_ISREG(expected.st_mode)||expected.st_nlink!=1
        ||expected.st_uid!=geteuid()||(expected.st_mode&077)!=0) {
        if(lock>=0)close(lock);
        set_error("job-lock-invalid");return -1;
    }
    if(inherited){
        char *end=NULL;errno=0;long n=strtol(inherited,&end,10);
        if(errno||!end||*end||n<3||n>INT_MAX||fstat((int)n,&actual)
            ||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino) {
            close(lock);set_error("inherited-lock-invalid");return -1;
        }
        int copy=fcntl((int)n,F_DUPFD_CLOEXEC,3);close(lock);lock=copy;
        if(lock<0){set_error("inherited-lock-invalid");return -1;}
    }
    if(flock(lock,LOCK_EX|LOCK_NB)) {close(lock);set_error("scanner-or-update-busy");return -1;}
    return lock;
}
static const char *argument(int argc,char **argv,const char *flag) {
    for(int i=2;i<argc;i++) {
        if(!strcmp(argv[i],flag)&&i+1<argc)return argv[i+1];
    }
    return NULL;
}
static json_object *scan_one(struct cl_engine *engine,const struct generation *gen,
                             const char *profile,const char *input,const struct ci_limits *limits,int *result_code) {
    json_object *out=result_base(profile,gen->id);
    struct context ctx={json_object_new_array(),json_object_new_array(),0,false,false};
    bool reduced=!strcmp(profile,CI_PROFILE);int fd=-1,exitcode=2;
    set_error("");
    if(ci_cpu_budget_check(limits)){set_error("native-cpu-budget-exhausted");goto scan_done;}
    fd=open(input,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    struct stat before,after;
    if(fd<0||fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_size<0||(uint64_t)before.st_size>CI_MAX_FILE||((uint64_t)before.st_size>limits->file_bytes)){set_error("input-invalid-or-too-large");goto scan_done;}
    char before_hash[65],after_hash[65];uint64_t before_size=0,after_size=0;
    if(!digest_fd(fd,before_hash,&before_size)){set_error("input-hash-failed");goto scan_done;}
    add_s(out,"sha256",before_hash);add_n(out,"size",(int64_t)before_size);
    struct cl_scan_options opts={0};opts.parse=~0U;
    opts.general=CL_SCAN_GENERAL_HEURISTICS|CL_SCAN_GENERAL_ALLMATCHES|CL_SCAN_GENERAL_COLLECT_METADATA;
    opts.heuristic=CL_SCAN_HEURISTIC_EXCEEDS_MAX|CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE|CL_SCAN_HEURISTIC_ENCRYPTED_DOC|CL_SCAN_HEURISTIC_BROKEN|CL_SCAN_HEURISTIC_BROKEN_MEDIA;
    cl_verdict_t verdict=CL_VERDICT_NOTHING_FOUND;const char *name=NULL;char *root_type=NULL;uint64_t scanned=0;
    cl_error_t rc=cl_scandesc_ex(fd,input,&verdict,&name,&scanned,engine,&opts,&ctx,NULL,NULL,NULL,NULL,&root_type);
    bool intact=!fstat(fd,&after)&&digest_fd(fd,after_hash,&after_size)&&before_size==after_size&&!strcmp(before_hash,after_hash)
        &&before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_size==after.st_size
        &&before.st_mtim.tv_sec==after.st_mtim.tv_sec&&before.st_mtim.tv_nsec==after.st_mtim.tv_nsec
        &&before.st_ctim.tv_sec==after.st_ctim.tv_sec&&before.st_ctim.tv_nsec==after.st_ctim.tv_nsec;
    add_s(out,"root_type",root_type);add_n(out,"scanned_bytes",(int64_t)scanned);add_n(out,"native_status",rc);
    bool eligible_type=root_type&&(!strcmp(root_type,"CL_TYPE_PDF")||!strcmp(root_type,"CL_TYPE_JPEG")||!strcmp(root_type,"CL_TYPE_PNG"));
    free(root_type);
    if(!intact){set_error("input-changed-during-scan");goto scan_done;}
    if(ctx.bad_callback){set_error("scanner-metadata-invalid");goto scan_done;}
    bool success=rc==CL_SUCCESS||(rc==CL_VIRUS&&(verdict==CL_VERDICT_STRONG_INDICATOR||verdict==CL_VERDICT_POTENTIALLY_UNWANTED))||(rc==CL_ESTATE&&ctx.guard);
    if(!success){set_error("native-scan-failed");goto scan_done;}
    if(ci_cpu_budget_check(limits)){set_error("native-cpu-budget-exhausted");goto scan_done;}
    add_b(out,"completed",true);
    bool qualified=!reduced||(CI_REDUCED_COVERAGE_QUALIFIED&&gen->manifest_qualification);
    bool applicable=!reduced||(qualified&&!ctx.guard&&eligible_type);
    add_b(out,"coverage_qualified",qualified);add_b(out,"applicability_proven",applicable);
    if(ctx.guard)reason(&ctx,"excluded-pe-consumer-reached");
    if(reduced&&!eligible_type)reason(&ctx,"profile-root-type-unsupported");
    if(reduced&&!qualified)reason(&ctx,"reduced-profile-unqualified");
    bool detected=verdict==CL_VERDICT_STRONG_INDICATOR||verdict==CL_VERDICT_POTENTIALLY_UNWANTED;
    if(detected){add_s(out,"status","detected");exitcode=1;}
    else if(ctx.incomplete||!applicable||!qualified||json_object_array_length(ctx.findings)>0){add_s(out,"status","held");exitcode=3;}
    else{add_s(out,"status","clean");exitcode=0;}
    set_error("");
scan_done:
    if(exitcode==2&&*error_reason)reason(&ctx,error_reason);
    json_object_object_add(out,"findings",ctx.findings);json_object_object_add(out,"reason_codes",ctx.reasons);
    if(fd>=0)close(fd);
    *result_code=exitcode;return out;
}
/* Private pipe protocol for a trusted gateway: client filenames never reach this
 * interface. The loaded generation and profile are immutable for worker life.
 * CPU is a worker-lifetime budget; wall time is rearmed for every request. */
static int worker_loop(struct cl_engine *engine,const struct generation *gen,const char *generation,
                       const char *profile,const char *engine_hash,uint64_t max_age,
                       const struct ci_limits *limits,uint64_t max_requests) {
    char line[8192];
    for(uint64_t ordinal=0;ordinal<max_requests;ordinal++) {
        alarm((unsigned)limits->wall_seconds);
        size_t used=0;int c;
        while((c=fgetc(stdin))!=EOF) {
            if(!c||used>=sizeof(line)-1)return 2;
            line[used++]=(char)c;if(c=='\n')break;
        }
        if(!used&&c==EOF)return 0;
        if(!used||line[used-1]!='\n')return 2;
        line[used]=0;
        struct json_tokener *tok=json_tokener_new();if(!tok)return 2;
        json_tokener_set_flags(tok,JSON_TOKENER_STRICT|JSON_TOKENER_VALIDATE_UTF8);
        json_object *request=json_tokener_parse_ex(tok,line,(int)used);
        bool valid=json_tokener_get_error(tok)==json_tokener_success&&request&&json_object_is_type(request,json_type_object)
            &&json_object_object_length(request)==2;
        size_t end=json_tokener_get_parse_end(tok);while(end<used&&(line[end]==' '||line[end]=='\t'||line[end]=='\n'||line[end]=='\r'))end++;
        valid=valid&&end==used;json_tokener_free(tok);
        const char *job=valid?get_s(request,"request_id"):NULL,*input=valid?get_s(request,"input"):NULL;
        valid=valid&&job&&*job&&strlen(job)<=128&&input&&input[0]=='/'&&strlen(input)<PATH_MAX;
        if(valid)for(const unsigned char *p=(const unsigned char*)job;*p;p++)if(*p<32||*p==127)valid=false;
        if(!valid){if(request)json_object_put(request);return 2;}
        /* Waiting for a request and processing it have separate wall envelopes.
         * An original arriving near the idle deadline still gets its full job
         * allowance; CPU remains cumulative over the worker lifetime. */
        alarm((unsigned)limits->wall_seconds);
        struct generation checked={0};checked.dirfd=-1;
        bool same=verify_generation(&checked,generation,engine_hash,max_age)
            &&!strcmp(checked.id,gen->id)&&!strcmp(checked.manifest_sha256,gen->manifest_sha256);
        if(checked.manifest)json_object_put(checked.manifest);
        if(checked.dirfd>=0)close(checked.dirfd);
        int code=2;json_object *response;
        if(same)response=scan_one(engine,gen,profile,input,limits,&code);
        else{response=result_base(profile,gen->id);json_object *reasons=NULL;json_object_object_get_ex(response,"reason_codes",&reasons);
            json_object_array_add(reasons,json_object_new_string("worker-generation-changed-or-stale"));}
        add_s(response,"request_id",job);emit(response);json_object_put(request);
        if(!same||ci_cpu_budget_check(limits))return 2;
    }
    return 0;
}

#include "bounded.c"

int main(int argc,char **argv) {
    if(argc<2){fprintf(stderr,"usage: compact-scan scan|prepare|self-test|doctor --generation DIR [--input FILE] --certs DIR [--profile full|" CI_PROFILE "]\n");return 2;}
    const char *command=argv[1],*generation=argument(argc,argv,"--generation"),*certs=argument(argc,argv,"--certs");
    const char *profile=argument(argc,argv,"--profile");if(!profile)profile="full";
    const char *state=argument(argc,argv,"--state"),*inherited=argument(argc,argv,"--lock-fd");
    bool identity_only=!strcmp(command,"doctor")||!strcmp(command,"options");
    struct ci_limits limits={0};
    if(state&&(ci_limits_parse(argc,argv,&limits)||ci_limits_apply(&limits))) {
        json_object *o=result_base(profile,NULL);json_object *a=NULL;
        json_object_object_get_ex(o,"reason_codes",&a);json_object_array_add(a,json_object_new_string("native-limits-invalid"));emit_startup_failure(o);return 2;
    }
    if(!state){
        pid_t expected_parent;
        if(ci_expected_parent(&expected_parent)||ci_parent_death(expected_parent)){
            json_object *o=result_base(profile,NULL);json_object *a=NULL;
            json_object_object_get_ex(o,"reason_codes",&a);json_object_array_add(a,json_object_new_string("native-parent-invalid"));emit_startup_failure(o);return 2;
        }
    }
    /* Do not initialize parsers or hash the DSO while another job owns this
     * state. The descriptor intentionally lives through free() and atexit;
     * process exit releases it after the complete native lifetime. */
    if(state||!identity_only){
        int lock=acquire_lock(state,inherited);
        if(lock<0){json_object *o=result_base(profile,NULL);json_object *a=NULL;
            json_object_object_get_ex(o,"reason_codes",&a);json_object_array_add(a,json_object_new_string(error_reason));emit_startup_failure(o);return 2;}
    }
    if(!bootstrap_modules()||cl_init(CL_INIT_DEFAULT)!=CL_SUCCESS||!(cl_subset_runtime_capabilities()&1U)) {
        json_object *o=result_base(profile,NULL);json_object *a=NULL;json_object_object_get_ex(o,"reason_codes",&a);
        json_object_array_add(a,json_object_new_string("required-rar-parser-unavailable"));emit_startup_failure(o);return 2;
    }
    char hash[65]={0},options[65]={0};options_hash(options);
    if(!engine_identity(hash)){fprintf(stderr,"cannot bind loaded engine\n");return 2;}
    if(identity_only) {
        json_object *o=result_base(profile,NULL);add_s(o,"status","ready");add_b(o,"completed",true);
        add_s(o,"engine_sha256",hash);add_s(o,"scan_options_sha256",options);add_s(o,"scan_option_spec",option_spec);
        add_s(o,"guard_version",cl_subset_guard_version());add_s(o,"ordering_version",CI_ORDERING_VERSION);
        add_b(o,"reduced_build_qualified",CI_REDUCED_COVERAGE_QUALIFIED);add_b(o,"rar_parser_available",true);emit(o);return 0;
    }
    if(!strcmp(command,"prepare")) {
        if(!generation||!certs){fprintf(stderr,"prepare requires --generation and --certs\n");return 2;}
        uint64_t line_limit=0;
        if(ci_positive_number(argument(argc,argv,"--line-bytes"),&line_limit)) {
            json_object *o=result_base(profile,NULL);json_object *a=NULL;json_object_object_get_ex(o,"reason_codes",&a);
            json_object_array_add(a,json_object_new_string("line-limit-required"));emit(o);return 2;
        }
        return ci_prepare_generation_with_line_limit(generation,certs,line_limit);
    }
    if(!strcmp(command,"validate-bounded")) {
        if(!generation||!certs||!state){fprintf(stderr,"validate-bounded requires generation, certs, state and native resource limits\n");return 2;}
        return ci_validate_bounded(generation,certs,&limits);
    }
    json_object *out=result_base(profile,NULL);struct context ctx={json_object_new_array(),json_object_new_array(),0,false,false};
    struct generation gen={0};gen.dirfd=-1;struct skips skips={0};struct cl_engine *engine=NULL;int exitcode=2;
    bool reduced=!strcmp(profile,CI_PROFILE);
    if(strcmp(profile,"full")&&!reduced){set_error("unsupported-profile");goto done;}
    if(strcmp(command,"scan")&&strcmp(command,"worker")&&strcmp(command,"self-test")&&strcmp(command,"selftest")){set_error("unsupported-command");goto done;}
    if(!generation||!certs){set_error("missing-generation-or-certificates");goto done;}
    uint64_t max_age=48*3600;
    const char *age=argument(argc,argv,"--max-age-seconds");
    if(age&&ci_positive_number(age,&max_age)){set_error("database-age-limit-invalid");goto done;}
    if(!verify_generation(&gen,generation,hash,max_age))goto done;
    add_s(out,"generation_id",gen.id);
    const char *prepared_profile=get_s(gen.manifest,"profile");
    if(!prepared_profile||(strcmp(prepared_profile,"full")&&strcmp(prepared_profile,CI_PROFILE))
        ||(reduced&&strcmp(prepared_profile,CI_PROFILE))){set_error("generation-profile-mismatch");goto done;}
    if(reduced){json_object *files=NULL,*spec=NULL;json_object_object_get_ex(gen.manifest,"files",&files);
        if(!json_object_object_get_ex(files,"profile/skip.tsv",&spec)||!load_skips(&skips,gen.dirfd)) {set_error("profile-exclusions-invalid");goto done;}}
    engine=engine_load(generation,certs,reduced,&skips);
    if(!engine){set_error("database-load-or-compile-failed");goto done;}
    if(ci_cpu_budget_check(&limits)){set_error("native-cpu-budget-exhausted");goto done;}
    if(strcmp(command,"scan")&&strcmp(command,"worker")) {add_s(out,"status","ready");add_b(out,"completed",true);reason(&ctx,"selected-engine-load-and-compile-passed");exitcode=0;goto done;}
    if(!strcmp(command,"worker")) {
        uint64_t requests=0;
        if(ci_positive_number(argument(argc,argv,"--worker-max-requests"),&requests)){set_error("worker-request-limit-required");goto done;}
        json_object_put(out);out=NULL;
        json_object_put(ctx.findings);ctx.findings=NULL;json_object_put(ctx.reasons);ctx.reasons=NULL;
        exitcode=worker_loop(engine,&gen,generation,profile,hash,max_age,&limits,requests);goto done;
    }
    const char *input=argument(argc,argv,"--input");if(!input)input=argument(argc,argv,"--file");
    if(!input){set_error("missing-input");goto done;}
    json_object_put(out);out=scan_one(engine,&gen,profile,input,&limits,&exitcode);
    json_object_put(ctx.findings);ctx.findings=NULL;json_object_put(ctx.reasons);ctx.reasons=NULL;

done:
    if(out){
        if(ctx.reasons){if(exitcode==2&&*error_reason)reason(&ctx,error_reason);
            json_object_object_add(out,"findings",ctx.findings);json_object_object_add(out,"reason_codes",ctx.reasons);}
        emit(out);
    }
    if(engine)cl_engine_free(engine);
    free(skips.keys);free(skips.bytes);
    if(gen.manifest)json_object_put(gen.manifest);
    if(gen.dirfd>=0)close(gen.dirfd);
    return exitcode;
}
