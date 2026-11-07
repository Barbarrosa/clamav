/* SPDX-License-Identifier: GPL-2.0-only
 * Destructive, isolated-process token storage feasibility probe.
 *
 * IMPORTANT: after repacking, the engine is NOT a scanner. It has byte token
 * storage without a corresponding verifier format change. Only exact token
 * reconstruction, allocator residency, and ordinary destruction are tested.
 * Signed source databases are read only and preserved.
 */
#define _GNU_SOURCE
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "mpool.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "token-probe: %s\n", #x); exit(2); } } while (0)

static double wall(void)
{
    struct timespec t;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static long resident_kib(void)
{
    char line[256];
    long result = -1;
    FILE *f = fopen("/proc/self/status", "r");
    CHECK(f);
    while (fgets(line, sizeof line, f)) if (sscanf(line, "VmRSS: %ld kB", &result) == 1) break;
    fclose(f);
    CHECK(result > 0);
    return result;
}

static void snapshot(const char *phase, struct cl_engine *engine)
{
    size_t carved = 0, mapped = 0;
    struct rusage usage;
    CHECK(!getrusage(RUSAGE_SELF, &usage));
    if (engine) CHECK(!mpool_getstats(engine, &carved, &mapped));
    printf("{\"kind\":\"memory\",\"phase\":\"%s\",\"rss_kib\":%ld,\"hwm_kib\":%ld,"
           "\"pool_carved_bytes\":%zu,\"pool_mapped_bytes\":%zu}\n",
           phase, resident_kib(), usage.ru_maxrss, carved, mapped);
    fflush(stdout);
}

static uint64_t hash_token(uint64_t h, uint16_t value)
{
    h = (h ^ (value & 255)) * UINT64_C(1099511628211);
    return (h ^ (value >> 8)) * UINT64_C(1099511628211);
}

int main(int argc, char **argv)
{
    struct cl_engine *engine;
    unsigned signatures = 0;
    uint64_t patterns = 0, eligible = 0, skipped = 0, tokens = 0;
    uint64_t old_bytes = 0, requested_bytes = 0, reconstruction_hash = UINT64_C(1469598103934665603);
    double start, loaded, compiled, converted;
    int force_ac;
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s DB CERTS control|pool-byte|heap-byte [force-ac]\n", argv[0]);
        return 2;
    }
    CHECK(!strcmp(argv[3], "control") || !strcmp(argv[3], "pool-byte") || !strcmp(argv[3], "heap-byte"));
    force_ac = argc == 5 && !strcmp(argv[4], "force-ac");
    CHECK(cl_init(CL_INIT_DEFAULT) == CL_SUCCESS);
    engine = cl_engine_new(); CHECK(engine);
    CHECK(cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, argv[2]) == CL_SUCCESS);
    CHECK(cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1) == CL_SUCCESS);
    if (force_ac) CHECK(cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1) == CL_SUCCESS);
    start = wall();
    CHECK(cl_load(argv[1], engine, &signatures, CL_DB_STDOPT) == CL_SUCCESS);
    loaded = wall();
    CHECK(cl_engine_compile(engine) == CL_SUCCESS);
    compiled = wall();
    snapshot("compiled", engine);

    /* heap-byte keeps a separate owner vector because the normal destructor
     * uses mpool_free. Its size is explicit and counts against the result. */
    size_t capacity = 0, heap_count = 0;
    for (unsigned t = 0; t < CLI_MTARGETS; t++) if (engine->root[t]) capacity += engine->root[t]->ac_patterns;
    void **heap_owners = !strcmp(argv[3], "heap-byte") ? calloc(capacity ? capacity : 1, sizeof(void *)) : NULL;
    CHECK(strcmp(argv[3], "heap-byte") || heap_owners);

    for (unsigned t = 0; t < CLI_MTARGETS; t++) {
        struct cli_matcher *root = engine->root[t];
        if (!root) continue;
        for (unsigned i = 0; i < root->ac_patterns; i++) {
            struct cli_ac_patt *p = root->ac_pattable[i];
            uint16_t *old = p->prefix ? p->prefix : p->pattern;
            size_t count = (size_t)p->prefix_length[0] + p->length[0];
            int pure = 1;
            patterns++;
            CHECK(old || !count);
            CHECK(p->prefix || !p->prefix_length[0]);
            CHECK(p->pattern == old + p->prefix_length[0]);
            for (size_t j = 0; j < count; j++) if (old[j] > 255) { pure = 0; break; }
            if (!pure) { skipped++; continue; }
            eligible++;
            tokens += count;
            old_bytes += count * sizeof(uint16_t);
            /* Preserve at least uint16_t pointer alignment, even though only
             * byte loads will be used by the hypothetical future reader. */
            size_t bytes = (count + 2) & ~(size_t)1;
            requested_bytes += bytes;
            uint64_t before_hash = reconstruction_hash;
            for (size_t j = 0; j < count; j++) before_hash = hash_token(before_hash, old[j]);
            if (strcmp(argv[3], "control")) {
                unsigned char *repacked = !strcmp(argv[3], "pool-byte") ? mpool_malloc(root->mempool, bytes) : malloc(bytes);
                CHECK(repacked);
                for (size_t j = 0; j < count; j++) repacked[j] = (unsigned char)old[j];
                memset(repacked + count, 0, bytes - count);
                uint64_t after_hash = reconstruction_hash;
                for (size_t j = 0; j < count; j++) {
                    CHECK((uint16_t)repacked[j] == old[j]);
                    after_hash = hash_token(after_hash, repacked[j]);
                }
                CHECK(before_hash == after_hash);
                mpool_free(root->mempool, old);
                if (!strcmp(argv[3], "heap-byte")) {
                    heap_owners[heap_count++] = repacked;
                    /* Remove pool ownership from this isolated engine. No
                     * scanner invocation is allowed after this phase. */
                    p->pattern = p->prefix = NULL;
                } else {
                    p->pattern = (uint16_t *)repacked;
                    if (p->prefix) p->prefix = (uint16_t *)repacked;
                }
            }
            reconstruction_hash = before_hash;
        }
    }
    converted = wall();
    snapshot("after_conversion_before_flush", engine);
    mpool_flush(engine->mempool);
    snapshot("after_conversion_and_flush", engine);
    printf("{\"kind\":\"result\",\"mode\":\"%s\",\"signatures\":%u,\"patterns\":%llu,"
           "\"eligible_patterns\":%llu,\"tagged_patterns_kept_wide\":%llu,\"eligible_tokens\":%llu,"
           "\"original_eligible_token_payload_bytes\":%llu,\"new_eligible_request_bytes\":%llu,"
           "\"heap_owner_directory_bytes\":%zu,\"reconstruction_hash\":\"%016llx\","
           "\"load_seconds\":%.9f,\"compile_seconds\":%.9f,\"conversion_seconds\":%.9f,"
           "\"every_repacked_token_exact\":true,\"scanner_compatible_after_conversion\":%s,"
           "\"scope\":\"isolated destructive storage feasibility probe; no optimized scanner or performance qualification\"}\n",
           argv[3], signatures, (unsigned long long)patterns, (unsigned long long)eligible,
           (unsigned long long)skipped, (unsigned long long)tokens, (unsigned long long)old_bytes,
           (unsigned long long)requested_bytes, heap_owners ? capacity * sizeof(void *) : 0,
           (unsigned long long)reconstruction_hash, loaded - start, compiled - loaded, converted - compiled,
           !strcmp(argv[3], "control") ? "true" : "false");
    fflush(stdout);
    cl_engine_free(engine);
    for (size_t i = 0; i < heap_count; i++) free(heap_owners[i]);
    free(heap_owners);
    snapshot("all_freed", NULL);
    return 0;
}
