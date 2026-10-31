/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production matcher with allocation injection at its compiled
 * store allocations. Include the implementation so static builder sorting is
 * available as a reference; also run the separate baseline differential probe.
 */
#include "clamav-config.h"
#include "matcher.h"
#include "others.h"
#include "str.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static long fail_at = -1, allocation;
static void *injected_malloc(size_t n)
{
    if (fail_at >= 0 && allocation++ == fail_at) return NULL;
    return malloc(n);
}
static void *injected_calloc(size_t n, size_t w)
{
    if (fail_at >= 0 && allocation++ == fail_at) return NULL;
    return calloc(n, w);
}
#define malloc injected_malloc
#define calloc injected_calloc
#ifdef TEST_LEGACY_HASH
#undef ENABLE_FLAT_HASH_STORE
#endif
#include "../../libclamav/matcher-hash.c"
#undef malloc
#undef calloc

static void init(struct cl_engine *e)
{
    memset(e, 0, sizeof(*e));
#ifdef USE_MPOOL
    e->mempool = mpool_create();
    assert(e->mempool);
#endif
    struct cli_matcher *root;
    assert(hm_root(e,HASH_PURPOSE_WHOLE_FILE_DETECT,&root)==CL_SUCCESS);
}
static void destroy(struct cl_engine *e)
{
    hm_free(e->hm_hdb);
    MPOOL_FREE(e->mempool, e->hm_hdb);
#ifdef USE_MPOOL
    mpool_destroy(e->mempool);
#endif
}
static void digest(unsigned i, uint8_t *p)
{
    for (unsigned j = 0; j < 32; j++) p[j] = (uint8_t)(i * 73 + j * 19);
    memcpy(p + 9, &i, sizeof(i));
}
static void populate(struct cl_engine *e)
{
    for (unsigned t = 0; t < CLI_HASH_AVAIL_TYPES; t++) {
        for (unsigned i = 0; i < 257; i++) {
            uint8_t d[32]; char name[48];
            digest(i, d);
            snprintf(name, sizeof(name), "Hash.%u.%u", t, i);
            const char *copy = i == 19 ? NULL : CLI_MPOOL_STRDUP(e->hm_hdb->mempool, i == 20 ? "" : name);
            assert(i == 19 || copy);
            assert(hm_addhash_bin(e, HASH_PURPOSE_WHOLE_FILE_DETECT, d, t,
                                 i % 11 ? (i % 31) + 1 : 0, copy) == CL_SUCCESS);
        }
        uint8_t d[32]; digest(700, d);
        for (unsigned i = 0; i < 7; i++) {
            char name[32]; snprintf(name, sizeof(name), "Duplicate.%u", i);
            char *copy = CLI_MPOOL_STRDUP(e->hm_hdb->mempool, name); assert(copy);
            assert(hm_addhash_bin(e, HASH_PURPOSE_WHOLE_FILE_DETECT, d, t, 999, copy) == CL_SUCCESS);
        }
    }
}
static void compare(struct cli_matcher *a, struct cli_matcher *b)
{
    for (unsigned t = 0; t < CLI_HASH_AVAIL_TYPES; t++) {
        assert(cli_hm_have_any(a,t) == cli_hm_have_any(b,t));
        assert(cli_hm_have_wild(a,t) == cli_hm_have_wild(b,t));
        for (unsigned i = 0; i < 704; i++) {
            uint8_t unaligned[33]; digest(i, unaligned + 1);
            uint32_t sizes[] = {0, 1, (i % 31) + 1, 999, UINT32_MAX - 1, UINT32_MAX};
            for (unsigned k = 0; k < sizeof(sizes)/sizeof(*sizes); k++) {
                const char *x = "unchanged", *y = "unchanged";
                assert(cli_hm_have_size(a,t,sizes[k]) == cli_hm_have_size(b,t,sizes[k]));
                cl_error_t u = cli_hm_scan(unaligned+1,sizes[k],&x,a,t);
                cl_error_t v = cli_hm_scan(unaligned+1,sizes[k],&y,b,t);
                assert(u == v && ((!x && !y) || (x && y && !strcmp(x,y))));
                assert(cli_hm_scan(unaligned+1,sizes[k],NULL,b,t) == v);
            }
            const char *x = "unchanged", *y = "unchanged";
            assert(cli_hm_scan_wild(unaligned+1,&x,a,t) == cli_hm_scan_wild(unaligned+1,&y,b,t));
            assert((!x && !y) || (x && y && !strcmp(x,y)));
        }
    }
}
int main(void)
{
    struct cl_engine oracle; init(&oracle); populate(&oracle); hm_sort_all(oracle.hm_hdb);
#ifdef TEST_LEGACY_HASH
    struct cl_engine legacy; init(&legacy); populate(&legacy);
    assert(hm_flush(legacy.hm_hdb)==CL_SUCCESS);
    compare(oracle.hm_hdb,legacy.hm_hdb);
    assert(!legacy.hm_hdb->hm.compiled);
    destroy(&legacy); destroy(&oracle);
    puts("{\"legacy_layout_verified\":true,\"differential_queries\":12672}");
    return 0;
#else
    long failures = 0;
    for (long n = 0; n < 100; n++) {
        struct cl_engine candidate; init(&candidate); populate(&candidate);
        fail_at = n; allocation = 0;
        cl_error_t r = hm_flush(candidate.hm_hdb);
        fail_at = -1;
        if (r == CL_EMEM) {
            assert(!candidate.hm_hdb->hm.compiled);
            /* A retry must behave as if the failed attempt never sorted. */
            assert(hm_flush(candidate.hm_hdb) == CL_SUCCESS);
            failures++;
        } else assert(r == CL_SUCCESS);
        compare(oracle.hm_hdb,candidate.hm_hdb);
        uint8_t d[32]; digest(700,d); const char *saved=NULL;
        assert(cli_hm_scan(d,999,&saved,candidate.hm_hdb,0) == CL_VIRUS);
        assert(saved && !strcmp(saved,"Duplicate.4"));
        assert(hm_flush(candidate.hm_hdb) == CL_SUCCESS); /* idempotent */
        compare(oracle.hm_hdb,candidate.hm_hdb);
        assert(!strcmp(saved,"Duplicate.4")); /* borrowed pointer survives */
        destroy(&candidate);
        if (r == CL_SUCCESS) break;
    }
    assert(failures > 0);
    destroy(&oracle);
    struct cl_engine e; init(&e);
    uint8_t d[32]; digest(1,d);
    size_t length = 0x1000000;
    char *large = MPOOL_MALLOC(e.hm_hdb->mempool,length+1); assert(large);
    memset(large,'A',length); large[length]=0;
    assert(hm_addhash_bin(&e,HASH_PURPOSE_WHOLE_FILE_DETECT,d,0,1,large)==CL_SUCCESS);
    digest(2,d); char *small = CLI_MPOOL_STRDUP(e.hm_hdb->mempool,"after-24-bit-boundary"); assert(small);
    assert(hm_addhash_bin(&e,HASH_PURPOSE_WHOLE_FILE_DETECT,d,0,2,small)==CL_SUCCESS);
    assert(hm_flush(e.hm_hdb)==CL_SUCCESS);
    assert(e.hm_hdb->hm.compiled[0].name_width==4);
    const char *name=NULL;
    assert(cli_hm_scan(d,2,&name,e.hm_hdb,0)==CL_VIRUS);
    assert(!strcmp(name,"after-24-bit-boundary"));
    destroy(&e);
    init(&e);
    char official[]="Official.Test (Clam)", unofficial[]="Local.Test";
    const char *hex="00000000000000000000000000000000";
    assert(hm_addhash_str(&e,HASH_PURPOSE_WHOLE_FILE_DETECT,hex,42,official,1)==CL_SUCCESS);
    assert(hm_addhash_str(&e,HASH_PURPOSE_WHOLE_FILE_DETECT,hex,43,unofficial,0)==CL_SUCCESS);
    assert(hm_addhash_str(&e,HASH_PURPOSE_WHOLE_FILE_DETECT,"bad",44,"",1)==CL_EMALFDB);
    assert(hm_addhash_str(&e,HASH_PURPOSE_WHOLE_FILE_DETECT,"bad",44,"Valid",1)==CL_EARG);
    assert(hm_flush(e.hm_hdb)==CL_SUCCESS);
    memset(d,0,sizeof(d));
    assert(cli_hm_scan(d,42,&name,e.hm_hdb,0)==CL_VIRUS && !strcmp(name,"Official.Test"));
    assert(cli_hm_scan(d,43,&name,e.hm_hdb,0)==CL_VIRUS && !strcmp(name,"Local.Test.UNOFFICIAL"));
    assert(!strcmp(unofficial,"Local.Test"));
    destroy(&e);
    printf("{\"allocation_failures_retried\":%ld,\"differential_queries_per_comparison\":12672,\"unaligned_digests\":true,\"duplicate_selection\":true,\"null_and_empty_names\":true,\"stable_name_pointer\":true,\"wide_name_offsets\":true}\n",failures);
    return 0;
#endif
}
