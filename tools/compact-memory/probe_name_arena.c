/* SPDX-License-Identifier: GPL-2.0-only
 * Diagnostic only: copy hash names after compilation, then release old pool
 * fragments. The existing destructor does not own this layout: deliberately
 * exit without freeing the engine in BOTH modes. Not a deployable engine patch.
 * Emits aggregate counts and hashes only, never signature strings/addresses.
 */
#define _GNU_SOURCE
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "mpool.h"
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <openssl/evp.h>

static size_t name_count, name_bytes;
static char *arena;
static size_t cursor;
static EVP_MD_CTX *digest;

static double now(void) {struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t)); return t.tv_sec+t.tv_nsec*1e-9;}
static long rss(void) {FILE *f=fopen("/proc/self/status","r");char line[256];long n=-1;assert(f);while(fgets(line,sizeof line,f))if(sscanf(line,"VmRSS: %ld kB",&n)==1)break;fclose(f);return n;}
static void memory(const char *phase,const struct cl_engine *e) {
    struct rusage u;size_t carved=0,mapped=0;assert(!getrusage(RUSAGE_SELF,&u));assert(!mpool_getstats(e,&carved,&mapped));
    printf("{\"kind\":\"memory\",\"phase\":\"%s\",\"rss_bytes\":%ld,\"hwm_bytes\":%ld,\"pool_carved_bytes\":%zu,\"pool_mapped_bytes\":%zu}\n",phase,rss()*1024,u.ru_maxrss*1024,carved,mapped);fflush(stdout);
}
static void each(struct cl_engine *e, void (*visit)(mpool_t *,const char **)) {
    struct cli_matcher *roots[]={e->hm_hdb,e->hm_mdb,e->hm_imp,e->hm_fp};
    for(size_t r=0;r<sizeof(roots)/sizeof(roots[0]);r++) {
        struct cli_matcher *root=roots[r];if(!root)continue;assert(!root->hm.compiled);
        for(unsigned type=0;type<CLI_HASH_AVAIL_TYPES;type++) {
            const struct cli_htu32 *ht=&root->hm.sizehashes[type];
            for(size_t i=0;i<ht->capacity;i++) {
                if(!ht->htable[i].key||ht->htable[i].key==UINT32_MAX)continue;
                struct cli_sz_hash *s=ht->htable[i].data.as_ptr;
                for(uint32_t j=0;j<s->items;j++)visit(root->mempool,&s->virusnames[j]);
            }
            struct cli_sz_hash *s=&root->hwild.hashes[type];
            for(uint32_t j=0;j<s->items;j++)visit(root->mempool,&s->virusnames[j]);
        }
    }
}
static void count(mpool_t *mp,const char **slot) {(void)mp;if(*slot){size_t n=strlen(*slot)+1;assert(name_bytes<=SIZE_MAX-n);name_bytes+=n;name_count++;}}
static uintptr_t *pointers;static size_t pointer_at;
static void collect(mpool_t *mp,const char **slot) {(void)mp;if(*slot)pointers[pointer_at++]=(uintptr_t)*slot;}
static int pointer_compare(const void *a,const void *b) {uintptr_t x=*(const uintptr_t *)a,y=*(const uintptr_t *)b;return x>y?1:x<y?-1:0;}
static void hash_name(mpool_t *mp,const char **slot) {
    (void)mp;uint64_t length=*slot?strlen(*slot)+1:0;unsigned char wire[8];
    for(unsigned i=0;i<8;i++)wire[i]=(unsigned char)(length>>(8*i));
    assert(EVP_DigestUpdate(digest,wire,sizeof wire));if(length)assert(EVP_DigestUpdate(digest,*slot,length));
}
static void hash_all(struct cl_engine *e,char out[65]) {
    unsigned char sum[32];unsigned n;digest=EVP_MD_CTX_new();assert(digest);assert(EVP_DigestInit_ex(digest,EVP_sha256(),NULL));
    each(e,hash_name);assert(EVP_DigestFinal_ex(digest,sum,&n)&&n==32);EVP_MD_CTX_free(digest);
    for(unsigned i=0;i<32;i++)sprintf(out+i*2,"%02x",sum[i]);out[64]=0;
}
static void copy_name(mpool_t *mp,const char **slot) {
    if(!*slot)return;size_t n=strlen(*slot)+1;assert(cursor<=name_bytes-n);
    memcpy(arena+cursor,*slot,n);mpool_free(mp,(void *)*slot);*slot=arena+cursor;cursor+=n;
}
int main(int argc,char **argv) {
    if(argc!=4){fprintf(stderr,"usage: %s DB CERTS MODE(control|pack)\n",argv[0]);return 2;}
    int pack=!strcmp(argv[3],"pack");assert(pack||!strcmp(argv[3],"control"));
    assert(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);struct cl_engine *e=cl_engine_new();assert(e);
    assert(cl_engine_set_num(e,CL_ENGINE_DISABLE_CACHE,1)==CL_SUCCESS);assert(cl_engine_set_str(e,CL_ENGINE_CVDCERTSDIR,argv[2])==CL_SUCCESS);
    unsigned signatures=0;double start=now();assert(cl_load(argv[1],e,&signatures,CL_DB_STDOPT)==CL_SUCCESS);
    assert(cl_engine_compile(e)==CL_SUCCESS);double compiled=now();memory("compiled",e);
    each(e,count);assert(name_count<=SIZE_MAX/sizeof(*pointers));pointers=malloc(name_count*sizeof(*pointers));assert(pointers);each(e,collect);assert(pointer_at==name_count);
    qsort(pointers,name_count,sizeof(*pointers),pointer_compare);size_t aliases=0;for(size_t i=1;i<name_count;i++)aliases+=pointers[i]==pointers[i-1];
    free(pointers);pointers=NULL;assert(!aliases);char before[65],after[65];hash_all(e,before);memory("validated",e);
    double transfer=now();if(pack){arena=malloc(name_bytes);assert(arena);each(e,copy_name);assert(cursor==name_bytes);mpool_flush(e->mempool);}
    double transferred=now();memory(pack?"packed":"control",e);hash_all(e,after);assert(!strcmp(before,after));
    printf("{\"kind\":\"result\",\"mode\":\"%s\",\"signatures\":%u,\"name_records\":%zu,\"name_payload_bytes\":%zu,\"original_pointer_aliases\":%zu,\"distinct_occurrences_preserved\":true,\"ordered_names_sha256\":\"%s\",\"every_name_exact\":true,\"load_compile_seconds\":%.9f,\"transfer_seconds\":%.9f,\"engine_destructor_supported\":false,\"scope\":\"postcompile hash-name allocation-residency experiment, not integrated scanner or performance qualification\"}\n",argv[3],signatures,name_count,name_bytes,aliases,after,compiled-start,transferred-transfer);fflush(stdout);
    return 0;
}
