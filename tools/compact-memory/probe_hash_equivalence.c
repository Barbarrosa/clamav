/* SPDX-License-Identifier: GPL-2.0-only
 * Build separately against baseline and fork. Hash exact return codes/names
 * for canonical present, mutated-digest and alternate-size queries. Raw
 * signatures and names are never written by this diagnostic.
 */
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include <openssl/evp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

struct query { uint32_t size; unsigned char purpose, type, digest[32]; };
static struct query *queries;
static size_t count, capacity;
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9; }
static long rss(void) {
    FILE *f=fopen("/proc/self/status","r");char line[256];long n=-1;
    if(!f)return -1;
    while(fgets(line,sizeof(line),f))if(sscanf(line,"VmRSS: %ld kB",&n)==1)break;
    fclose(f);return n;
}
static void add(unsigned purpose,unsigned type,uint32_t size,const uint8_t *d) {
    if(count==capacity) {capacity=capacity?capacity*2:4096;queries=realloc(queries,capacity*sizeof(*queries));assert(queries);}
    struct query *q=&queries[count++];memset(q,0,sizeof(*q));q->purpose=purpose;q->type=type;q->size=size;memcpy(q->digest,d,cli_hash_len(type));
}
static void collect(struct cli_matcher *r,unsigned purpose) {
    if(!r)return;
    for(unsigned t=0;t<CLI_HASH_AVAIL_TYPES;t++) {
#ifdef ENABLE_FLAT_HASH_STORE
        if(r->hm.compiled) {
            const struct cli_hash_compiled *g=&r->hm.compiled[t];
            const struct cli_htu32_element *slot=NULL;
            while((slot=cli_htu32_next(&g->directory,slot))) {
                size_t b=slot->data.as_size_t;
                for(size_t j=g->starts[b];j<g->starts[b+1];j++)add(purpose,t,slot->key,g->hashes+j*cli_hash_len(t));
            }
            for(size_t j=g->starts[g->buckets];j<g->items;j++)add(purpose,t,0,g->hashes+j*cli_hash_len(t));
            continue;
        }
#endif
        const struct cli_htu32_element *item=NULL;
        while((item=cli_htu32_next(&r->hm.sizehashes[t],item))) {
            const struct cli_sz_hash *s=item->data.as_ptr;
            for(size_t j=0;j<s->items;j++)add(purpose,t,item->key,s->hash_array+j*cli_hash_len(t));
        }
        const struct cli_sz_hash *s=&r->hwild.hashes[t];
        for(size_t j=0;j<s->items;j++)add(purpose,t,0,s->hash_array+j*cli_hash_len(t));
    }
}
static int cmp(const void *a,const void *b) {
    const struct query *x=a,*y=b;
    if(x->purpose!=y->purpose)return (x->purpose>y->purpose)-(x->purpose<y->purpose);
    if(x->type!=y->type)return (x->type>y->type)-(x->type<y->type);
    if(x->size!=y->size)return (x->size>y->size)-(x->size<y->size);
    return memcmp(x->digest,y->digest,32);
}
static uint64_t random64(uint64_t *s){*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;return *s;}
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    assert(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);
    struct cl_engine *e=cl_engine_new();assert(e);
    assert(cl_engine_set_str(e,CL_ENGINE_CVDCERTSDIR,argv[2])==CL_SUCCESS);
    assert(cl_engine_set_num(e,CL_ENGINE_DISABLE_CACHE,1)==CL_SUCCESS);
    unsigned signatures=0;double start=now();
    assert(cl_load(argv[1],e,&signatures,CL_DB_STDOPT)==CL_SUCCESS);
    double loaded=now();long load_rss=rss();
    assert(cl_engine_compile(e)==CL_SUCCESS);
    double compiled=now();long compile_rss=rss();struct rusage usage;assert(!getrusage(RUSAGE_SELF,&usage));
    struct cli_matcher *roots[]={e->hm_hdb,e->hm_mdb,e->hm_imp,e->hm_fp};
    for(unsigned p=0;p<4;p++)collect(roots[p],p);
    qsort(queries,count,sizeof(*queries),cmp);
    EVP_MD_CTX *hash=EVP_MD_CTX_new();assert(hash);assert(EVP_DigestInit_ex(hash,EVP_sha256(),NULL)==1);
    uint64_t hits[3]={0,0,0};
    for(size_t i=0;i<count;i++)for(unsigned variant=0;variant<3;variant++) {
        const struct query *q=&queries[i];uint8_t unaligned[33];memcpy(unaligned+1,q->digest,32);
        uint32_t size=q->size;
        if(variant==1)unaligned[cli_hash_len(q->type)]^=1;
        if(variant==2)size=size==UINT32_MAX-1?1:size+1;
        const char *name="UNCHANGED";
        cl_error_t r=size?cli_hm_scan(unaligned+1,size,&name,roots[q->purpose],q->type):cli_hm_scan_wild(unaligned+1,&name,roots[q->purpose],q->type);
        unsigned char code[2]={(unsigned char)r,(unsigned char)!!name};
        assert(EVP_DigestUpdate(hash,code,sizeof(code))==1);
        if(name)assert(EVP_DigestUpdate(hash,name,strlen(name)+1)==1);
        hits[variant]+=r==CL_VIRUS;
    }
    unsigned char digest[32];unsigned length;assert(EVP_DigestFinal_ex(hash,digest,&length)==1);EVP_MD_CTX_free(hash);
    char hex[65];for(unsigned i=0;i<32;i++)sprintf(hex+2*i,"%02x",digest[i]);
    printf("{\"kind\":\"hash_equivalence\",\"signatures\":%u,\"records\":%zu,\"queries\":%zu,\"result_sha256\":\"%s\",\"hits\":[%llu,%llu,%llu],\"load_seconds\":%.9f,\"compile_seconds\":%.9f,\"load_rss_kib\":%ld,\"compiled_rss_kib\":%ld,\"compile_peak_rss_kib\":%ld}\n",signatures,count,count*3,hex,(unsigned long long)hits[0],(unsigned long long)hits[1],(unsigned long long)hits[2],loaded-start,compiled-loaded,load_rss,compile_rss,usage.ru_maxrss);
    for(unsigned mode=0;mode<4;mode++)for(unsigned rep=0;rep<8;rep++) {
        uint64_t state=12345,sum=0;start=now();
        for(unsigned i=0;i<262144;i++) {
            size_t index=mode==2?i%32:mode==1?i%count:random64(&state)%count;
            const struct query *q=&queries[index];uint32_t size=mode==3?q->size^0x40000000:q->size;
            sum+=cli_hm_have_size(roots[q->purpose],q->type,size);
        }
        printf("{\"kind\":\"size_lookup\",\"mode\":%u,\"repeat\":%u,\"ns_per_query\":%.4f,\"checksum\":%llu}\n",mode,rep,(now()-start)*1e9/262144,(unsigned long long)sum);
    }
    free(queries);cl_engine_free(e);return 0;
}
