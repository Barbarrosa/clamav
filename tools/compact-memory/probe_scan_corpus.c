/* SPDX-License-Identifier: GPL-2.0-only
 * Public-API differential scan probe. Ordered callback names and final return
 * names/codes feed a SHA-256 transcript. Same corpus/order/options in both builds.
 */
#include "clamav.h"
#include <openssl/evp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
struct transcript { EVP_MD_CTX *hash; unsigned long callbacks; };
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static long rss(void){FILE *f=fopen("/proc/self/status","r");char line[128];long n=-1;if(!f)return n;while(fgets(line,sizeof(line),f))if(sscanf(line,"VmRSS: %ld kB",&n)==1)break;fclose(f);return n;}
static void string(EVP_MD_CTX *h,const char *s){unsigned char present=!!s;assert(EVP_DigestUpdate(h,&present,1)==1);if(s)assert(EVP_DigestUpdate(h,s,strlen(s)+1)==1);}
static void found(int fd,const char *name,void *opaque){(void)fd;struct transcript *t=opaque;t->callbacks++;string(t->hash,name);}
int main(int argc,char **argv){
    if(argc!=4)return 2;
    assert(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);struct cl_engine *e=cl_engine_new();assert(e);
    assert(cl_engine_set_str(e,CL_ENGINE_CVDCERTSDIR,argv[2])==CL_SUCCESS);
    assert(cl_engine_set_num(e,CL_ENGINE_DISABLE_CACHE,1)==CL_SUCCESS);
    cl_engine_set_clcb_virus_found(e,found);
    unsigned signatures=0;double start=now();assert(cl_load(argv[1],e,&signatures,CL_DB_STDOPT)==CL_SUCCESS);double loaded=now();
    if(getenv("PROBE_DEBUG_COMPILE"))cl_debug();
    assert(cl_engine_compile(e)==CL_SUCCESS);double compiled=now();long compiled_rss=rss();struct rusage usage;assert(!getrusage(RUSAGE_SELF,&usage));
    printf("{\"kind\":\"engine\",\"signatures\":%u,\"load_seconds\":%.9f,\"compile_seconds\":%.9f,\"compiled_rss_kib\":%ld,\"compile_peak_rss_kib\":%ld}\n",signatures,loaded-start,compiled-loaded,compiled_rss,usage.ru_maxrss);
    FILE *list=fopen(argv[3],"r");assert(list);char **paths=NULL;size_t count=0;char line[8192];
    while(fgets(line,sizeof(line),list)){size_t n=strlen(line);assert(n&&line[n-1]=='\n');line[n-1]=0;paths=realloc(paths,(count+1)*sizeof(*paths));assert(paths);paths[count++]=strdup(line);assert(paths[count-1]);}fclose(list);
    for(unsigned mode=0;mode<2;mode++){
        struct transcript t={EVP_MD_CTX_new(),0};assert(t.hash);assert(EVP_DigestInit_ex(t.hash,EVP_sha256(),NULL)==1);
        struct cl_scan_options options={0};options.parse=~0U;options.general=CL_SCAN_GENERAL_HEURISTICS|(mode?CL_SCAN_GENERAL_ALLMATCHES:0);
        unsigned long scanned=0,viruses=0,errors=0;start=now();
        for(size_t i=0;i<count;i++){
            const char *name=NULL;unsigned long before=t.callbacks;
            cl_error_t ret=cl_scanfile_callback(paths[i],&name,&scanned,e,&options,&t);
            unsigned char code[4]={(unsigned char)ret,(unsigned char)(ret>>8),0,0};
            assert(EVP_DigestUpdate(t.hash,code,sizeof(code))==1);string(t.hash,name);
            unsigned long events=t.callbacks-before;assert(EVP_DigestUpdate(t.hash,&events,sizeof(events))==1);
            viruses+=ret==CL_VIRUS;errors+=ret!=CL_VIRUS&&ret!=CL_CLEAN;
        }
        double elapsed=now()-start;unsigned char digest[32];unsigned length;assert(EVP_DigestFinal_ex(t.hash,digest,&length)==1);EVP_MD_CTX_free(t.hash);char hex[65];for(unsigned i=0;i<32;i++)sprintf(hex+2*i,"%02x",digest[i]);
        printf("{\"kind\":\"scan_corpus\",\"allmatch\":%u,\"files\":%zu,\"virus_files\":%lu,\"errors\":%lu,\"callbacks\":%lu,\"transcript_sha256\":\"%s\",\"seconds\":%.9f,\"rss_kib\":%ld}\n",mode,count,viruses,errors,t.callbacks,hex,elapsed,rss());
    }
    for(size_t i=0;i<count;i++)free(paths[i]);free(paths);cl_engine_free(e);return 0;
}
