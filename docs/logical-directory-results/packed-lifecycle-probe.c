#define _GNU_SOURCE
#include "clamav-config.h"
#include "others.h"
#include "matcher-ac.h"
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
static cl_error_t observed_compile(struct cl_engine *engine) {
    cl_error_t result=cl_engine_compile(engine);unsigned i;
    if(result!=CL_SUCCESS)return result;
    for(i=0;i<CLI_MTARGETS;i++) {
        struct cli_matcher *r=engine->root[i];unsigned packed=0;size_t bytes,pages,j,resident=0;long page;uintptr_t start;unsigned char *vec;
        if(!r||!r->ac_lsigtable||!r->ac_lsigs)continue;
#if defined(ENABLE_LSIG_DIRECTORY_IDS) && SIZEOF_VOID_P == 8
        packed=!!(r->ac_heap_tables & CLI_AC_LSIG_DIRECTORY_PACKED);
        bytes=cli_ac_lsig_directory_bytes(r);
#else
        bytes=(size_t)r->ac_lsigs*sizeof(*r->ac_lsigtable);
#endif
        page=sysconf(_SC_PAGESIZE);if(page<=0)return CL_EARG;
        start=(uintptr_t)r->ac_lsigtable & ~((uintptr_t)page-1);
        pages=((uintptr_t)r->ac_lsigtable+bytes-start+(size_t)page-1)/(size_t)page;
        vec=malloc(pages);if(!vec)return CL_EMEM;
        if(mincore((void *)start,pages*(size_t)page,vec)){free(vec);return CL_EARG;}
        for(j=0;j<pages;j++)resident+=!!(vec[j]&1);
        free(vec);
        printf("{\"kind\":\"logical_directory_residency\",\"target\":%u,\"logical_rules\":%u,\"packed\":%u,\"payload_bytes\":%zu,\"page_bytes\":%ld,\"covered_pages\":%zu,\"resident_pages\":%zu}\n",i,r->ac_lsigs,packed,bytes,page,pages,resident);fflush(stdout);
    }
    return result;
}
#define cl_engine_compile observed_compile
#include "/workspace/clamav/tools/compact-memory/top-six-qualification/probe.c"
