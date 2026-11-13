/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only unsigned toy databases; does not authorize a production generation. */
#define _GNU_SOURCE
#include "clamav.h"
#include <json-c/json.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct run { unsigned flags; json_object *names; };
static void note(uint32_t flags,void *p){((struct run*)p)->flags|=flags;}
static void virus(int fd,const char *name,void*p){(void)fd;json_object_array_add(((struct run*)p)->names,json_object_new_string(name));}
static int skip(const char *fmt,const char *name,unsigned custom,void*p){
    (void)custom;(void)p;
    if(!strcmp(fmt,"ndb")||!strcmp(fmt,"ldb"))return !strcmp(name,"Boundary.PE");
    return !strcmp(fmt,"mdb")||!strcmp(fmt,"msb")||!strcmp(fmt,"imp");
}
int main(int argc,char**argv){
    assert(argc>=5);assert(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);
    int guarded=atoi(argv[3]);struct cl_engine *engine=cl_engine_new();assert(engine);
    assert(cl_engine_set_str(engine,CL_ENGINE_CVDCERTSDIR,argv[2])==CL_SUCCESS);
    if(guarded){assert(cl_engine_enable_subset_guard(engine,guarded==2?NULL:note)==CL_SUCCESS);
        cl_engine_set_clcb_sigload(engine,skip,NULL);}
    unsigned count=0;assert(cl_load(argv[1],engine,&count,CL_DB_STDOPT)==CL_SUCCESS);
    cl_engine_set_clcb_sigload(engine,NULL,NULL);assert(cl_engine_compile(engine)==CL_SUCCESS);
    assert(cl_engine_enable_subset_guard(engine,note)==CL_ESTATE);
    /* A caller attempting to re-enable the cache still cannot bypass the guard. */
    if(guarded)assert(cl_engine_set_num(engine,CL_ENGINE_DISABLE_CACHE,0)==CL_SUCCESS);
    cl_engine_set_clcb_virus_found(engine,virus);
    for(int i=4;i<argc;i++){
        struct run run={0,json_object_new_array()};struct cl_scan_options options={0};
        options.parse=~0U;options.general=CL_SCAN_GENERAL_ALLMATCHES|CL_SCAN_GENERAL_HEURISTICS;
        options.heuristic=CL_SCAN_HEURISTIC_EXCEEDS_MAX;
        cl_verdict_t verdict=CL_VERDICT_NOTHING_FOUND;const char*name=NULL;
        cl_error_t rc=cl_scanfile_ex(argv[i],&verdict,&name,NULL,engine,&options,&run,NULL,NULL,NULL,NULL,NULL);
        json_object *out=json_object_new_object();json_object_object_add(out,"path",json_object_new_string(argv[i]));
        json_object_object_add(out,"status",json_object_new_int(rc));json_object_object_add(out,"verdict",json_object_new_int(verdict));
        json_object_object_add(out,"flags",json_object_new_int(run.flags));json_object_object_add(out,"names",run.names);
        puts(json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN));json_object_put(out);
    }
    cl_engine_free(engine);return 0;
}
