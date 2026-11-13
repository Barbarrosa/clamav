/* SPDX-License-Identifier: GPL-2.0-only
 * Diagnostic only: synthetic raw signatures are fed to the real native parser
 * as official-context occurrences. This executable cannot authenticate a
 * production generation and is never installed. The production compact-scan
 * has no raw-signature or resource-injection option.
 */
#define _GNU_SOURCE
#include "clamav.h"
static const char *fixture_raw,*fixture_mode,*fixture_generation;
static cl_error_t fixture_load(const char *,struct cl_engine *,unsigned *,unsigned);
static cl_error_t fixture_stats(const struct cl_engine *,uint64_t [CL_SUBSET_VALIDATION_COUNTERS]);
#define cl_load fixture_load
#define cl_subset_validation_stats fixture_stats
#define main compact_scan_program_main
#include "../native/scan.c"
#undef main
#undef cl_load
#undef cl_subset_validation_stats

static cl_error_t fixture_load(const char *path,struct cl_engine *engine,unsigned *loaded,unsigned options) {
    (void)path;
    cl_error_t status=cl_load(fixture_raw,engine,loaded,options|CL_DB_OFFICIAL);
    if(status==CL_SUCCESS&&!strcmp(fixture_mode,"split")&&*loaded>2){errno=ENOMEM;return CL_EMEM;}
    if(status==CL_SUCCESS&&(!strcmp(fixture_mode,"singleton-resource")&&*loaded>1))return CL_EMEM;
    if(status==CL_SUCCESS&&!strcmp(fixture_mode,"baseline-resource"))return CL_EMEM;
    if(status==CL_SUCCESS&&!strcmp(fixture_mode,"transcript")&&*loaded==1){
        char name[PATH_MAX];snprintf(name,sizeof(name),"%s/fixture.ndb",fixture_raw);
        FILE *file=fopen(name,"a");if(!file)return CL_EWRITE;
        fputs("Changed:1:*:61626364\n",file);fclose(file);
    }
    if(status==CL_SUCCESS&&!strcmp(fixture_mode,"generation")&&*loaded>1){
        char name[PATH_MAX];snprintf(name,sizeof(name),"%s/databases/main.cvd",fixture_generation);
        FILE *file=fopen(name,"a");if(!file)return CL_EWRITE;
        fputs("changed\n",file);fclose(file);
    }
    return status;
}
static cl_error_t fixture_stats(const struct cl_engine *engine,uint64_t counters[CL_SUBSET_VALIDATION_COUNTERS]) {
    cl_error_t status=cl_subset_validation_stats(engine,counters);
    if(status==CL_SUCCESS&&!strcmp(fixture_mode,"overflow"))counters[0]=(uint64_t)INT_MAX+1;
    if(status==CL_SUCCESS&&!strcmp(fixture_mode,"bm-overflow"))counters[0]=(uint64_t)UINT16_MAX+1;
    return status;
}
int main(int argc,char **argv) {
    if(argc!=5)return 2;
    fixture_generation=argv[1];fixture_raw=argv[2];fixture_mode=argv[4];
    if(!bootstrap_modules()||cl_init(CL_INIT_DEFAULT)!=CL_SUCCESS)return 2;
    struct ci_limits limits={256ULL*1024*1024,30,40,64ULL*1024*1024};
    if(ci_limits_apply(&limits))return 2;
    return ci_validate_bounded(argv[1],argv[3],&limits);
}
