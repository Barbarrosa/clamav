/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only batch interface reuses the production adapter's engine/skip/callback
 * implementation. It does not expose a shipping manifest bypass. */
#define main ci_scanner_cli_main
#include "../native/scan.c"
#undef main
#include <assert.h>
int main(int argc,char **argv) {
    assert(argc==5);assert(bootstrap_modules());assert(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);assert(cl_subset_runtime_capabilities()&1U);
    int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);assert(root>=0);
    bool reduced=atoi(argv[3])!=0;struct skips skips={0};
    if(reduced)assert(load_skips(&skips,root));
    struct cl_engine *engine=engine_load(argv[1],argv[2],reduced,&skips);assert(engine);
    FILE *list=fopen(argv[4],"r");assert(list);char *path=NULL;size_t capacity=0;ssize_t n;
    while((n=getline(&path,&capacity,list))>=0) {
        assert(n&&path[n-1]=='\n');path[n-1]=0;
        int fd=open(path,O_RDONLY|O_NOFOLLOW);assert(fd>=0);char before[65],after[65];uint64_t size,size_after;
        assert(digest_fd(fd,before,&size));struct context ctx={json_object_new_array(),json_object_new_array(),0,false,false};
        struct cl_scan_options options={0};options.parse=~0U;
        options.general=CL_SCAN_GENERAL_ALLMATCHES|CL_SCAN_GENERAL_HEURISTICS|CL_SCAN_GENERAL_COLLECT_METADATA;
        options.heuristic=CL_SCAN_HEURISTIC_EXCEEDS_MAX|CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE|CL_SCAN_HEURISTIC_ENCRYPTED_DOC|CL_SCAN_HEURISTIC_BROKEN|CL_SCAN_HEURISTIC_BROKEN_MEDIA;
        cl_verdict_t verdict=CL_VERDICT_NOTHING_FOUND;const char *name=NULL;char *type=NULL;uint64_t scanned=0;
        cl_error_t rc=cl_scandesc_ex(fd,path,&verdict,&name,&scanned,engine,&options,&ctx,NULL,NULL,NULL,NULL,&type);
        assert(digest_fd(fd,after,&size_after)&&size==size_after&&!strcmp(before,after));close(fd);
        json_object *out=json_object_new_object();add_s(out,"path",path);add_s(out,"sha256",before);add_n(out,"size",(int64_t)size);
        add_n(out,"status",rc);add_n(out,"verdict",verdict);add_n(out,"flags",ctx.guard);add_b(out,"incomplete",ctx.incomplete);
        add_b(out,"bad_callback",ctx.bad_callback);add_s(out,"root_type",type);add_n(out,"scanned_bytes",(int64_t)scanned);
        json_object_object_add(out,"findings",ctx.findings);json_object_object_add(out,"reasons",ctx.reasons);emit(out);free(type);
    }
    free(path);fclose(list);cl_engine_free(engine);free(skips.keys);free(skips.bytes);close(root);return 0;
}
