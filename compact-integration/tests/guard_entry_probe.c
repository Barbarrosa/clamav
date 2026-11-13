/* SPDX-License-Identifier: GPL-2.0-only
 * Assert the guard runs before an empty/uninitialized target root is consulted.
 * The test callback escapes immediately; no parser state has been allocated. */
#define _GNU_SOURCE
#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include <assert.h>
#include <setjmp.h>
#include <string.h>
static jmp_buf escape;
static void notification(uint32_t flags,void *p) {
    cli_ctx *ctx=p;
    assert(flags&CL_SUBSET_GUARD_PE);assert(ctx->subset_guard_flags&CL_SUBSET_GUARD_PE);
    longjmp(escape,1);
}
int main(int argc,char **argv) {
    assert(argc==2);assert(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);
    struct cl_engine *engine=cl_engine_new();assert(engine);
    assert(cl_engine_enable_subset_guard(engine,notification)==CL_SUCCESS);
    cli_ctx ctx={0};ctx.engine=engine;ctx.cb_ctx=&ctx;
    if(!setjmp(escape)) {
        if(!strcmp(argv[1],"buff")) (void)cli_scan_buff((const unsigned char*)"MZ",2,0,&ctx,CL_TYPE_MSEXE,NULL);
        else if(!strcmp(argv[1],"fmap")) (void)cli_scan_fmap(&ctx,CL_TYPE_MSEXE,false,NULL,AC_SCAN_VIR,NULL);
        else return 2;
        return 3; /* Guard failed to execute before target-root-dependent work. */
    }
    cl_engine_free(engine);return 0;
}
