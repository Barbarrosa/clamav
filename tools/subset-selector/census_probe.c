/* SPDX-License-Identifier: GPL-2.0-only
 * Reuse the production callback and existing read-only census. Diagnostic-only
 * build: link against relink_internal.py output. Its RSS is NOT a benchmark.
 */
#define main scan_probe_reference_main
#include "scan_probe.c"
#undef main
#define main census_reference_main
#include "../compact-memory/engine_census.c"
#undef main
int main(int argc,char **argv)
{
    if(argc!=4)return 2;
    CHECK(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);
    struct cl_engine *engine=load_engine(argv[1],argv[2],argv[3],"diagnostic_engine");
    census(engine);
    cl_engine_free(engine);
    return 0;
}
