from pathlib import Path
import hashlib,json,os,shlex,subprocess
base=Path('/workspace')
wrapper=r'''#define _GNU_SOURCE
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
'''
records={}
for role,src,build in [('directory',base/'clamav',base/'clamav-system-build'),('packed',base/'clamav-opt-logical',base/'clamav-logical-build')]:
    source=base/('logical-'+role+'-lifecycle-probe.c');binary=source.with_suffix('')
    source.write_text(wrapper+'#include '+json.dumps(str(base/'clamav/tools/compact-memory/top-six-qualification/probe.c'))+'\n')
    flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','json-c','openssl'],text=True))
    lib=build/'libclamav';runtimes=[lib,build/'libclamunrar_iface',build/'libclamunrar']
    cmd=['cc','-std=gnu11','-fgnu89-inline','-O2','-Wall','-Wextra','-Wno-unused-function','-I'+str(build),'-I'+str(src/'libclamav'),'-I'+str(src/'libclamav_rust'),'-I'+str(src/'libclamunrar_iface'),'-I'+str(src/'libclammspack/mspack'),'-I'+str(src),'-I'+str(base/'clamav-sysroot/usr/include'),'-I'+str(base/'clamav-sysroot/usr/include/json-c'),str(source),'-L'+str(lib),'-L'+str(base/'clamav-sysroot/usr/lib/x86_64-linux-gnu'),'-Wl,--disable-new-dtags','-Wl,-rpath,'+':'.join(str(p) for p in runtimes),'-lclamav','-ldl','-pthread',*flags,'-o',str(binary)]
    subprocess.run(cmd,check=True)
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    records[role]={'source':str(source),'source_sha256':sha(source),'binary':str(binary),'binary_sha256':sha(binary),'library':str(lib/'libclamav.so.14.0.0'),'library_sha256':sha(lib/'libclamav.so.14.0.0'),'command':cmd}
(base/'logical-lifecycle-probes.json').write_text(json.dumps(records,indent=2)+'\n')
