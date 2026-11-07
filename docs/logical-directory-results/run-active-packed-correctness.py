#!/usr/bin/env python3
import argparse, importlib.util, json, os, shlex, subprocess, time
from pathlib import Path
spec=importlib.util.spec_from_file_location('qualification','/workspace/clamav/tools/compact-memory/top-six-qualification/correctness.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
base=Path('/workspace');out=base/'top-six-logical-packed-correctness';out.mkdir(exist_ok=True)
args=argparse.Namespace(build=base/'clamav-system-build',certs=base/'clamav/certs',cc='cc',include=[base/'clamav-sysroot/usr/include'],library_path=[base/'clamav-sysroot/usr/lib/x86_64-linux-gnu'],runtime_dir=[base/'clamav-system-build/libclamunrar_iface',base/'clamav-system-build/libclamunrar'],address_space_bytes=3*1024**3,cpu_seconds=60,wall_seconds=90,cpu=None)
roles={'baseline':(base/'clamav',base/'clamav-system-build'), 'candidate':(base/'clamav-opt-logical',base/'clamav-logical-build')}
probes={};libs={};sources={}
for role,(src,build) in roles.items():
    directory=out/role;directory.mkdir(exist_ok=True);lib=build/'libclamav/libclamav.so.14.0.0';libs[role]=lib
    prefix='''#define _GNU_SOURCE
#include "clamav-config.h"
#include "others.h"
#include "matcher-ac.h"
#include <stdio.h>
#include <sys/resource.h>
static void runtime_identity(void);
static cl_error_t qualified_load(const char *path,struct cl_engine *engine,unsigned *count,unsigned options) {
    struct rlimit a,c;runtime_identity();
    if(getrlimit(RLIMIT_AS,&a)||getrlimit(RLIMIT_CPU,&c))return CL_EARG;
    printf("{\\"kind\\":\\"qualification_limits\\",\\"address_space_bytes\\":%llu,\\"cpu_seconds\\":%llu}\\n",(unsigned long long)a.rlim_cur,(unsigned long long)c.rlim_cur);fflush(stdout);
    return cl_load(path,engine,count,options|CL_DB_PUA);
}
static cl_error_t qualified_compile(struct cl_engine *engine) {
    cl_error_t ret=cl_engine_compile(engine);unsigned i;
    if(ret!=CL_SUCCESS)return ret;
    for(i=0;i<CLI_MTARGETS;i++) {
        struct cli_matcher *r=engine->root[i];unsigned packed=0;size_t bytes=0;
        if(!r||!r->ac_lsigs)continue;
#if defined(ENABLE_LSIG_DIRECTORY_IDS) && SIZEOF_VOID_P == 8
        packed=!!(r->ac_heap_tables & CLI_AC_LSIG_DIRECTORY_PACKED);
        bytes=cli_ac_lsig_directory_bytes(r);
#else
        bytes=(size_t)r->ac_lsigs*sizeof(*r->ac_lsigtable);
#endif
        printf("{\\"kind\\":\\"logical_directory\\",\\"target\\":%u,\\"logical_rules\\":%u,\\"packed\\":%u,\\"bytes\\":%zu}\\n",i,r->ac_lsigs,packed,bytes);fflush(stdout);
    }
    return ret;
}
#define cl_load qualified_load
#define cl_engine_compile qualified_compile
'''
    source=directory/'correctness-probe.c';source.write_text(prefix+'#include '+json.dumps(str(base/'clamav/tools/subset-selector/scan_probe.c'))+'\n');sources[role]=q.sha(source)
    probe=directory/'correctness-probe';probes[role]=probe
    flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','json-c','openssl'],text=True))
    cmd=['cc','-std=gnu11','-fgnu89-inline','-O2','-Wall','-Wextra','-Werror','-DSUBSET_BOUNDARY_TEST','-I'+str(build),'-I'+str(src/'libclamav'),'-I'+str(src/'libclamav_rust'),'-I'+str(src/'libclamunrar_iface'),'-I'+str(src/'libclammspack/mspack'),'-I'+str(src),'-I'+str(base/'clamav-sysroot/usr/include'),'-I'+str(base/'clamav-sysroot/usr/include/json-c'),'-Wl,--export-dynamic',str(source),'-L'+str(lib.parent),'-L'+str(base/'clamav-sysroot/usr/lib/x86_64-linux-gnu'),'-Wl,--disable-new-dtags','-Wl,-rpath,'+':'.join(str(p) for p in [lib.parent]+args.runtime_dir),'-lclamav','-ldl',*flags,'-o',str(probe)]
    subprocess.run(cmd,check=True,text=True)
marker=out/'marker.bin';marker.write_bytes(b'ABCDEFGH')
macro_yes=out/'macro-yes.bin';macro_yes.write_bytes(b'ABCDMACROABCDMACRO')
macro_no=out/'macro-no.bin';macro_no.write_bytes(b'ABCD'+b'x'*100+b'MACROABCD'+b'x'*100+b'MACRO')
cases=[]
def add(name,rules,files,predicate,action=0):
    directory=out/name;directory.mkdir()
    (directory/'rules.ldb').write_text(rules)
    listing=out/(name+'.txt');listing.write_text(''.join(str(p)+'\n' for p in files))
    cases.append({'name':name,'database':str(directory),'files':str(listing),'inputs':[{'path':str(p),'sha256':q.sha(p)} for p in files],'predicate':predicate,'action':action,'repeats':2,'environment':{},'reject_load':False,'database_sha256':{'rules.ldb':q.sha(directory/'rules.ldb')}})
# 20k independently represented rules, with groups of 65 identical names.
rules=''.join(f'Packed.Alias.{i//65:05d};Engine:54-255,Target:0;0&1;41424344;45464748\n' for i in range(20000))
add('packed-duplicate-alias-order',rules,[marker],{'kind':'ordering','expected':308})
# Exercise macro reads through a packed directory, including conservative pattern directory retention.
filler=''.join(f'Packed.Other.{i:05d};Engine:54-255,Target:0;0;{q.hashlib.sha256(str(i).encode()).digest()[:12].hex()}\n' for i in range(16400))
add('packed-macro',filler+'Strong.Macro;Engine:54-255,Target:0;0&1;41424344;${4-16}0$\n',[macro_yes,macro_no],{'kind':'macro','expected':'Strong.Macro.UNOFFICIAL'})
macrodb=Path(cases[-1]['database'])/'macro.ndb';macrodb.write_text('Macro.Group:0:$0$:4d4143524f\n');cases[-1]['database_sha256']['macro.ndb']=q.sha(macrodb)
# Callbacks operate after lookup; preserve rule identity/multiplicity and acceptance semantics.
for action,name in ((1,'ignore'),(2,'stop'),(3,'trust')):
    add('packed-callback-'+name,rules,[marker],{'kind':name},action)
(out/'plan.json').write_text(json.dumps({'cases':cases,'sources':sources,'libraries':{r:q.sha(p) for r,p in libs.items()},'scope':'Additional active-packed logical directory fixtures; uses frozen shared exact semantic comparison and predicates.'},indent=2)+'\n')
checks=[]
for case in cases:
    observations={role:q.execute(args,case,role,libs[role],probes[role],out) for role in roles}
    formats={}
    for role,obs in observations.items():
        rows=[json.loads(line) for line in (out/obs['stdout']).read_text().splitlines() if line.strip()]
        formats[role]=[row for row in rows if row.get('kind')=='logical_directory']
    active=any(row['packed'] and row['logical_rules']>=16384 for row in formats['candidate'])
    passed=active and all(v['status']=='passed' for v in observations.values()) and observations['baseline'].get('semantic_sha256')==observations['candidate'].get('semantic_sha256') and observations['baseline'].get('signatures')==observations['candidate'].get('signatures')
    check={'case':case['name'],'passed':passed,'packed_mode_active':active,'formats':formats,'observations':observations};checks.append(check)
    print(json.dumps({'case':case['name'],'passed':passed,'packed_mode_active':active,'errors':{r:v.get('error') for r,v in observations.items() if v.get('error')}}),flush=True)
summary={'status':'passed' if all(c['passed'] for c in checks) else 'failed','checks':checks,'libraries':{r:q.sha(p) for r,p in libs.items()},'script_sha256':q.sha(Path(__file__))}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
raise SystemExit(0 if summary['status']=='passed' else 1)
