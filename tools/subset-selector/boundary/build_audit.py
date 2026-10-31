#!/usr/bin/env python3
"""Relink a test-only engine copy with independent PE-boundary witnesses.
Original source/build objects/library are never changed. Linux/Ninja only.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('source','build','output'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();build=a.build.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    header='''#ifndef SUBSET_AUDIT_H
#define SUBSET_AUDIT_H
extern void subset_boundary_witness(void *, const char *) __attribute__((weak));
static inline void subset_audit(cli_ctx *ctx, const char *site) {
    if (subset_boundary_witness) subset_boundary_witness(ctx->cb_ctx, site);
}
#endif
'''
    (out/'subset_audit.h').write_text(header)
    replacements={}
    evidence={}
    for file in ('matcher.c','pe.c','scanners.c'):
        original=source/'libclamav'/file;text=original.read_text()
        text=text.replace('#include "others.h"','#include "others.h"\n#include "subset_audit.h"',1)
        sites=[]
        def insert_function(name,statement):
            nonlocal text
            import re
            pattern=re.compile(r'(^[^\n;]*\b'+re.escape(name)+r'\([^;]*?\)\s*\n\{)',re.M)
            text,count=pattern.subn(lambda m:m.group(0)+'\n    '+statement,text,count=1)
            assert count==1,(file,name)
        if file=='matcher.c':
            for name in ('cli_scan_buff','cli_scan_fmap'):
                insert_function(name,'if (ftype == CL_TYPE_MSEXE) subset_audit(ctx, "'+name+'-PE");');sites.append(name+'-PE')
        elif file=='pe.c':
            for name in ('scan_pe_mdb','scan_pe_imp','cli_scanpe'):
                insert_function(name,'subset_audit(ctx, "'+name+'");');sites.append(name)
        else:
            needle='cli_dbgmsg("scanraw: MaxEmbeddedPE exceeded\\n");'
            assert text.count(needle)==1
            text=text.replace(needle,'subset_audit(ctx, "MaxEmbeddedPE-skip");\n                                    '+needle)
            sites.append('MaxEmbeddedPE-skip')
        patched=out/file;patched.write_text(text)
        obj='libclamav/CMakeFiles/clamav.dir/'+file+'.o'
        commands=subprocess.check_output(['ninja','-C',str(build),'-t','commands',obj],text=True)
        args=shlex.split(commands.splitlines()[-1]);assert '-c' in args and '-o' in args
        args[args.index('-c')+1]=str(patched);args[args.index('-o')+1]=str(out/(file+'.o'))
        args+=['-I'+str(out),'-iquote',str(source/'libclamav')]
        if '-MF' in args:args[args.index('-MF')+1]=str(out/(file+'.d'))
        subprocess.run(args,cwd=build,check=True)
        replacements[obj]=str(out/(file+'.o'))
        evidence[file]={'source_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'sites':sites,'compile_command':args}
    library=next((build/'libclamav').glob('libclamav.so.*.*.*'))
    commands=subprocess.check_output(['ninja','-C',str(build),'-t','commands',str(library.relative_to(build))],text=True)
    args=shlex.split(commands.splitlines()[-1]);assert args[:2]==[':','&&'] and args[-2:]==['&&',':']
    args=[replacements.get(x,x) for x in args[2:-2] if not x.startswith('-Wl,--dependency-file=')]
    args[args.index('-o')+1]=str(out/library.name)
    subprocess.run(args,cwd=build,check=True)
    for name in ('libclamav.so','.'.join(library.name.split('.')[:3])):
        link=out/name;link.unlink(missing_ok=True);link.symlink_to(library.name)
    evidence['library']=library.name;evidence['link_command']=args
    (out/'instrumentation.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(out/library.name)

if __name__=='__main__':main()
