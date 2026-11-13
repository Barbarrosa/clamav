#!/usr/bin/env python3
"""Remove each central production guard in an isolated diagnostic DSO.
The direct entry probes must reject both mutations. No shipping source/object is modified.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse,difflib,hashlib,json,os,pathlib,re,resource,shlex,subprocess

def command(build,target):
    output=subprocess.check_output(['ninja','-C',str(build),'-t','commands',target],text=True)
    return shlex.split(output.splitlines()[-1])
def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--build',type=pathlib.Path,required=True)
    p.add_argument('--probe',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    for k,v in vars(a).items():setattr(a,k,v.resolve())
    a.output.mkdir(parents=True,exist_ok=False);source=a.source/'libclamav/matcher.c';original=source.read_text()
    original_object='libclamav/CMakeFiles/clamav.dir/matcher.c.o';library=next((a.build/'libclamav').glob('libclamav.so.*.*.*'))
    cases=[]
    for function,mode in [('cli_scan_buff','buff'),('cli_scan_fmap','fmap')]:
        out=a.output/function;out.mkdir();mutated=out/'matcher.c'
        body=re.search(r'\b'+function+r'\([^;]*?\)\s*\n\{',original).end()
        guard='if (ftype == CL_TYPE_MSEXE) cli_subset_guard(ctx, CL_SUBSET_GUARD_PE);'
        position=original.index(guard,body);assert position-body<300
        text=original[:position]+'/* mutation: coverage guard removed */'+original[position+len(guard):];mutated.write_text(text)
        args=command(a.build,original_object);args[args.index('-c')+1]=str(mutated);args[args.index('-o')+1]=str(out/'matcher.o')
        if '-MF' in args:args[args.index('-MF')+1]=str(out/'matcher.d')
        args+=['-iquote',str(a.source/'libclamav')];subprocess.run(args,cwd=a.build,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        args=command(a.build,str(library.relative_to(a.build)));assert args[:2]==[':','&&'] and args[-2:]==['&&',':']
        args=[str(out/'matcher.o') if x==original_object else x for x in args[2:-2] if not x.startswith('-Wl,--dependency-file=')]
        args[args.index('-o')+1]=str(out/library.name);subprocess.run(args,cwd=a.build,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (out/'libclamav.so.14').symlink_to(library.name)
        env=os.environ.copy();env['LD_LIBRARY_PATH']=str(out)+':'+env.get('LD_LIBRARY_PATH','')
        def limits():resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        result=subprocess.run([str(a.probe),mode],env=env,preexec_fn=limits,timeout=15,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert result.returncode!=0,(function,'mutation escaped')
        cases.append({'function':function,'mutation_rejected':True,'probe_exit':result.returncode,'mutated_source_sha256':hashlib.sha256(text.encode()).hexdigest()})
    report={'protocol':1,'status':'passed','original_source_sha256':hashlib.sha256(original.encode()).hexdigest(),'cases':cases,
            'shipping_source_modified':False,'scope':'central buffer/fmap guards before target-root presence; actual per-family recursive guards tested separately'}
    (a.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
