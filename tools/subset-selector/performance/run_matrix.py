#!/usr/bin/env python3
"""Serial, balanced three-way performance and cache experiment. GPL-2.0-only.

All measurements are fresh. This does not alter the shipping scanner flags.
The diagnostic clean-result-cache case intentionally disables metadata collection.
"""
import argparse
import hashlib
import json
import os
import platform
import random
import subprocess
import time
from pathlib import Path


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        while b:=f.read(1024*1024):h.update(b)
    return h.hexdigest()


def parse(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def cg():
    try:
        root=Path('/sys/fs/cgroup')
        stats={k:int(v) for k,v in (line.split() for line in (root/'memory.stat').read_text().splitlines())}
        return {'current_bytes':int((root/'memory.current').read_text()),'file_bytes':stats.get('file'),
                'anonymous_bytes':stats.get('anon'),'scope':'shared cgroup; not isolated service charge'}
    except (OSError,ValueError):return {'scope':'unavailable'}


def main(a):
    a.output.mkdir(parents=True,exist_ok=True)
    os.sched_setaffinity(0,{a.cpu})
    db=a.generation/'databases';dbfiles=sorted(p for p in db.iterdir() if p.is_file())
    listdb=a.output/'database-files.txt';listdb.write_text(''.join(str(p)+'\n' for p in dbfiles))
    empty=a.output/'empty.txt';empty.write_text('')
    env={'platform':platform.platform(),'cpu':a.cpu,'affinity':sorted(os.sched_getaffinity(0)),
         'cpu_model':next((l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),'unknown'),
         'compiler':subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
         'rounds':a.rounds,'warm_repetitions':a.repetitions,'seed':a.seed,
         'concurrent_scans':1,'allmatch':True,'raw_output':'JSONL; original byte hashes and full callback histories retained',
         'database':[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p)} for p in dbfiles],
         'generation_sha256':sha(a.generation/'manifest.json'),'fixture_list_sha256':sha(a.fixtures),
         'fixture_bytes':sum(Path(p).stat().st_size for p in a.fixtures.read_text().splitlines()),
         'fixture_count':len(a.fixtures.read_text().splitlines()),
         'hashes':{key:sha(getattr(a,key)) for key in ('upstream_probe','fork_probe','upstream_lib','fork_lib','upstream_freshclam','fork_freshclam')},
         'main_scan_options':'all parsers, all-match, metadata, heuristics; clean-result cache disabled equally',
         'cache_diagnostic_options':'same except metadata off and clean-result cache enabled equally; not a shipping evidence policy',
         'page_cache_control':'fsync + POSIX_FADV_DONTNEED or complete read, verified with mincore at 0% or 100%; no global drop_caches',
         'memory':'RSS high water and sampled RSS/PSS/USS; working-set page residency recorded separately; no additive total with shared cgroup',
         'timing':'native process; engine startup and integrity-preserving scan pipeline timed; memory snapshots outside timed scan intervals'}
    env['runtime_modules']={}
    for v,lib in [('upstream',a.upstream_lib),('fork',a.fork_lib)]:
        build=lib.parent.parent
        env['runtime_modules'][v]=[{'path':str(p.resolve()),'sha256':sha(p)} for p in (
            build/'libclamunrar_iface/libclamunrar_iface.so.14.0.0',
            build/'libclamunrar/libclamunrar.so.14.0.0')]
    (a.output/'environment.json').write_text(json.dumps(env,indent=2)+'\n')
    rng=random.Random(a.seed);variants=['upstream','full','legal-redress'];plan=[]
    for r in range(a.rounds):
        cases=[(v,c) for v in variants for c in ('empty','hydrated')];rng.shuffle(cases)
        for v,c in cases:plan.append(dict(stage='primary',variant=v,cache=c,round=r,case='scan',files=str(a.fixtures),repeats=a.repetitions))
    for r in range(a.rounds):
        order=variants.copy();rng.shuffle(order)
        for v in order:plan.append(dict(stage='result-cache',variant=v,cache='hydrated',round=r,case='result-cache',files=str(a.fixtures),repeats=a.repetitions))
    for r in range(a.lifecycle_rounds):
        cases=[(v,d) for v in variants for d in ('main.cvd','daily.cvd','bytecode.cvd')];rng.shuffle(cases)
        for v,d in cases:plan.append(dict(stage='lifecycle',variant=v,cache='hydrated',round=r,case='update',database=d,files=str(empty),repeats=1))
    for stage,files in [('positive',a.positive),('adverse',a.adverse)]:
        if files:
            for v in variants:plan.append(dict(stage=stage,variant=v,cache='hydrated',round=0,case='scan',files=str(files),repeats=1))
    (a.output/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    for index,case in enumerate(plan):
        v=case['variant'];stem=f'{index:03}-{case["stage"]}-{v}-{case["cache"]}-{case["round"]}'
        if case.get('database'):stem+='-'+case['database']
        output=a.output/(stem+'.jsonl');stderr=a.output/(stem+'.stderr');record=a.output/(stem+'-process.json')
        probe=a.upstream_probe if v=='upstream' else a.fork_probe
        cmd=[str(probe),str(db),str(a.certs),str(a.generation/'skip.tsv') if v=='legal-redress' else '-',
             case['files'],case['case'],str(listdb),case['cache'],str(case['repeats']),'1']
        if a.resume and record.exists():
            old=json.loads(record.read_text())
            if old['command']==cmd and old['returncode']==0 and old['stdout_sha256']==sha(output) and old['probe_sha256']==sha(probe):
                print('verified completed',stem,flush=True);continue
            raise RuntimeError('existing run cannot be reused: '+stem)
        childenv=os.environ.copy()
        build=(a.upstream_lib if v=='upstream' else a.fork_lib).parent.parent
        childenv['LD_LIBRARY_PATH']=':'.join(str(build/d) for d in ('libclamav','libclamunrar_iface','libclamunrar'))+':'+childenv.get('LD_LIBRARY_PATH','')
        if case['case']=='update':
            childenv['BENCH_FRESHCLAM_LIBRARY']=str(a.upstream_freshclam if v=='upstream' else a.fork_freshclam)
            childenv['BENCH_FRESHCLAM_DATABASE']=str(db/case['database'])
        before=cg();start=time.monotonic()
        with output.open('w') as out,stderr.open('w') as err:
            p=subprocess.run(cmd,stdout=out,stderr=err,env=childenv,timeout=900)
            out.flush();os.fsync(out.fileno());err.flush();os.fsync(err.fileno())
        info={**case,'command':cmd,'returncode':p.returncode,'process_wall_seconds':time.monotonic()-start,
              'stdout_sha256':sha(output),'stderr_sha256':sha(stderr),'probe_sha256':sha(probe),'shared_cgroup_before':before,'shared_cgroup_after':cg()}
        record.write_text(json.dumps(info,indent=2)+'\n')
        if p.returncode:raise RuntimeError(stem+' failed: '+stderr.read_text()[-1500:])
        rows=parse(output);scans=[r for r in rows if r['kind']=='scan']
        if case['stage'] in ('primary','result-cache'):
            expected=env['fixture_count']*(case['repeats']+1)
            assert len(scans)==expected, (stem,'scan rows missing')
            assert all(r['candidate_outcome']=='clean' and r['hold_bits']==0 and r['sha256']==r['after_sha256'] for r in scans), (stem,'invalid performance sample')
            if case['stage']=='result-cache':
                initial=[r for r in scans if r['phase']=='result_cache_empty'];warm=[r for r in scans if r['phase']=='result_cache_hydrated']
                assert not any(r['root_cache_hit'] for r in initial), 'initial result cache was not empty'
                assert all(r['root_cache_hit'] for r in warm), 'not all warmed files hit result cache'
        print(f'completed {index+1}/{len(plan)} {stem}',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('upstream-probe','fork-probe','upstream-lib','fork-lib','upstream-freshclam','fork-freshclam','generation','certs','fixtures','output'):
        p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--positive',type=Path);p.add_argument('--adverse',type=Path)
    p.add_argument('--rounds',type=int,default=5);p.add_argument('--lifecycle-rounds',type=int,default=3)
    p.add_argument('--repetitions',type=int,default=3);p.add_argument('--seed',type=int,default=20261029)
    p.add_argument('--cpu',type=int,default=min(os.sched_getaffinity(0)));p.add_argument('--resume',action='store_true')
    a=p.parse_args()
    for k,v in vars(a).items():
        if isinstance(v,Path):setattr(a,k,v.resolve())
    main(a)
