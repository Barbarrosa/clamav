#!/usr/bin/env python3
"""Paired fresh-process benchmark; no private corpus, no automatic qualification.
GPL-2.0-only. Cgroup observations are SHARED totals, not attributable deltas.
"""
import argparse, collections, hashlib, json, os, platform, statistics, subprocess, sys, time
from pathlib import Path
from select_db import sha,validate_generation


def group_memory():
    try:
        stat=dict(l.split() for l in Path('/sys/fs/cgroup/memory.stat').read_text().splitlines())
        return {'current':int(Path('/sys/fs/cgroup/memory.current').read_text()),'file':int(stat['file']),'anon':int(stat['anon']),'kernel':int(stat.get('kernel','0'))}
    except (OSError,KeyError):return {}


def run(a,label,skip,files,repeats=1,broad=0,overlap=0,extra=None):
    out=a.output/(label+'.jsonl');err=a.output/(label+'.stderr');env=os.environ.copy();env.update(extra or {})
    command=[str(a.probe),str(a.generation/'databases'),str(a.certs),str(skip),str(files),str(repeats),str(broad),'0',str(overlap)]
    if a.configured_profiles:
        command=[sys.executable,str(Path(__file__).with_name('scan.py')),
                 '--probe',str(a.probe),'--generation',str(a.generation),'--lib',str(a.lib),
                 '--certs',str(a.certs),'--files',str(files),'--repetitions',str(repeats),
                 '--database-profile='+('full' if skip=='-' else 'pdf-jpeg-png-pe-exclusions'),'--allmatch']
        if broad:command.append('--broad')
        if overlap:command.append('--reload-overlap')
    samples=[];start=time.monotonic()
    with out.open('w') as o,err.open('w') as e:
        p=subprocess.Popen(command,stdout=o,stderr=e,env=env)
        while p.poll() is None:
            samples.append({'elapsed':time.monotonic()-start,**group_memory()});time.sleep(.05)
    record={'command':command,'returncode':p.returncode,'wall_seconds':time.monotonic()-start,'shared_cgroup_samples':samples,
            'stdout_sha256':sha(out),'stderr_sha256':sha(err)}
    (a.output/(label+'-process.json')).write_text(json.dumps(record,indent=2)+'\n')
    if p.returncode:raise RuntimeError(label+' failed')
    return [json.loads(l) for l in out.read_text().splitlines() if l.startswith('{')]


def semantic(r):return {k:r[k] for k in ['return_code','verdict','final_name','root_type','scanned_bytes','events']}

def main(a):
    if a.configured_profiles and a.positive:raise ValueError('use test_flags.py for configured-profile positive/held comparisons')
    a.output.mkdir(parents=True,exist_ok=True);manifest=validate_generation(a.generation,a.lib)
    cpu=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
    environment={'cpu':cpu,'platform':platform.platform(),'compiler':subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                 'probe_sha256':sha(a.probe),'lib_sha256':sha(a.lib),'database_manifest_sha256':sha(a.generation/'manifest.json'),
                 'concurrency':1,'scan_cache':'disabled','metadata':'enabled equally','memory_units':'KiB unless bytes explicit',
                 'cgroup_scope':'shared task group; samples cannot establish isolated service charge',
                 'input_list_sha256':sha(a.fixtures),'configured_profiles':a.configured_profiles}
    (a.output/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
    results=[];refs={};comparisons=[]
    for i,variant in enumerate(['full','reduced','reduced','full','full','reduced']):
        rows=run(a,f'pair-{i}-{variant}','-' if variant=='full' else a.generation/'skip.tsv',a.fixtures,a.repetitions)
        eng=next(r for r in rows if r['kind']=='engine');batches=[r for r in rows if r['kind']=='batch'];scans=[r for r in rows if r['kind']=='scan'];results.append({'variant':variant,'engine':eng,'batches':batches})
        refs.setdefault(variant,scans)
        print(f'completed {i} {variant}',flush=True)
    for x,y in zip(refs['full'],refs['reduced']):
        if not y['hold_bits']:
            comparisons.append({'name':Path(x['path']).name,'allmatch':x['allmatch'],'round':x['round'],'exact_equal':semantic(x)==semantic(y)})
    empty=a.output/'empty.txt';empty.write_text('')
    for v in ['full','reduced']:
        run(a,'reload-'+v,'-' if v=='full' else a.generation/'skip.tsv',empty,overlap=1)
    if a.freshclam:
        for name in ['main.cvd','daily.cvd','bytecode.cvd']:
            run(a,'updater-'+name,a.generation/'skip.tsv',empty,overlap=1,
                extra={'SUBSET_FRESHCLAM_LIBRARY':str(a.freshclam),'SUBSET_FRESHCLAM_DATABASE':str(a.generation/'databases'/name)})
        # Conservative helper directory test beyond per-file normal FreshClam checks.
        run(a,'updater-complete-snapshot',a.generation/'skip.tsv',empty,overlap=1,extra={'SUBSET_FRESHCLAM_LIBRARY':str(a.freshclam)})
    if a.positive:
        for v in ['full','reduced']:
            run(a,'official-positives-'+v,'-' if v=='full' else a.generation/'skip.tsv',a.positive,broad=1)
    summary={'runs':results,'candidate_equivalence':comparisons,'candidate_equivalence_pass':all(x['exact_equal'] for x in comparisons),
             'qualification':'not granted; consult synthetic ordering and parser audit'}
    for v in ['full','reduced']:
        rows=[r for r in results if r['variant']==v]
        summary[v]={'compiled_rss_kib_mean':statistics.mean(r['engine']['compiled_rss_kib'] for r in rows),
                    'construction_hwm_kib_max':max(r['engine']['construction_hwm_kib'] for r in rows),
                    'scan_hwm_kib_max':max(b['scan_hwm_kib'] for r in rows for b in r['batches']),
                    'load_seconds_mean':statistics.mean(r['engine']['load_seconds'] for r in rows),
                    'compile_seconds_mean':statistics.mean(r['engine']['compile_seconds'] for r in rows),
                    'first_hit_batch_seconds_mean':None if a.configured_profiles else statistics.mean(b['seconds'] for r in rows for b in r['batches'] if b['allmatch']==0),
                    'all_match_batch_seconds_mean':statistics.mean(b['seconds'] for r in rows for b in r['batches'] if b['allmatch']==1)}
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ['full','reduced','candidate_equivalence_pass']},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for k in ['probe','generation','certs','lib','fixtures','output']:p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--freshclam',type=Path);p.add_argument('--positive',type=Path);p.add_argument('--repetitions',type=int,default=3)
    p.add_argument('--configured-profiles',action='store_true',help='measure the scan.py documented flags, both profiles with all-match')
    a=p.parse_args()
    for k,v in vars(a).items():
        if isinstance(v,Path):setattr(a,k,v.resolve())
    main(a)
