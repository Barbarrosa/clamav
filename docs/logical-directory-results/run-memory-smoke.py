#!/usr/bin/env python3
import argparse, hashlib,json,os,resource,shutil,statistics,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--case',choices=['scan','reload'],required=True);p.add_argument('--order',default='directory,packed,packed,directory');p.add_argument('--output',type=Path,required=True);p.add_argument('--repeats',type=int,default=3);a=p.parse_args()
base=Path('/workspace');out=a.output;out.mkdir()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
ident=json.loads((base/'logical-lifecycle-probes.json').read_text())
db=out/'database';db.mkdir();bound={}
for path in sorted((base/'clamav-system-database').glob('*.cvd')):
    target=db/path.name;shutil.copyfile(path,target);bound[str(target)]=sha(target)
dblist=out/'database-files.txt';dblist.write_text(''.join(str(path)+'\n' for path in db.glob('*.cvd')))
files=base/'memory-perturb-corpus/files.txt';bound[str(files)]=sha(files)
for path in files.read_text().splitlines():bound[path]=sha(path)
cpus=sorted(os.sched_getaffinity(0));cpu=cpus[0]
limits={'address_space_bytes':3*1024**3,'cpu_seconds':150,'cpu_hard_seconds':155,'wall_seconds':180,'cpu':cpu}
plan={'case':a.case,'order':a.order.split(','),'repeats':a.repeats,'identities':ident,'inputs':bound,'environment':{'CVD_CERTS_DIR':str(base/'clamav/certs')},'limits':limits,'scope':'Serial bounded full DB memory/lifecycle or hot-path smoke; not a complete 18-metric qualification or all-input proof. Database cache hydrated with private copied inputs.'}
(out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n');runs=[]
def impose():
    resource.setrlimit(resource.RLIMIT_AS,(limits['address_space_bytes'],limits['address_space_bytes']));resource.setrlimit(resource.RLIMIT_CPU,(150,155));os.sched_setaffinity(0,{cpu})
for i,role in enumerate(plan['order']):
    entry=ident[role];assert sha(entry['binary'])==entry['binary_sha256'];assert sha(entry['library'])==entry['library_sha256']
    stem=f'{i:02d}-{role}';stdout=out/(stem+'.jsonl');stderr=out/(stem+'.stderr')
    env=os.environ.copy()
    for key in list(env):
        if key.startswith(('SUBSET_','CM_PAD_','BENCH_','QUAL_')) or key in ('LD_PRELOAD','LD_LIBRARY_PATH'):env.pop(key)
    libdir=Path(entry['library']).parent;build=libdir.parent
    env['CVD_CERTS_DIR']=str(base/'clamav/certs')
    env['LD_LIBRARY_PATH']=':'.join(str(p) for p in [libdir,build/'libclamunrar_iface',build/'libclamunrar'])
    command=[entry['binary'],str(db),str(base/'clamav/certs'),str(files),a.case,str(dblist),'hydrated',str(a.repeats),'1','1']
    started=time.monotonic()
    with stdout.open('wb') as o,stderr.open('wb') as e:
        proc=subprocess.Popen(command,stdout=o,stderr=e,env=env,preexec_fn=impose)
        try:proc.wait(timeout=180)
        except subprocess.TimeoutExpired:proc.kill();proc.wait();raise
    rows=[json.loads(line) for line in stdout.read_text().splitlines() if line.strip()]
    assert proc.returncode==0,(role,proc.returncode,stderr.read_text()[-1000:])
    runtime=[r for r in rows if r.get('kind')=='runtime'];assert len(runtime)==1 and runtime[0]['engine_sha256']==entry['library_sha256']
    engines=[r for r in rows if r.get('kind') in ('engine','reload_overlap')];assert engines and all(r['signatures']==3628192 for r in engines)
    directory=[r for r in rows if r.get('kind')=='logical_directory_residency']
    assert directory and (role!='packed' or any(r['packed'] for r in directory))
    picked=[r for r in rows if r.get('kind') in ('engine','startup','batch','reload_overlap','reload','old_engine_freed','all_engines_freed')]
    scans=[{k:r[k] for k in ('phase','round','allmatch','return_code','verdict','final_name','root_type','sha256','after_sha256','hold_bits','candidate_outcome','scanned_bytes','input_bytes','events')} for r in rows if r.get('kind')=='scan']
    semantic=hashlib.sha256(json.dumps(scans,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    run={'role':role,'wall_seconds':time.monotonic()-started,'return_code':proc.returncode,'stdout':stdout.name,'stdout_sha256':sha(stdout),'stderr':stderr.name,'stderr_sha256':sha(stderr),'directories':directory,'measurements':picked,'semantic_sha256':semantic}
    runs.append(run);(out/'runs.json').write_text(json.dumps(runs,indent=2)+'\n')
    print(json.dumps({'role':role,'wall_seconds':run['wall_seconds'],'measurements':picked,'directories':directory}),flush=True)
assert all(sha(path)==expected for path,expected in bound.items())
assert len({r['semantic_sha256'] for r in runs})==1
report={'status':'passed','case':a.case,'runs':runs,'scope':plan['scope'],'plan_sha256':sha(out/'plan.json'),'runner_sha256':sha(Path(__file__))}
(out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
