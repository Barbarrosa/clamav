#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import json,statistics,hashlib,collections,shutil,gzip
from pathlib import Path
import argparse
p=argparse.ArgumentParser(description='Collect the recorded experiment directory layout; see result README.')
p.add_argument('--work',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=a.work;out=a.output;out.mkdir(parents=True,exist_ok=True)
def rows(p):return [json.loads(l) for l in p.read_text().splitlines() if l.startswith('{')]
def scan(p):return [r for r in rows(p) if r['kind']=='scan']
def sem(r):return {k:r[k] for k in ['return_code','verdict','final_name','root_type','scanned_bytes','events']}
# Preserve raw reproducible aggregate evidence; no CVDs or complaint bytes.
for folder in ['bench','accepted-bench','integration-gate','integration-asan']:
 dest=out/folder;dest.mkdir(exist_ok=True)
 for p in (w/folder).iterdir():
  if p.is_file() and p.suffix in ['.json','.jsonl','.stderr']:
   shutil.copy2(p,dest/p.name)
for name in ['unit-tests-final.log','retained-ctest.log','retained-ctest-fixed.log','integration-gate-exit-code.txt','signed-input-tests.json','signed-input-tests.log','cld-verification.json','intake-output.json','intake-memory.json','fixture-manifest.json','accepted-manifest.json','census-full.jsonl','census-reduced.jsonl','selector-v1.1.log']:
 if (w/name).exists():shutil.copy2(w/name,out/name)
for v in ['full','reduced']:
 for prefix in ['extra']:
  shutil.copy2(w/f'{prefix}-{v}.jsonl',out/f'{prefix}-{v}.jsonl')
manifest=json.load(open(w/'generation-v1.1/manifest.json'));old=json.load(open(w/'generation-final/manifest.json'))
shutil.copy2(w/'generation-v1.1/manifest.json',out/'database-manifest.json')
shutil.copy2(w/'generation-final/manifest.json',out/'benchmark-database-manifest.json')
for name in ['skip.tsv','decisions.sqlite']:
 with open(w/'generation-v1.1'/name,'rb') as src,open(out/(name+'.gz'),'wb') as dst:
  with gzip.GzipFile(filename='',mode='wb',fileobj=dst,mtime=0) as g:shutil.copyfileobj(src,g)
assert manifest['skip_sha256']==old['skip_sha256']
accepted=json.load(open(w/'accepted-bench/summary.json'));mixed=json.load(open(w/'bench/summary.json'))
result={'status':'EXPERIMENTAL; automatic reduced clean release disabled','retained_runtime_revision':'005bb6c6ca880b13184775956d0f87faf541ea0b',
        'signature_count_full':3628192,'signature_count_reduced':601004,'skipped_callback_events':3027189,
        'candidate_names':manifest['excluded_callback_names'],'selector_self_peak_rss_kib':manifest['selector_peak_rss_kib'],
        'selector_elapsed_seconds':manifest['elapsed_seconds'],'selector_full_validation':manifest['full_load_validation'],
        'selector_mapping_and_index_bytes':14925375,
        'final_generation_has_identical_skip_sha_to_measured_generation':True,
        'accepted_workload':{'files':28,'input_bytes':sum(r['bytes'] for r in json.load(open(w/'accepted-manifest.json'))),'fresh_processes_per_variant':3,'repetitions_per_mode_per_process':3,'full':accepted['full'],'reduced':accepted['reduced'],
                             'exact_public_transcripts_equal':accepted['candidate_equivalence_pass']},
        'mixed_workload':{'files':40,'full':mixed['full'],'reduced':mixed['reduced'],'note':'timing includes held PE inputs and is NOT coverage-equivalent throughput'},
        'synthetic_gate':json.load(open(w/'integration-gate/summary.json'))}
for v in ['full','reduced']:
 ss=[]
 for p in sorted((w/'accepted-bench').glob(f'pair-*-{v}.jsonl')):ss+=scan(p)
 assert all(not r['hold_bits'] and r['candidate_outcome']=='clean' for r in ss)
 ts=sorted(r['seconds'] for r in ss)
 result['accepted_workload'][v]['per_file_latency_median_seconds']=statistics.median(ts)
 result['accepted_workload'][v]['per_file_latency_p95_seconds']=ts[int(.95*(len(ts)-1))]
 result['accepted_workload'][v]['MiB_per_second_first_hit']=(result['accepted_workload']['input_bytes']/1048576)/accepted[v]['first_hit_batch_seconds_mean']
 result['accepted_workload'][v]['scan_calls']=len(ss)
result['lifecycle']={}
for label in ['reload-full','reload-reduced','updater-main.cvd','updater-daily.cvd','updater-bytecode.cvd','updater-complete-snapshot']:
 result['lifecycle'][label]=[r for r in rows(w/'bench'/(label+'.jsonl')) if r['kind'] in ['reload_overlap','freshclam_load_test_overlap']]
full=scan(w/'bench/official-positives-full.jsonl');red=scan(w/'bench/official-positives-reduced.jsonl')
result['official_positive_fixtures']={'files':89,'modes':2,'full_verdict_counts':dict(collections.Counter(r['verdict'] for r in full)),
 'reduced_verdict_counts':dict(collections.Counter(r['verdict'] for r in red)),
 'holds':sum(bool(r['hold_bits']) for r in red),'nonheld':sum(not r['hold_bits'] for r in red),
 'nonheld_exact_equal':all(sem(x)==sem(y) for x,y in zip(full,red) if not y['hold_bits']),
 'all_exact_equal_including_held':all(sem(x)==sem(y) for x,y in zip(full,red)),
 'note':'Held inputs do not count as successful equivalent scans; generic whole-file hash detections remain visible.'}
result['extra_compatibility']=[{k:r[k] for k in ['path','allmatch','root_type','candidate_outcome','hold_bits','return_code']} for r in scan(w/'extra-reduced.jsonl')]
# Summarize shared cgroup observations; do not pretend a baseline subtraction isolates service charges.
samples=[]
for p in (w/'accepted-bench').glob('*-process.json'):samples+=json.load(p.open())['shared_cgroup_samples']
result['shared_cgroup_observations_bytes']={k:{'min':min(r[k] for r in samples if k in r),'max':max(r[k] for r in samples if k in r)} for k in ['current','file','anon','kernel']}
result['shared_cgroup_observations_bytes']['interpretation']='shared workspace group, not isolated scanner budget; cold-cache charge and production ceiling unqualified'
result['disk_bytes']={n:(w/'generation-v1.1'/n).stat().st_size for n in ['skip.tsv','decisions.sqlite','manifest.json']}
result['disk_bytes']['signed_database_files']=sum(r['bytes'] for r in manifest['signed_databases'])
result['intake_process_metrics']=json.load(open(w/'intake-output.json')).get('linux_process_high_water_kib')
(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'accepted':result['accepted_workload'],'intake':result['intake_process_metrics'],'official':result['official_positive_fixtures'],'disk':result['disk_bytes']},indent=2))
