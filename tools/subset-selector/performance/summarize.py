#!/usr/bin/env python3
"""Analyze the three-way matrix without mixing historical measurements. GPL-2.0-only."""
import argparse
import collections
import hashlib
import json
import math
import random
import statistics
import sys
from pathlib import Path
from profile_labels import RESTRICTED_VARIANT, VARIANTS, normalize_variant
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from equivalence import detection_equivalent


METRICS=('wall_seconds','cpu_seconds','user_cpu_seconds','system_cpu_seconds','cpu_percent_one_core',
         'rss_kib','hwm_kib','pss_kib','uss_kib','anon_pss_kib','file_pss_kib','minor_faults','major_faults','block_read_bytes','block_write_bytes')


def percentile(values,q):
    values=sorted(values);pos=(len(values)-1)*q;lo=int(pos);hi=math.ceil(pos)
    return values[lo]+(values[hi]-values[lo])*(pos-lo)


def stats(values):
    values=list(values);rng=random.Random(20261029)
    means=[statistics.mean(rng.choices(values,k=len(values))) for _ in range(4000)]
    return {'n':len(values),'mean':statistics.mean(values),'median':statistics.median(values),
            'min':min(values),'max':max(values),'sd':statistics.stdev(values) if len(values)>1 else 0,
            'mean_95ci':[percentile(means,.025),percentile(means,.975)]}


def fields(rows):return {key:stats(r[key] for r in rows) for key in METRICS}


def mean_row(rows):return {key:statistics.mean(r[key] for r in rows) for key in METRICS}


def paired_percent(left,right):
    keys=sorted(left.keys()&right.keys());pairs=[(left[k],right[k]) for k in keys];rng=random.Random(20261029)
    estimates=[];median_estimates=[]
    for _ in range(4000):
        sample=rng.choices(pairs,k=len(pairs));estimates.append(100*(sum(y for x,y in sample)/sum(x for x,y in sample)-1))
        median_estimates.append(100*(statistics.median(y for x,y in sample)/statistics.median(x for x,y in sample)-1))
    return {'pairs':len(pairs),'percent_change':100*(sum(y for x,y in pairs)/sum(x for x,y in pairs)-1),
            '95ci':[percentile(estimates,.025),percentile(estimates,.975)],
            'median_percent_change':100*(statistics.median(y for x,y in pairs)/statistics.median(x for x,y in pairs)-1),
            'median_95ci':[percentile(median_estimates,.025),percentile(median_estimates,.975)]}


def main(a):
    environment=json.loads((a.results/'environment.json').read_text());plan=json.loads((a.results/'plan.json').read_text())
    records=[]
    for p in sorted(a.results.glob('*-process.json')):
        r=json.loads(p.read_text());assert r['returncode']==0,p
        out=p.with_name(p.name.replace('-process.json','.jsonl'));data=out.read_bytes()
        assert hashlib.sha256(data).hexdigest()==r['stdout_sha256'],out
        # Keep raw file names and verified bytes intact; only the report label changes.
        r['variant']=normalize_variant(r['variant'])
        rows=[json.loads(l) for l in data.decode().splitlines() if l.startswith('{')];r['rows']=rows;r['file']=p.name;records.append(r)
        assert all(row['unrar_modules_verified']==1 for row in rows if row['kind']=='startup'),p
    assert len(records)==len(plan),(len(records),len(plan))
    primary={v:[r for r in records if r['stage']=='primary' and r['variant']==v] for v in VARIANTS}
    diagnostics={v:[r for r in records if r['stage']=='result-cache' and r['variant']==v] for v in VARIANTS}
    result={'schema':1,'environment':environment,'completed_processes':len(records),
            'confidence_method':'95% percentile bootstrap, 4,000 resamples of fresh-process summaries; repeated warm scans averaged within each process',
            'variants':{},'comparisons':{},'validation':{},'automatic_reduced_release_enabled':False}
    reference={}
    for r in primary['upstream']:
        for s in r['rows']:
            if s['kind']=='scan':reference.setdefault(s['path'],s)
    comparison_count=collections.Counter()
    for v in VARIANTS:
        out={};runs=primary[v];engines=[next(x for x in r['rows'] if x['kind']=='engine') for r in runs]
        counts={e['signatures'] for e in engines};assert len(counts)==1
        out['signatures_loaded']=counts.pop();out['signed_source_bytes']=sum(d['bytes'] for d in environment['database'])
        out['compiled_rss_kib']=stats(e['compiled_rss_kib'] for e in engines)
        out['construction_hwm_kib']=stats(e['construction_hwm_kib'] for e in engines)
        out['startup']={}
        for cache in ('empty','hydrated'):
            rows=[next(x for x in r['rows'] if x['kind']=='startup') for r in runs if r['cache']==cache]
            out['startup'][cache]=fields(rows)
        out['scan']={};out['scan_latency_ms']={};out['scan_by_format']={}
        for phase in ('file_cache_empty','file_cache_hydrated'):
            process_rows=[];latencies=[];by_format=collections.defaultdict(list)
            for r in runs:
                batches=[b for b in r['rows'] if b['kind']=='batch' and b['phase']==phase]
                process_rows.append(mean_row(batches))
                for s in r['rows']:
                    if s['kind']=='scan' and s['phase']==phase:
                        assert s['candidate_outcome']=='clean' and s['hold_bits']==0 and not s['root_cache_hit']
                        assert detection_equivalent(reference[s['path']],s),(v,r['file'],s['path'])
                        comparison_count[v]+=1;latencies.append(1000*s['wall_seconds']);by_format[s['root_type']].append(1000*s['wall_seconds'])
            out['scan'][phase]=fields(process_rows)
            out['scan_latency_ms'][phase]={'observations':len(latencies),'median':statistics.median(latencies),'p95':percentile(latencies,.95),'p99':percentile(latencies,.99)}
            out['scan_by_format'][phase]={k:{'n':len(vals),'mean':statistics.mean(vals),'median':statistics.median(vals),'p95':percentile(vals,.95)} for k,vals in by_format.items()}
        out['warm_throughput_mib_per_second']=environment['fixture_bytes']/2**20/out['scan']['file_cache_hydrated']['wall_seconds']['mean']
        out['scan_hwm_kib_max']=max(b['hwm_kib'] for r in runs for b in r['rows'] if b['kind']=='batch')
        out['result_cache']={};diag=diagnostics[v]
        out['result_cache']['compiled_rss_kib']=stats(next(x for x in r['rows'] if x['kind']=='startup')['rss_kib'] for r in diag)
        capacity={next(x for x in r['rows'] if x['kind']=='startup')['cache_capacity'] for r in diag};assert len(capacity)==1
        out['result_cache']['capacity']=capacity.pop()
        for phase in ('result_cache_empty','result_cache_hydrated'):
            process_rows=[];hits=0;count=0
            for r in diag:
                batch=[b for b in r['rows'] if b['kind']=='batch' and b['phase']==phase];process_rows.append(mean_row(batch))
                for b in batch:hits+=b['root_cache_hits'];count+=b['files']
            out['result_cache'][phase]={'metrics':fields(process_rows),'root_cache_hits':hits,'files':count,'hit_percent':100*hits/count}
        assert out['result_cache']['result_cache_empty']['hit_percent']==0
        assert out['result_cache']['result_cache_hydrated']['hit_percent']==100
        out['result_cache']['cpu_reduction_percent']=100*(1-out['result_cache']['result_cache_hydrated']['metrics']['cpu_seconds']['mean']/out['result_cache']['result_cache_empty']['metrics']['cpu_seconds']['mean'])
        lifecycle=[r for r in records if r['stage']=='lifecycle' and r['variant']==v]
        reload=[next(x for x in r['rows'] if x['kind']=='reload') for r in lifecycle];out['reload']=fields(reload)
        out['updates']={}
        for db in ('main.cvd','daily.cvd','bytecode.cvd'):
            rows=[next(x for x in r['rows'] if x['kind']=='update_validation') for r in lifecycle if r['database']==db]
            assert all(x['return_code']==0 for x in rows);out['updates'][db]=fields(rows)
        out['update_overlap_peak_kib']=max(d['hwm_kib']['max'] for d in out['updates'].values())
        out['update_validation_cpu_seconds_full_set']=sum(d['cpu_seconds']['mean'] for d in out['updates'].values())
        for stage in ('positive','adverse'):
            entry=next((r for r in records if r['stage']==stage and r['variant']==v),None)
            if entry:
                scans=[s for s in entry['rows'] if s['kind']=='scan' and s['round']==0]
                out[stage]={'files':len(scans),'detected_verdicts':sum(s['verdict'] in (2,3) for s in scans),
                            'held':sum(bool(s['hold_bits']) for s in scans),'failures':sum(s['candidate_outcome']=='failed' for s in scans),
                            'integrity_changes':sum(s['sha256']!=s['after_sha256'] for s in scans),
                            'peak_rss_kib':max(s['hwm_kib'] for s in entry['rows'] if s['kind']=='batch')}
        result['variants'][v]=out
    original=result['variants']['upstream']
    for v,out in result['variants'].items():
        out['percent_full_signature_count']=100*out['signatures_loaded']/original['signatures_loaded']
        out['omitted_signature_count']=original['signatures_loaded']-out['signatures_loaded']
        out['compiled_rss_reduction_vs_upstream_percent']=100*(1-out['compiled_rss_kib']['mean']/original['compiled_rss_kib']['mean'])
    for a_name,b_name in [('upstream','full'),('upstream',RESTRICTED_VARIANT),('full',RESTRICTED_VARIANT)]:
        values={}
        for v in (a_name,b_name):
            values[v]={(r['round'],r['cache']):statistics.mean(b['wall_seconds'] for b in r['rows'] if b['kind']=='batch' and b['phase']=='file_cache_hydrated') for r in primary[v]}
        result['comparisons'][a_name+'-to-'+b_name]={'warm_scan_wall_percent':paired_percent(values[a_name],values[b_name])}
    pages=[row for r in records for row in r['rows'] if row['kind']=='page_cache']
    assert all(row['resident_percent']==(100 if row['requested_warm'] else 0) for row in pages)
    result['page_cache_working_sets']={}
    for label,phase in [('database','before_load'),('accepted_inputs','before_hydrated_scan')]:
        resident={row['resident_bytes'] for r in records if r['stage']=='primary'
                  for row in r['rows'] if row['kind']=='page_cache' and row['phase']==phase and row['requested_warm']}
        assert len(resident)==1
        result['page_cache_working_sets'][label]={'empty_resident_bytes':0,'hydrated_resident_bytes':resident.pop()}
    result['validation']={'primary_semantic_comparisons':dict(comparison_count),'all_primary_semantics_equal':True,
                          'page_cache_checks':len(pages),'all_page_cache_states_verified':True,
                          'result_cache_hits_verified':True,'all_updater_load_tests_passed':True,
                          'all_unrar_runtime_module_checks_passed':True,
                          'valid_fixture_count':environment['fixture_count'],'unique_fixture_hashes':len({s['sha256'] for s in reference.values()})}
    result['validation']['extended_comparisons']={}
    for stage in ('positive','adverse'):
        by_variant={v:{(s['path'],s['round']):s for r in records if r['stage']==stage and r['variant']==v
                       for s in r['rows'] if s['kind']=='scan'} for v in VARIANTS}
        base=by_variant['upstream']
        result['validation']['extended_comparisons'][stage]={}
        for v in ('full',RESTRICTED_VARIANT):
            mismatches=[];eligible=0;eligible_mismatches=[]
            for key,left in base.items():
                right=by_variant[v][key]
                equal=detection_equivalent(left,right)
                if not equal:mismatches.append({'path':key[0],'round':key[1],
                    'upstream_verdict':left['verdict'],'variant_verdict':right['verdict'],
                    'upstream_holds':left['hold_bits'],'variant_holds':right['hold_bits']})
                allowed=left['root_type'] in ('CL_TYPE_PDF','CL_TYPE_JPEG','CL_TYPE_PNG') and left['hold_bits']==0
                if allowed:
                    eligible+=1
                    if not equal:eligible_mismatches.append(key)
            result['validation']['extended_comparisons'][stage][v]={
                'comparisons':len(base),'equivalent':len(base)-len(mismatches),
                'mismatches':mismatches,'eligible':eligible,'eligible_mismatches':eligible_mismatches}
            assert not eligible_mismatches,(stage,v,'eligible detection mismatch')
            if v=='full':assert not mismatches,(stage,'full database detection mismatch',mismatches)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'completed_processes':len(records),'validation':result['validation'],'comparisons':result['comparisons']},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--results',type=Path,required=True);p.add_argument('--output',type=Path,required=True);main(p.parse_args())
