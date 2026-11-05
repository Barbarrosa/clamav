#!/usr/bin/env python3
"""Collect the documented-flag experiment, without signed database bodies.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import gzip
import json
import shutil
import statistics
from pathlib import Path
from equivalence import detection_equivalent
from select_db import sha


def rows(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.startswith('{')]


def collect(a):
    a.output.mkdir(parents=True,exist_ok=True)
    bench=a.work/'configured-bench';b=json.loads((bench/'summary.json').read_text())
    native=json.loads((a.work/'native-final/summary.json').read_text())
    integration=json.loads((a.work/'integration-final/summary.json').read_text())
    asan=json.loads((a.work/'integration-asan/summary.json').read_text())
    assert native['passed'] and integration['accepting_allmatch_detection_equivalence_passed'] and asan['accepting_allmatch_detection_equivalence_passed']
    reference={(r['path'],r['round']):r for r in rows(bench/'pair-0-full.jsonl') if r['kind']=='scan'}
    counts={'full':0,'reduced':0};latencies={'full':[],'reduced':[]}
    for p in sorted(bench.glob('pair-*.jsonl')):
        variant='reduced' if 'reduced' in p.name else 'full'
        scans=[r for r in rows(p) if r['kind']=='scan']
        assert len(scans)==len(reference)==84
        for r in scans:
            assert r['allmatch']==1 and not r['hold_bits'] and r['candidate_outcome']=='clean'
            assert detection_equivalent(reference[(r['path'],r['round'])],r), (p,r['path'])
            counts[variant]+=1;latencies[variant].append(r['seconds']*1000)
    fresh={}
    for v in ('full','reduced'):
        reload=next(r for r in rows(bench/('reload-'+v+'.jsonl')) if r['kind']=='reload_overlap')
        timings=sorted(latencies[v])
        fresh[v]={'compiled_rss_mib_mean':b[v]['compiled_rss_kib_mean']/1024,
                  'construction_peak_mib_max':b[v]['construction_hwm_kib_max']/1024,
                  'scan_peak_mib_max':b[v]['scan_hwm_kib_max']/1024,
                  'reload_overlap_peak_mib':reload['construction_hwm_kib']/1024,
                  'load_seconds_mean':b[v]['load_seconds_mean'],'compile_seconds_mean':b[v]['compile_seconds_mean'],
                  'allmatch_batch_seconds_mean':b[v]['all_match_batch_seconds_mean'],
                  'per_file_milliseconds_median':statistics.median(timings),
                  'per_file_milliseconds_p95':timings[int(.95*(len(timings)-1))],
                  'equivalent_scan_count':counts[v]}
    manifest=json.loads((a.generation/'manifest.json').read_text())
    summary={'schema':1,'configuration_flag':'--database-profile=pdf-jpeg-png-pe-exclusions','default_flag':'--database-profile=full',
             'scan_mode':'restricted forces accepting all-match; full defaults to original first-hit',
             'fresh_measurements':fresh,
             'compiled_rss_reduction_percent':100*(1-b['reduced']['compiled_rss_kib_mean']/b['full']['compiled_rss_kib_mean']),
             'allmatch_batch_slowdown_percent':100*(b['reduced']['all_match_batch_seconds_mean']/b['full']['all_match_batch_seconds_mean']-1),
             'full_exact_baseline_comparisons':sum(x['exact_full_baseline_matches'] for x in native['full_comparisons']),
             'native_restricted_eligible_detection_equivalence_matches':native['eligible_detection_equivalence_matches'],
             'native_restricted_held_cases':native['held_cases'],
             'synthetic_allmatch_detection_equivalence_passed':True,
             'synthetic_cases':['strong','mixed-weak-strong','mixed-PUA-strong','weak-only','PUA-only'],
             'synthetic_rules_per_case':integration['rules_per_severity_fixture'],
             'asan_ubsan_probe_passed':True,'asan_scope':'adapter instrumented; retained shared engine unchanged; leak detection disabled',
             'historical_exact_order_gate_passed':integration['qualification_passed'],
             'automatic_reduced_release_enabled':False,'release_blocker':'parser-completeness-unproven',
             'selector_version':manifest['selector_version'],'skip_sha256':manifest['skip_sha256'],
             'generation_manifest_sha256':sha(a.generation/'manifest.json'),
             'baseline_probe_sha256':native['baseline_probe_sha256'],'probe_sha256':native['probe_sha256'],
             'engine_library_sha256':native['library_sha256'],
             'update_placement':'separate worker; full preparation and FreshClam validation do not fit 303 MiB alongside scanner',
             'scope':'pinned database and generated fixtures; no universal detection or parser-completeness proof; process RSS not isolated cgroup budget'}
    for dirname in ('native-final','integration-final','integration-asan','configured-bench'):
        dest=a.output/dirname;dest.mkdir(exist_ok=True)
        for p in sorted((a.work/dirname).iterdir()):
            if p.is_file() and (p.name.endswith(('.json','.stderr')) or p.suffix=='.jsonl'):
                if p.suffix=='.jsonl':
                    with (dest/(p.name+'.gz')).open('wb') as out,gzip.GzipFile(fileobj=out,mode='wb',mtime=0) as z:z.write(p.read_bytes())
                else:shutil.copyfile(p,dest/p.name)
    for name in ('unit-selector-final.log','unit-configuration-final.log','intake.json','intake.stderr','equivalence-replay.json','selector-final.log'):
        shutil.copyfile(a.work/name,a.output/name)
    shutil.copyfile(a.generation/'manifest.json',a.output/'generation-manifest.json')
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    files={p.relative_to(a.output).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(a.output.rglob('*')) if p.is_file() and p.name!='files.json'}
    (a.output/'files.json').write_text(json.dumps(files,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('work','generation','output'):p.add_argument('--'+key,type=Path,required=True)
    collect(p.parse_args())
