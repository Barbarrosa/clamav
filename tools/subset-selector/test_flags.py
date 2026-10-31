#!/usr/bin/env python3
"""Real-engine regression: configured modes versus the previous full probe.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from equivalence import detection_equivalent
from select_db import sha


def main(a):
    a.output.mkdir(parents=True, exist_ok=True)
    records = {}
    commands = {}
    common = [sys.executable, str(Path(__file__).with_name('scan.py')),
              '--generation', str(a.generation), '--probe', str(a.probe),
              '--lib', str(a.lib), '--certs', str(a.certs), '--files', str(a.fixtures)]
    commands['baseline'] = [str(a.baseline_probe), str(a.generation/'databases'),
                            str(a.certs), '-', str(a.fixtures), '1', '0', '0', '0']
    commands['default'] = common
    commands['full'] = common + ['--database-profile=full']
    commands['full-all'] = common + ['--database-profile=full', '--allmatch']
    commands['restricted'] = common + ['--database-profile=legal-redress']
    for label, cmd in commands.items():
        with (a.output/(label+'.jsonl')).open('w') as out, (a.output/(label+'.stderr')).open('w') as err:
            result = subprocess.run(cmd, stdout=out, stderr=err)
        assert result.returncode == 0, (label, result.returncode)
        records[label] = [json.loads(l) for l in (a.output/(label+'.jsonl')).read_text().splitlines() if l.startswith('{')]
        print('completed', label, flush=True)
    def rows(label, mode):
        return [r for r in records[label] if r['kind']=='scan' and r['allmatch']==mode]
    def exact(row):
        return {k:v for k,v in row.items() if k!='seconds'}
    count = len(a.fixtures.read_text().splitlines())
    comparisons = []
    for label, mode in [('default',0),('full',0),('full-all',1)]:
        reference, actual = rows('baseline',mode), rows(label,mode)
        assert len(reference)==len(actual)==count, (label, 'missing scans')
        assert all(exact(x)==exact(y) for x,y in zip(reference,actual)), label+' changed full results'
        engine = next(r for r in records[label] if r['kind']=='engine')
        assert engine['skipped']==0 and engine['sigload_calls']==0
        comparisons.append({'mode':label,'exact_full_baseline_matches':count})
    full, reduced = rows('full-all',1), rows('restricted',1)
    assert len(full)==len(reduced)==count
    assert not rows('restricted',0), 'restricted mode must never use first-hit'
    engine = next(r for r in records['restricted'] if r['kind']=='engine')
    assert engine['skipped']>0
    eligible = []; held = 0
    for x,y in zip(full,reduced):
        assert x['path']==y['path']
        assert x['sha256']==y['sha256']==y['after_sha256']
        assert y['outcome']!='clean', 'incomplete parser gate bypassed'
        if x['hold_bits'] or y['hold_bits']:
            assert y['outcome'] in ('held','failed'), 'full policy hold lost'
            held += 1
        elif x['candidate_outcome']=='failed' or y['candidate_outcome']=='failed':
            assert x['candidate_outcome']==y['candidate_outcome']
        else:
            assert detection_equivalent(x,y), 'detection difference: '+x['path']
            eligible.append(x['path'])
    summary = {'baseline_probe_sha256':sha(a.baseline_probe), 'probe_sha256':sha(a.probe),
               'library_sha256':sha(a.lib), 'generation_manifest_sha256':sha(a.generation/'manifest.json'),
               'fixture_list_sha256':sha(a.fixtures), 'commands':commands,
               'full_comparisons':comparisons, 'restricted_allmatch_only':True,
               'eligible_detection_equivalence_matches':len(eligible), 'held_cases':held,
               'reduced_automatic_release':False, 'passed':True}
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('baseline-probe','probe','lib','certs','generation','fixtures','output'):
        p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args()
    for key,value in vars(a).items():setattr(a,key,value.resolve())
    main(a)
