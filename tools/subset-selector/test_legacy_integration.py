#!/usr/bin/env python3
"""1.4 public-API differential tests; no invented modern severity values.
Synthetic unsigned signatures, harmless marker data. GPL-2.0-only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from equivalence import detection_equivalent


def main(a):
    a.output.mkdir(parents=True, exist_ok=False)
    marker = a.output / 'marker.pdf'
    marker.write_bytes(b'%PDF-1.7\n%' + b' ' * 1024 + b'ABCDEFGH' + b' ' * 1024 + b'\n%%EOF\n')
    files = a.output / 'files.txt'
    files.write_text(str(marker) + '\n')
    report = []

    def scan(db, skips, probe, label):
        cmd = [str(probe), str(db), str(a.certs), str(skips), str(files), '1', '0', '0', '0', 'all']
        with (a.output / (label + '.jsonl')).open('w') as out, (a.output / (label + '.stderr')).open('w') as err:
            subprocess.run(cmd, stdout=out, stderr=err, check=True, timeout=120)
        records = [json.loads(s) for s in (a.output / (label + '.jsonl')).read_text().splitlines()]
        assert next(r for r in records if r['kind'] == 'runtime')['scan_api'] == 'legacy-1.4'
        rows = [r for r in records if r['kind'] == 'scan']
        assert len(rows) == 1 and rows[0]['path'] == str(marker)
        return rows[0]

    for kind in ('strong', 'weak', 'pua', 'weak-only', 'pua-only'):
        db = a.output / kind
        db.mkdir()
        skip = db / 'skip.tsv'
        with (db / 'test.ndb').open('w') as signatures, skip.open('w') as exclusions:
            for i in range(a.rules):
                prefix = 'Heuristics' if kind.startswith('weak') else 'PUA' if kind.startswith('pua') else 'Synthetic'
                if kind in ('weak', 'pua') and i == a.rules // 2:
                    prefix = 'Synthetic.Strong'
                signatures.write(f'{prefix}.Order.{i:05d}:0:*:41424344??464748\n')
                digest = hashlib.sha256(f'distractor/{i}'.encode()).hexdigest()[:24]
                signatures.write(f'PE.Excluded.{i:05d}:1:*:{digest[:12]}??{digest[14:]}\n')
                exclusions.write(f'ndb\tPE.Excluded.{i:05d}\n')
        old = scan(db, '-', a.baseline_probe, kind + '-original')
        full = scan(db, '-', a.probe, kind + '-full')
        reduced = scan(db, skip, a.probe, kind + '-reduced')
        # Name order can change under the memory representation. Compare all-match
        # named evidence with multiplicity, return codes, layers and holds.
        assert old['return_code'] == full['return_code'] == reduced['return_code'] == 1
        assert full['verdict'] is None and reduced['verdict'] is None
        assert detection_equivalent(old, full), kind + ': original/full differs'
        assert detection_equivalent(full, reduced), kind + ': full/reduced differs'
        names = [e['name'] for e in full['events'] if e['event'] == 'legacy_virus']
        assert len(names) >= a.rules, (kind, len(names))
        report.append({'kind': kind, 'original_full_equivalent': True, 'reduced_equivalent': True,
                       'named_callback_count': len(names), 'modern_severity_available': False})
    summary = {'passed': True, 'rules_per_family': a.rules, 'families': report,
               'contract': 'legacy return codes, named callback multisets, layer sequence and policy holds',
               'automatic_release_qualified': False}
    (a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('probe', 'baseline-probe', 'certs', 'output'):
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--rules', type=int, default=10000)
    a = p.parse_args()
    for key in ('probe', 'baseline_probe', 'certs', 'output'):
        setattr(a, key, getattr(a, key).resolve())
    if a.rules < 2:
        p.error('--rules must be at least 2')
    main(a)
