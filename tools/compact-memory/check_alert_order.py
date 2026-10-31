#!/usr/bin/env python3
"""Compare first-alert selection and ordered all-match alerts across libraries.

Harmless markers and custom signatures stress allocator-address tie breaking.
The all-match multiset and ordered sequence are reported separately.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def digest(lines):
    return hashlib.sha256(('\n'.join(lines) + '\n').encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clamscan', type=Path, required=True)
    parser.add_argument('--certs', type=Path, help='Explicit signature-verification certificate directory')
    parser.add_argument('--library', action='append', required=True, help='LABEL=LIBRARY_DIRECTORY')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rules', type=int, default=10000)
    parser.add_argument('--hash-distractors', type=int, default=0, help='Preload hash allocations before AC tie fixtures')
    parser.add_argument('--expect-equal', action='append', default=[], help='LABEL=LABEL; check both modes')
    args = parser.parse_args()
    if args.rules < 1:
        parser.error('rules must be positive')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    database_dir = out / 'database'
    database_dir.mkdir(exist_ok=True)
    if args.hash_distractors:
        with (database_dir / 'preload.hdb').open('w') as stream:
            for i in range(args.hash_distractors):
                h = hashlib.md5(f'hash-distractor/{i}'.encode()).hexdigest()
                stream.write(f'{h}:{i+1}:Foundations.Hash.{i}\n')
    database, target = database_dir / 'ordering.ndb', out / 'marker.bin'
    with database.open('w') as stream:
        for i in range(args.rules):
            stream.write(f'Foundations.Order.{i:05d}:0:*:41424344??464748\n')
            body = hashlib.sha256(f'distractor/{i}'.encode()).digest()[:12].hex()
            stream.write(f'Foundations.Other.{i:05d}:0:*:{body[:12]}??{body[14:]}\n')
    target.write_bytes(b'\0' * 1024 + b'ABCDEFGH' + b'\0' * 1024)
    libraries, hashes, results = {}, {}, {}
    for spec in args.library:
        label, sep, path = spec.partition('=')
        if not sep or not re.fullmatch('[a-z0-9_-]+', label) or label in libraries:
            parser.error('expected unique LABEL=PATH')
        libraries[label] = Path(path).resolve()
        hashes[label] = hashlib.sha256((libraries[label] / 'libclamav.so').read_bytes()).hexdigest()
    for mode in ('first', 'all'):
        results[mode] = {}
        for label, lib in libraries.items():
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = str(lib)
            command = [str(args.clamscan.resolve()), '--no-summary', '--stdout', '-d', str(database_dir), str(target)]
            if args.certs:
                command.extend(['--cvdcertsdir', str(args.certs.resolve())])
            if mode == 'all':
                command.append('--allmatch')
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            if result.returncode != 1:
                raise RuntimeError(f'{label}/{mode}: {result.returncode}: {result.stderr}')
            lines = result.stdout.splitlines()
            prefix = str(target) + ': '
            if not lines or any(not line.startswith(prefix) or not line.endswith(' FOUND') for line in lines):
                raise RuntimeError('Unexpected scanner output')
            names = [line[len(prefix):-len(' FOUND')] for line in lines]
            results[mode][label] = {'count': len(names), 'ordered_sha256': digest(names),
                                    'multiset_sha256': digest(sorted(names)),
                                    'distinct_names': len(Counter(names)),
                                    'first': names[0], 'last': names[-1]}
    failures = []
    for pair in args.expect_equal:
        left, sep, right = pair.partition('=')
        if not sep or left not in libraries or right not in libraries:
            parser.error('unknown library in --expect-equal')
        for mode in results:
            if results[mode][left] != results[mode][right]:
                failures.append(f'{mode}: {left} != {right}')
    report = {'kind': 'duplicate_alert_order_differential', 'rule_pairs': args.rules, 'hash_distractors': args.hash_distractors,
              'database_sha256': hashlib.sha256(database.read_bytes()).hexdigest(),
              'libraries': hashes, 'results': results, 'required_comparison_failures': failures}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
