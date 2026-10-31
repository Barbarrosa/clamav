#!/usr/bin/env python3
"""Probe whether AC first-match ordering can hide a stronger matching indicator.

Uses harmless custom signatures, not malware. This is a diagnostic: failures
are recorded in JSON; --require-strong additionally makes them fail the command.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clamscan', type=Path, required=True)
    parser.add_argument('--certs', type=Path, help='Explicit signature-verification certificate directory')
    parser.add_argument('--library', action='append', required=True, help='LABEL=DIR')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--strong-index', type=int, action='append', required=True)
    parser.add_argument('--rules', type=int, default=10000)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--require-strong', action='append', default=[])
    args = parser.parse_args()
    if args.repeats < 1 or args.rules < 1 or any(
            i < 0 or i >= args.rules for i in args.strong_index):
        parser.error('invalid rule count, repetition count or strong index')
    libraries = {}
    for spec in args.library:
        label, sep, path = spec.partition('=')
        if not sep or not label or label in libraries:
            parser.error('expected unique LABEL=DIR')
        libraries[label] = Path(path).resolve()
    if any(label not in libraries for label in args.require_strong):
        parser.error('unknown --require-strong library')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    target = out / 'marker.bin'
    target.write_bytes(b'\0' * 1024 + b'ABCDEFGH' + b'\0' * 1024)
    report = {
        'kind': 'mixed_severity_order_differential',
        'rules': args.rules,
        'marker_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
        'libraries': {label: hashlib.sha256((lib / 'libclamav.so').read_bytes()).hexdigest()
                      for label, lib in libraries.items()},
        'cases': [],
    }
    failures = []
    for index in args.strong_index:
        expected = f'Foundations.Order.{index:05d}.UNOFFICIAL'
        for category in ('Weak', 'PUA'):
            database = out / f'{category.lower()}-{index:05d}.ndb'
            with database.open('w') as stream:
                for i in range(args.rules):
                    name = f'Foundations.Order.{i:05d}'
                    if i != index:
                        prefix = category + '.'
                        name = prefix + 'X' * (len(name) - len(prefix) - 6) + f'.{i:05d}'
                    stream.write(f'{name}:0:*:41424344??464748\n')
                    body = hashlib.sha256(f'distractor/{i}'.encode()).digest()[:12].hex()
                    stream.write(f'Foundations.Other.{i:05d}:0:*:{body[:12]}??{body[14:]}\n')
            case = {'strong_index': index, 'other_category': category,
                    'database_sha256': hashlib.sha256(database.read_bytes()).hexdigest(),
                    'results': {}}
            for label, lib in libraries.items():
                case['results'][label] = {}
                for mode in ('first', 'all'):
                    runs = []
                    for _ in range(args.repeats if mode == 'first' else 1):
                        env = os.environ.copy()
                        env['LD_LIBRARY_PATH'] = str(lib)
                        command = [str(args.clamscan.resolve()), '--no-summary', '--stdout',
                                   '--detect-pua=yes', '--heuristic-scan-precedence=no',
                                   '-d', str(database), str(target)]
                        if args.certs:
                            command.extend(['--cvdcertsdir', str(args.certs.resolve())])
                        if mode == 'all':
                            command.append('--allmatch')
                        run = subprocess.run(command, env=env, capture_output=True, text=True)
                        lines = run.stdout.splitlines()
                        prefix = str(target) + ': '
                        if run.returncode not in (0, 1) or not lines or any(
                                not line.startswith(prefix) or not
                                (line.endswith(' FOUND') or line == prefix + 'OK') for line in lines):
                            raise RuntimeError(f'{label}/{mode}: {run.returncode}: {run.stdout} {run.stderr}')
                        names = [line[len(prefix):-6] for line in lines if line.endswith(' FOUND')]
                        result = {'exit': run.returncode, 'first_output': lines[0][len(prefix):],
                                  'alert_count': len(names), 'strong_found': expected in names,
                                  'stderr': run.stderr}
                        runs.append(result)
                        if not result['strong_found']:
                            failures.append({'library': label, 'mode': mode, 'index': index,
                                             'category': category})
                    case['results'][label][mode] = runs
                print(f'{category}/{index:05d}/{label}: '
                      f'{case["results"][label]["first"][0]["first_output"]}', flush=True)
            report['cases'].append(case)
    report['missing_strong_observations'] = failures
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    if any(failure['library'] in args.require_strong for failure in failures):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
