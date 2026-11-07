#!/usr/bin/env python3
"""Bounded synthetic differential gates for full-rule memory changes.

Preserves ordered callbacks, final names, verdicts, errors and inputs. This is
observational evidence on explicit fixtures, not all-input equivalence or a
performance qualification. SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
SCAN_KEYS = ('round', 'allmatch', 'return_code', 'verdict', 'final_name', 'root_type',
             'sha256', 'after_sha256', 'hold_bits', 'candidate_outcome', 'scanned_bytes', 'events')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def semantic(scans):
    return [{key: row[key] for key in SCAN_KEYS} for row in scans]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def alerts(row):
    return [event['name'] for event in row['events'] if event['event'] == 'alert']


def generate_fixtures(output, rules=10000, hash_distractors=10000):
    """The ordering bytes match tools/compact-memory/check_alert_order.py."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    marker = output / 'marker.bin'
    marker.write_bytes(b'\0' * 1024 + b'ABCDEFGH' + b'\0' * 1024)
    sequential = output / 'sequential.bin'
    sequential.write_bytes(b'ABCDEFGH--IJKLMNOP')
    short = output / 'short.bin'
    short.write_bytes(b'ABCDEFGH')
    cases = []

    def add(name, entries, files, predicate, action=0, repeat=1, environment=None, reject=False):
        database = output / name
        database.mkdir()
        for filename, text in entries.items():
            (database / filename).write_text(text)
        listing = output / (name + '.txt')
        listing.write_text(''.join(str(Path(path).resolve()) + '\n' for path in files))
        cases.append({'name': name, 'database': str(database), 'files': str(listing),
                      'inputs': [{'path': str(Path(path).resolve()), 'sha256': sha(path) if Path(path).exists() else None}
                                 for path in files], 'predicate': predicate, 'action': action,
                      'repeats': repeat, 'environment': environment or {}, 'reject_load': reject,
                      'database_sha256': {p.name: sha(p) for p in sorted(database.iterdir())}})

    ordering = []
    for i in range(rules):
        ordering.append(f'Foundations.Order.{i:05d}:0:*:41424344??464748\n')
        body = hashlib.sha256(f'distractor/{i}'.encode()).digest()[:12].hex()
        ordering.append(f'Foundations.Other.{i:05d}:0:*:{body[:12]}??{body[14:]}\n')
    hashes = ''.join(f'{hashlib.md5(f"hash-distractor/{i}".encode()).hexdigest()}:{i+1}:Foundations.Hash.{i}\n'
                     for i in range(hash_distractors))
    add('duplicate-order', {'ordering.ndb': ''.join(ordering), 'preload.hdb': hashes},
        [marker], {'kind': 'ordering', 'expected': rules}, repeat=2)

    for category in ('Weak', 'PUA'):
        for strong in sorted(set((0, rules // 2, rules - 1))):
            records = []
            for i in range(rules):
                name = f'Foundations.Order.{i:05d}'
                if i != strong:
                    prefix = category + '.'
                    name = prefix + 'X' * (len(name) - len(prefix) - 6) + f'.{i:05d}'
                records.append(f'{name}:0:*:41424344??464748\n')
                body = hashlib.sha256(f'distractor/{i}'.encode()).digest()[:12].hex()
                records.append(f'Foundations.Other.{i:05d}:0:*:{body[:12]}??{body[14:]}\n')
            add(f'severity-{category.lower()}-{strong}', {'rules.ndb': ''.join(records)}, [marker],
                {'kind': 'strong', 'expected': f'Foundations.Order.{strong:05d}.UNOFFICIAL'})

    for category in ('Weak', 'PUA', 'Heuristics'):
        add('nonterminal-' + category.lower(), {'rules.ndb':
            f'{category}.First:0:*:41424344??464748\nStrong.Second:0:*:494a4b4c??4e4f50\n'},
            [sequential], {'kind': 'strong', 'expected': 'Strong.Second.UNOFFICIAL'})
    for category in ('Weak', 'PUA'):
        add('only-' + category.lower(), {'rules.ndb': f'{category}.Only:0:*:41424344??464748\n'},
            [short], {'kind': 'no_strong'})

    strong_db = {'rules.ndb': 'Strong.First:0:*:41424344??464748\nStrong.Second:0:*:494a4b4c??4e4f50\n'}
    for action, name in ((1, 'ignore'), (2, 'stop'), (3, 'trust')):
        add('callback-' + name, strong_db, [sequential], {'kind': name}, action=action)
    md5 = hashlib.md5(marker.read_bytes()).hexdigest()
    add('false-positive-trust', {'rules.ndb': 'Strong.Marker:0:*:41424344??464748\n',
        'rules.hdb': f'{md5}:{marker.stat().st_size}:Strong.WholeFile\n',
        'rules.fp': f'{md5}:{marker.stat().st_size}:Trusted.Marker\n'},
        [marker], {'kind': 'trusted'})
    add('file-limit', strong_db, [marker], {'kind': 'limit'}, environment={'SUBSET_TEST_MAX_FILESIZE': '1024'})
    add('missing-file', strong_db, [output / 'missing.bin'], {'kind': 'missing'})
    add('invalid-database', {'rules.ndb': 'Invalid.Marker:0:*:THIS_IS_NOT_HEX\n'},
        [marker], {'kind': 'rejected'}, reject=True)

    macro_yes, macro_no = output / 'macro-yes.bin', output / 'macro-no.bin'
    macro_yes.write_bytes(b'ABCDMACROABCDMACRO')
    macro_no.write_bytes(b'ABCD' + b'x' * 100 + b'MACROABCD' + b'x' * 100 + b'MACRO')
    add('macro-fallback', {'rules.ndb': 'Macro.Group:0:$0$:4d4143524f\n',
        'rules.ldb': 'Strong.Macro;Engine:54-255,Target:0;0&1;41424344;${4-16}0$\n'},
        [macro_yes, macro_no], {'kind': 'macro', 'expected': 'Strong.Macro.UNOFFICIAL'})
    add('invalid-macro', {'rules.ldb':
        'Invalid.Macro;Engine:54-255,Target:0;0&1;41424344;${4-16}32$\n'},
        [marker], {'kind': 'rejected'}, reject=True)
    add('custom-logical', {'rules.ldb':
        'Strong.Logical;Engine:54-255,Target:0;0&1;41424344;45464748\n'},
        [short], {'kind': 'strong', 'expected': 'Strong.Logical.UNOFFICIAL'})
    add('custom-patterns', {'rules.ndb':
        'Strong.Wild:0:*:4142??4445464748\n'
        'Strong.Alt:0:*:4142(4344|5859)45464748\n'
        'Strong.Gap:0:*:4142{1-3}4445464748\n'},
        [short], {'kind': 'ordering', 'expected': 3})
    return cases


def predicate_failures(case, rows):
    failures = []
    kind = case['predicate']['kind']
    for i, row in enumerate(rows):
        names = alerts(row)
        if kind == 'ordering':
            # Some retained-baseline paths emit repeated callbacks for a final
            # label. Preserve that exact multiplicity in the differential;
            # independently require every expected distinct rule to appear.
            if row['allmatch']:
                if len(set(names)) != case['predicate']['expected']:
                    failures.append(f'scan {i}: wrong distinct detection count')
            elif len(names) != 1:
                failures.append(f'scan {i}: wrong first-detection count')
        if kind == 'strong' and case['predicate']['expected'] not in names:
            failures.append(f'scan {i}: required strong indicator absent')
        if kind == 'no_strong' and (row['verdict'] == 2 or row['final_name'] and str(row['final_name']).startswith('Strong.')):
            failures.append(f'scan {i}: invented strong indicator')
        if kind == 'ignore' and (not names or row['final_name'] is not None):
            failures.append(f'scan {i}: ignore callback did not suppress accepted alerts')
        if kind == 'stop' and (not row['hold_bits'] & 128 or len(names) != 1):
            failures.append(f'scan {i}: stop callback was not honored')
        if kind == 'trust' and (not row['hold_bits'] & 256 or len(names) != 1 or row['verdict'] != 1):
            failures.append(f'scan {i}: trust callback was not honored')
        if kind == 'trusted' and row['verdict'] != 1:
            failures.append(f'scan {i}: false-positive trust changed')
        if kind == 'limit' and row['candidate_outcome'] == 'clean':
            failures.append(f'scan {i}: exceeded limit became clean')
        if kind == 'missing' and row['candidate_outcome'] != 'failed':
            failures.append(f'scan {i}: missing input did not fail')
        if kind == 'macro':
            expected = case['predicate']['expected']
            positive = case['inputs'][i % len(case['inputs'])]['path'].endswith('macro-yes.bin')
            if (expected in names) != positive:
                failures.append(f'scan {i}: macro fallback produced wrong result')
    return failures


def validate_run(case, rows, returncode, library_sha256, limits):
    runtimes = [row for row in rows if row.get('kind') == 'runtime']
    if not runtimes or any(row.get('engine_sha256') != library_sha256 or not row.get('unrar_modules_verified') for row in runtimes):
        raise ValueError('missing/wrong runtime library identity or unrar modules')
    observed = [row for row in rows if row.get('kind') == 'qualification_limits']
    if len(observed) != 1 or any(observed[0].get(key) != value for key, value in limits.items()):
        raise ValueError('process resource limits differ from plan')
    scans = [row for row in rows if row.get('kind') == 'scan']
    if case['reject_load']:
        if returncode != 2 or scans or any(row.get('kind') == 'engine' for row in rows):
            raise ValueError('malformed database was not cleanly rejected during loading')
        return {'semantic_sha256': digest({'load_rejected': True, 'return_code': returncode}),
                'scan_records': 0, 'predicate_failures': [], 'signatures': None}
    if returncode != 0 or len(scans) != len(case['inputs']) * 2 * case['repeats']:
        raise ValueError('process failed or scan observations incomplete')
    engines = [row for row in rows if row.get('kind') == 'engine']
    if len(engines) != 1:
        raise ValueError('missing/duplicate engine load record')
    for i, row in enumerate(scans):
        expected = case['inputs'][i % len(case['inputs'])]
        expected_round = i // (2 * len(case['inputs']))
        expected_allmatch = (i // len(case['inputs'])) % 2
        if row.get('round') != expected_round or row.get('allmatch') != expected_allmatch or row.get('path') != expected['path']:
            raise ValueError('scan order/path differs from plan')
        before, after = row.get('sha256'), row.get('after_sha256')
        if expected['sha256'] is not None and (before != expected['sha256'] or after != before):
            raise ValueError('wrong or modified scan input')
        if expected['sha256'] is None and (before or after):
            raise ValueError('missing-input case unexpectedly scanned another input')
    value = semantic(scans)
    return {'semantic_sha256': digest(value), 'scan_records': len(scans),
            'predicate_failures': predicate_failures(case, scans), 'signatures': engines[0]['signatures'],
            'ordered_alert_sha256': digest([alerts(row) for row in scans]),
            'alert_multiset_sha256': digest([sorted(Counter(alerts(row)).items()) for row in scans])}


def build_probe(args, library, output):
    source = output / 'correctness-probe.c'
    probe_source = ROOT / 'tools/subset-selector/scan_probe.c'
    source.write_text('''#define _GNU_SOURCE
#include "clamav.h"
#include <stdio.h>
#include <sys/resource.h>
static void runtime_identity(void);
static cl_error_t qualified_load(const char *path, struct cl_engine *engine, unsigned *count, unsigned options) {
    struct rlimit a, c;
    runtime_identity();
    if (getrlimit(RLIMIT_AS,&a) || getrlimit(RLIMIT_CPU,&c)) return CL_EARG;
    printf("{\\"kind\\":\\"qualification_limits\\",\\"address_space_bytes\\":%llu,\\"cpu_seconds\\":%llu}\\n",
           (unsigned long long)a.rlim_cur,(unsigned long long)c.rlim_cur);
    fflush(stdout);
    return cl_load(path,engine,count,options|CL_DB_PUA);
}
#define cl_load qualified_load
''' + '#include ' + json.dumps(str(probe_source)) + '\n')
    binary = output / 'correctness-probe'
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c', 'openssl'], text=True))
    command = [args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-DSUBSET_BOUNDARY_TEST',
               '-I' + str(ROOT / 'libclamav'), '-I' + str(args.build), '-Wl,--export-dynamic']
    command += ['-I' + str(path) for path in args.include]
    command += [str(source), '-L' + str(library.parent), '-Wl,--disable-new-dtags',
                '-Wl,-rpath,' + ':'.join(str(path) for path in [library.parent] + args.runtime_dir)]
    command += ['-L' + str(path) for path in args.library_path]
    command += ['-lclamav', '-ldl'] + flags + ['-o', str(binary)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    return binary, source


def execute(args, case, role, library, probe, output):
    stem = role + '-' + case['name']
    stdout, stderr = output / (stem + '.jsonl'), output / (stem + '.stderr')
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith(('SUBSET_', 'CM_PAD_', 'BENCH_')) or name == 'LD_PRELOAD':
            environment.pop(name)
    environment['LD_LIBRARY_PATH'] = ':'.join(str(path) for path in [library.parent] + args.runtime_dir)
    environment.update(case['environment'])
    limits = {'address_space_bytes': args.address_space_bytes, 'cpu_seconds': args.cpu_seconds}

    def impose_limits():
        resource.setrlimit(resource.RLIMIT_AS, (args.address_space_bytes, args.address_space_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (args.cpu_seconds, args.cpu_seconds + 5))
        if args.cpu is not None:
            os.sched_setaffinity(0, {args.cpu})

    command = [str(probe), case['database'], str(args.certs), '-', case['files'],
               str(case['repeats']), '0', str(case['action']), '0']
    start = time.monotonic()
    record = {'role': role, 'case': case['name'], 'status': 'failed', 'timeout': False}
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(command, env=environment, stdout=out, stderr=err, preexec_fn=impose_limits)
        try:
            process.wait(timeout=args.wall_seconds)
        except subprocess.TimeoutExpired:
            record['timeout'] = True
            process.kill()
            process.wait()
    record.update(return_code=process.returncode, wall_seconds=time.monotonic() - start,
                  stdout=stdout.name, stderr=stderr.name, stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    try:
        if record['timeout'] or process.returncode < 0:
            raise ValueError('process timed out or terminated by signal')
        if any(sha(Path(case['database']) / name) != expected
               for name, expected in case['database_sha256'].items()):
            raise ValueError('signature fixture changed during the run')
        rows = [json.loads(line) for line in stdout.read_text().splitlines() if line.strip()]
        record.update(validate_run(case, rows, process.returncode, sha(library), limits))
        if record['predicate_failures']:
            raise ValueError('; '.join(record['predicate_failures']))
        record['status'] = 'passed'
    except (ValueError, KeyError, TypeError) as error:
        record['error'] = str(error)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'baseline-library', 'candidate-library', 'certs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--include', type=Path, action='append', default=[])
    parser.add_argument('--library-path', type=Path, action='append', default=[])
    parser.add_argument('--runtime-dir', type=Path, action='append', default=[])
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--rules', type=int, default=10000)
    parser.add_argument('--hash-distractors', type=int, default=10000)
    parser.add_argument('--address-space-bytes', type=int, default=3 * 1024**3)
    parser.add_argument('--cpu-seconds', type=int, default=60)
    parser.add_argument('--wall-seconds', type=int, default=90)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--allow-same-library-smoke', action='store_true')
    args = parser.parse_args()
    if not 2 <= args.rules <= 10000 or not 0 <= args.hash_distractors <= 10000 or min(args.address_space_bytes, args.cpu_seconds, args.wall_seconds) < 1:
        parser.error('invalid bounded fixture dimensions or process limits')
    if args.cpu is not None and args.cpu not in os.sched_getaffinity(0):
        parser.error('requested CPU is unavailable')
    for name in ('build', 'baseline_library', 'candidate_library', 'certs', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    args.runtime_dir = [path.resolve() for path in args.runtime_dir]
    args.include = [path.resolve() for path in args.include]
    args.library_path = [path.resolve() for path in args.library_path]
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('output must be empty; results cannot be mixed with an earlier run')
    same = sha(args.baseline_library) == sha(args.candidate_library)
    if same and not args.allow_same_library_smoke:
        parser.error('identical library bytes provide only a smoke control, not a candidate comparison')
    args.output.mkdir(parents=True, exist_ok=True)
    cases = generate_fixtures(args.output / 'fixtures', args.rules, args.hash_distractors)
    binding = {'libraries': {}, 'sources': {
        'correctness.py': sha(Path(__file__)), 'scan_probe.c': sha(ROOT / 'tools/subset-selector/scan_probe.c'),
        'check_alert_order.py': sha(ROOT / 'tools/compact-memory/check_alert_order.py'),
        'check_alert_severity.py': sha(ROOT / 'tools/compact-memory/check_alert_severity.py')},
        'rules': args.rules, 'hash_distractors': args.hash_distractors,
        'certificate_files': {str(path.relative_to(args.certs)): sha(path) for path in sorted(args.certs.rglob('*')) if path.is_file()},
        'database_options': 'CL_DB_STDOPT | CL_DB_PUA', 'same_library_smoke': same}
    probes = {}
    for role in ('baseline', 'candidate'):
        library = getattr(args, role + '_library')
        directory = args.output / role
        directory.mkdir()
        probe, source = build_probe(args, library, directory)
        probes[role] = probe
        binding['libraries'][role] = {'library_sha256': sha(library), 'probe_sha256': sha(probe),
                                     'wrapper_source_sha256': sha(source)}
    plan = {'schema_version': 1, 'binding': binding, 'cases': cases,
            'resource_limits': {'address_space_bytes': args.address_space_bytes, 'cpu_seconds': args.cpu_seconds,
                                'cpu_hard_seconds': args.cpu_seconds + 5, 'wall_seconds': args.wall_seconds, 'cpu': args.cpu}}
    (args.output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    checks = []
    for case in cases:
        observations = {role: execute(args, case, role, getattr(args, role + '_library'), probes[role], args.output)
                        for role in ('baseline', 'candidate')}
        passed = (all(value['status'] == 'passed' for value in observations.values()) and
                  observations['baseline'].get('semantic_sha256') == observations['candidate'].get('semantic_sha256') and
                  observations['baseline'].get('signatures') == observations['candidate'].get('signatures'))
        checks.append({'case': case['name'], 'passed': passed, 'observations': observations})
        print(json.dumps({'case': case['name'], 'passed': passed,
                          'errors': {role: value.get('error') for role, value in observations.items() if value.get('error')}}), flush=True)
    passed = all(check['passed'] for check in checks)
    report = {'schema_version': 1, 'status': 'passed' if passed else 'failed', 'passed': passed,
              'distinct_artifact_comparison': not same, 'qualifying_comparison': passed and not same,
              'binding': binding, 'checks': checks,
              'observational_scan_records': sum(value.get('scan_records', 0) for check in checks for value in check['observations'].values()),
              'resource_limits': plan['resource_limits'],
              'known_preexisting_issue': 'A second public cl_engine_compile already crashes the preserved retained baseline; this run neither tests nor fixes repeated compilation.',
              'scope': 'Bounded synthetic correctness gates only, not all-input equivalence or performance qualification.'}
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
