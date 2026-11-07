#!/usr/bin/env python3
"""Bounded, source-bound whole-engine measurements; missing evidence never passes.

This reuses the established scanner timings/cache controls and records all 18
contract dimensions. Unknown scratch/context extents stay null. Observational
passes are not all-input, statistical or deployment-wide guarantees.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import resource
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / 'tools/compact-memory/search-groundwork/baseline-contract.json'
SEMANTICS = ('phase', 'round', 'allmatch', 'return_code', 'verdict', 'final_name',
             'root_type', 'sha256', 'after_sha256', 'hold_bits', 'candidate_outcome',
             'scanned_bytes', 'input_bytes', 'events')
ROLES = ('upstream', 'retained', 'candidate')


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(part)
    return value.hexdigest()


def hash_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def verify_inputs(identities):
    for path, expected in identities.items():
        if not Path(path).is_file() or sha(path) != expected:
            raise ValueError('bound input/artifact changed: ' + path)


def module_identities(directories):
    result = {}
    for kind, prefix in (('iface', 'libclamunrar_iface.so'), ('unrar', 'libclamunrar.so')):
        for directory in directories:
            matches = sorted(Path(directory).glob(prefix + '*'))
            if matches:
                path = matches[0].resolve()
                result[kind] = {'path': str(path), 'sha256': sha(path)}
                break
        if kind not in result:
            raise ValueError('matching runtime directory missing for ' + kind)
    return result


def attach_evidence(args, variants):
    result = {}
    if args.correctness_report:
        report = json.loads(args.correctness_report.read_text())
        libraries = report.get('binding', {}).get('libraries', {})
        candidate = variants.get('candidate', {}).get('library_sha256')
        baselines = {variants[r]['library_sha256'] for r in ('retained', 'upstream') if r in variants}
        if (libraries.get('candidate', {}).get('library_sha256') != candidate or
                libraries.get('baseline', {}).get('library_sha256') not in baselines):
            raise ValueError('correctness report library binding differs from benchmark variants')
        result['correctness'] = {'sha256': sha(args.correctness_report),
            'qualifying_comparison': report.get('qualifying_comparison') is True,
            'status': report.get('status'),
            'scope': 'targeted independent suite only; not automatically all ten correctness properties'}
    if args.resource_audit:
        report = json.loads(args.resource_audit.read_text())
        candidate = variants.get('candidate', {}).get('source', {}).get('source_files', {})
        bound = {**report.get('whole_files_unchanged', {})}
        for field, path in (('observed_matcher_ac_sha256', 'libclamav/matcher-ac.c'),
                            ('observed_readdb_sha256', 'libclamav/readdb.c'),
                            ('observed_mpool_sha256', 'libclamav/mpool.c')):
            if report.get(field): bound[path] = report[field]
        if not bound or any(candidate.get(path) != digest for path, digest in bound.items()):
            raise ValueError('resource audit source binding is missing or stale')
        result['resource_audit'] = {'sha256': sha(args.resource_audit), 'source_binding_verified': True,
            'resource_deltas': report.get('resource_deltas'), 'scope': report.get('scope'),
            'interpretation': 'source-relative resource statements, not invented absolute zero-byte measurements'}
    return result


def numeric(value):
    return type(value) in (float, int) and value >= 0 and math.isfinite(value)


def quantile(values, fraction):
    if not values or not 0 < fraction <= 1 or any(not numeric(v) for v in values):
        raise ValueError('quantile needs finite nonnegative observations and 0<p<=1')
    return sorted(values)[math.ceil(fraction * len(values)) - 1]


def source_identity(path):
    path = Path(path).resolve()
    tracked = subprocess.check_output(['git', '-C', str(path), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).split(b'\0')
    suffixes = ('.c', '.h', '.cc', '.cpp', '.hpp', '.rs', '.cmake')
    identities = {}
    for entry in tracked:
        if not entry:
            continue
        name = os.fsdecode(entry)
        p = path / name
        if p.is_file() and (p.suffix in suffixes or p.name in ('CMakeLists.txt', 'Cargo.lock', 'Cargo.toml')):
            identities[name] = sha(p)
    return {'path': str(path),
            'revision': subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip(),
            'dirty': bool(subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True)),
            'source_files': identities, 'source_tree_sha256': hash_json(identities)}


def copy_database(source, destination):
    source, destination = Path(source).resolve(), Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for entry in sorted(source.iterdir()):
        if entry.is_symlink():
            raise ValueError('database directory must contain ordinary files, not symlinks')
        if entry.is_dir():
            raise ValueError('nested database directories require an explicit preparation adapter')
        if not entry.is_file():
            raise ValueError('database entry is not a regular file')
        target = destination / entry.name
        shutil.copyfile(entry, target)
        if target.stat().st_ino == entry.stat().st_ino and target.stat().st_dev == entry.stat().st_dev:
            raise ValueError('cache-control copy must have a separate inode')
        original = sha(entry)
        if sha(target) != original:
            raise ValueError('database bytes changed while copying')
        records.append({'name': entry.name, 'bytes': entry.stat().st_size, 'sha256': original})
    if not records:
        raise ValueError('database directory is empty')
    return records


def prepare_corpus(args, private):
    corpus = private / 'corpus'
    prepare = ROOT / 'tools/compact-memory/allocation-perturbation/prepare_corpus.py'
    subprocess.run([sys.executable, str(prepare), '--archive', str(args.archive),
                    '--output', str(corpus), '--per-group', '3' if args.stage == 'smoke' else '1000'], check=True)
    groups = {}
    for group in ('accepted', 'positive', 'adverse'):
        entries = sorted((corpus / group).iterdir())
        groups[group] = [{'path': str(p.resolve()), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in entries]
    groups['combined'] = [r for name in ('accepted', 'positive', 'adverse') for r in groups[name]]
    return groups


def semantic_transcript(rows, case, fixtures, repeats, concurrency):
    scans = [r for r in rows if r.get('kind') == 'scan']
    if case == 'scan':
        expected = [('file_cache_empty', 0)] + [('file_cache_hydrated', i) for i in range(1, repeats + 1)]
    elif case == 'concurrency':
        expected = [('concurrent_scan', i) for i in range(concurrency)]
    else:
        expected = []
    if len(scans) != len(expected) * len(fixtures):
        raise ValueError('incomplete scan transcript')
    canonical = []
    for phase, round_number in expected:
        group = [r for r in scans if r['phase'] == phase and r['round'] == round_number]
        if len(group) != len(fixtures):
            raise ValueError('missing or duplicate scan phase/round')
        for row, fixture in zip(group, fixtures):
            if (row.get('path') != fixture['path'] or row.get('sha256') != fixture['sha256'] or
                    row.get('after_sha256') != fixture['sha256'] or row.get('input_bytes') != fixture['bytes']):
                raise ValueError('scan input differs from ordered fixture manifest')
            if not numeric(row.get('engine_scan_wall_seconds')) or not numeric(row.get('engine_scan_cpu_seconds')):
                raise ValueError('missing/invalid measured per-file latency or CPU')
            if not isinstance(row.get('events'), list):
                raise ValueError('ordered callback transcript missing')
            canonical.append({key: row[key] for key in SEMANTICS})
    return hash_json(canonical), scans


def extract(rows, case, fixtures, args, identity):
    def one(kind):
        found = [r for r in rows if r.get('kind') == kind]
        if len(found) != 1:
            raise ValueError('missing/duplicate ' + kind + ' row')
        return found[0]
    runtime = one('runtime')
    if runtime.get('engine_sha256') != identity['library_sha256'] or not runtime.get('unrar_modules_verified'):
        raise ValueError('wrong runtime engine or missing unrar modules')
    limits = one('resource_limits')
    if (limits.get('address_space_bytes') != args.address_space_bytes or
            limits.get('cpu_soft_seconds') != args.cpu_seconds or limits.get('cpu_hard_seconds') != args.cpu_seconds + 5):
        raise ValueError('observed process limits differ from requested limits')
    expected_affinity = args.concurrency_cpus if case == 'concurrency' else [args.cpu]
    if limits.get('cpu_affinity') != sorted(expected_affinity):
        raise ValueError('observed CPU affinity differs from requested CPU set')
    modules = one('runtime_modules').get('modules', [])
    if len(modules) != 2 or {m.get('kind') for m in modules} != {'iface', 'unrar'}:
        raise ValueError('matching runtime module identities missing')
    for module in modules:
        expected = identity.get('runtime_modules', {}).get(module['kind'])
        if not expected or module.get('path') != expected['path'] or module.get('sha256') != expected['sha256']:
            raise ValueError('wrong runtime unrar module path/hash')
    one('all_engines_freed')
    startup, engine = one('startup'), one('engine')
    if engine.get('skipped') != 0 or startup.get('result_cache_enabled') != 0 or startup.get('metadata') != 1:
        raise ValueError('rule filtering/cache/metadata configuration differs')
    page_rows = [r for r in rows if r.get('kind') == 'page_cache']
    if not page_rows or any(r.get('resident_pages') != (r.get('pages') if r.get('requested_warm') else 0) for r in page_rows):
        raise ValueError('file-page cache control was not verified')
    digest, scans = semantic_transcript(rows, case, fixtures, args.scan_repeats, args.concurrency)
    observations = []
    def metric(name, value, subcase='lifecycle', **provenance):
        if not numeric(value):
            raise ValueError('invalid metric ' + name)
        observations.append({'metric': name, 'subcase': subcase, 'value': value,
                             'eligible': True, 'provenance': provenance})
    metric('startup_cpu_seconds', startup['cpu_seconds'])
    metric('startup_wall_seconds', startup['wall_seconds'])
    metric('construction_peak_bytes', engine['construction_hwm_kib'] * 1024,
           source='process_resident_high_water_through_compile')
    metric('resident_bytes_cold', startup['rss_kib'] * 1024,
           source='compiled_engine_before_declared_fixture_scans', all_names_or_fields_touched=False)
    if case == 'scan':
        batches = [r for r in rows if r.get('kind') == 'batch']
        for phase, subcase in (('file_cache_empty', 'cold_file_scan'), ('file_cache_hydrated', 'warm_file_scan')):
            selected = [r for r in scans if r['phase'] == phase]
            metric('scan_cpu_seconds', sum(r['engine_scan_cpu_seconds'] for r in selected), subcase,
                   source='sum_of_nonoverlapping_scanner_API_process_CPU_intervals')
            metric('scan_wall_seconds', sum(r['engine_scan_wall_seconds'] for r in selected), subcase,
                   source='sum_of_scanner_API_wall_intervals')
            samples = [r['engine_scan_wall_seconds'] * 1000 for r in selected]
            for probability, name, minimum in ((.95, 'scan_latency_p95_ms', 20), (.99, 'scan_latency_p99_ms', 100)):
                metric(name, quantile(samples, probability), subcase,
                       source='per_file_latency_distribution', quantile_method='nearest_rank', samples=len(samples))
                observations[-1]['eligible'] = len(samples) >= minimum
                if len(samples) < minimum:
                    observations[-1]['ineligible_reason'] = 'below contract sample minimum ' + str(minimum)
        if len(batches) != args.scan_repeats + 1:
            raise ValueError('missing or duplicate batch summaries')
        metric('resident_bytes_hydrated', batches[-1]['rss_kib'] * 1024,
               source='post_declared_warm_fixture_workload', all_names_or_fields_touched=False)
    elif case == 'concurrency':
        envelope = one('concurrency')
        if envelope.get('workers') != args.concurrency:
            raise ValueError('worker count differs from declared concurrency')
        metric('scan_cpu_seconds', envelope['cpu_seconds'], 'concurrent_scan',
               source='single_process_CPU_envelope_not_sum_of_overlapping_file_CPU', workers=args.concurrency)
        metric('scan_wall_seconds', envelope['wall_seconds'], 'concurrent_scan', workers=args.concurrency)
        samples = [r['engine_scan_wall_seconds'] * 1000 for r in scans]
        for probability, name, minimum in ((.95, 'scan_latency_p95_ms', 20), (.99, 'scan_latency_p99_ms', 100)):
            metric(name, quantile(samples, probability), 'concurrent_scan', source='per_file_latency_distribution',
                   quantile_method='nearest_rank', samples=len(samples), workers=args.concurrency)
            observations[-1]['eligible'] = len(samples) >= minimum
        metric('resident_bytes_hydrated', envelope['rss_kib'] * 1024,
               source='post_concurrent_fixture_workload', workers=args.concurrency, all_names_or_fields_touched=False)
    else:
        reload_row, replacement = one('reload'), one('reload_overlap')
        metric('reload_cpu_seconds', reload_row['cpu_seconds'])
        metric('reload_wall_seconds', reload_row['wall_seconds'])
        metric('reload_peak_bytes', reload_row['hwm_kib'] * 1024,
               source='process_high_water_through_replacement_compile', generation=case.get('generation', 'equal') if isinstance(case, dict) else 'bound_in_plan')
        one('old_engine_freed')
        if case == 'update':
            update = one('update_validation')
            if update.get('return_code') != 0 or one('update_runtime').get('library_sha256') != identity.get('freshclam_sha256'):
                raise ValueError('update validation failed or wrong freshclam runtime')
            metric('update_cpu_seconds', update['cpu_seconds'])
            metric('update_wall_seconds', update['wall_seconds'])
            metric('update_overlap_peak_bytes', update['hwm_kib'] * 1024,
                   source='process_high_water_through_validation_with_two_retained_engines')
    signature_sequence = [engine['signatures']]
    if case in ('reload', 'update'):
        signature_sequence.append(one('reload_overlap')['signatures'])
    return {'semantic_sha256': digest, 'scan_records': len(scans), 'signatures': signature_sequence,
            'observations': observations, 'page_cache_states_verified': True,
            'observed_limits': limits, 'replacement_scanned': False}


def execute(case, args, variants, output, database, database_list, lists, fixtures, changed, bound_inputs):
    identity = variants[case['variant']]
    stem = f"{case['ordinal']:03d}-{case['variant']}-{case['operation']}-{case['workload']}-r{case['round']}"
    stdout, stderr = output / (stem + '.jsonl'), output / (stem + '.stderr')
    command = [identity['probe'], str(database), str(args.certs), str(lists[case['workload']]),
               case['operation'], str(database_list), case['database_cache'], str(args.scan_repeats),
               str(args.concurrency), str(args.allmatch)]
    environment = os.environ.copy()
    for key in ('CM_PAD_GROUP', 'CM_PAD_BYTES', 'CM_PAD_LOG', 'CM_PAD_MAX_BYTES',
                'QUAL_RELOAD_DB', 'BENCH_FRESHCLAM_LIBRARY', 'BENCH_FRESHCLAM_DATABASE'):
        environment.pop(key, None)
    environment['LD_LIBRARY_PATH'] = ':'.join([str(Path(identity['library']).parent), *identity['runtime_dirs']])
    if changed:
        environment['QUAL_RELOAD_DB'] = str(changed)
    if case['operation'] == 'update':
        environment['BENCH_FRESHCLAM_LIBRARY'] = identity['freshclam']
        environment['BENCH_FRESHCLAM_DATABASE'] = str(database / args.update_member)
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (args.address_space_bytes, args.address_space_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (args.cpu_seconds, args.cpu_seconds + 5))
        os.sched_setaffinity(0, set(args.concurrency_cpus) if case['operation'] == 'concurrency' else {args.cpu})
    result = {**case, 'command': command, 'status': 'failed', 'timeout': False}
    start = time.monotonic()
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(command, env=environment, stdout=out, stderr=err,
                                   preexec_fn=limits, start_new_session=True)
        try:
            process.wait(timeout=args.wall_seconds)
        except subprocess.TimeoutExpired:
            result['timeout'] = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    result.update(returncode=process.returncode, process_wall_seconds=time.monotonic() - start,
                  stdout=stdout.name, stderr=stderr.name, stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    try:
        if process.returncode or result['timeout']:
            raise ValueError('failed or timed-out process')
        rows = [json.loads(line) for line in stdout.read_text().splitlines() if line.strip()]
        result.update(extract(rows, case['operation'], fixtures[case['workload']], args, identity))
        verify_inputs(bound_inputs)
        result['input_artifact_hashes_rechecked_after_process'] = True
        result['status'] = 'complete'
    except (KeyError, ValueError, TypeError) as error:
        result['validation_error'] = str(error)
    write(output / (stem + '-process.json'), result)
    return result


def compare(results, variants, minimum_rounds):
    required = json.loads(CONTRACT.read_text())
    comparisons = {}
    by_key = {(r['variant'], r['operation'], r['workload'], r['database_cache'], r['round']): r for r in results}
    for baseline in ('retained', 'upstream'):
        metrics = {name: {'status': 'unknown', 'pairs': [], 'reason': 'no paired observation supplied'}
                   for name in required['performance_metrics']}
        failures, semantics = [], []
        for candidate in (r for r in results if r['variant'] == 'candidate'):
            key = (baseline, candidate['operation'], candidate['workload'], candidate['database_cache'], candidate['round'])
            control = by_key.get(key)
            if not control or control['status'] != 'complete' or candidate['status'] != 'complete':
                failures.append({'case': key[1:], 'status': 'unknown', 'reason': 'paired process missing, failed or incomplete'})
                continue
            equal = candidate['semantic_sha256'] == control['semantic_sha256'] and candidate['signatures'] == control['signatures']
            semantics.append({'case': key[1:], 'equal': equal})
            if not equal:
                failures.append({'case': key[1:], 'status': 'failed', 'reason': 'ordered semantics or loaded signature count changed'})
            observations = {(r['metric'], r['subcase']): r for r in control['observations']}
            for item in candidate['observations']:
                before = observations.get((item['metric'], item['subcase']))
                if not before:
                    continue
                status = ('unknown' if not item['eligible'] or not before['eligible'] else
                          'failed' if item['value'] > before['value'] else 'passed_observed')
                metrics[item['metric']]['pairs'].append({'case': key[1:], 'subcase': item['subcase'],
                    'baseline': before['value'], 'candidate': item['value'], 'status': status,
                    'baseline_provenance': before['provenance'], 'candidate_provenance': item['provenance']})
        for name, row in metrics.items():
            pairs = row['pairs']
            if pairs:
                rounds = {pair['case'][-1] for pair in pairs if pair['status'] != 'unknown'}
                row['status'] = ('failed' if any(p['status'] == 'failed' for p in pairs) else
                                 'unknown' if len(rounds) < minimum_rounds or any(p['status'] == 'unknown' for p in pairs) else
                                 'passed_observed')
                row['reason'] = ('paired observed values, no all-input/statistical guarantee' if row['status'] != 'unknown'
                                 else 'insufficient rounds or percentile samples')
        comparisons[baseline] = {'metrics': metrics, 'semantics': semantics, 'case_issues': failures,
            'all_observed_semantics_equal': bool(semantics) and all(r['equal'] for r in semantics)}
    observed_failure = any(
        any(metric['status'] == 'failed' for metric in item['metrics'].values()) or
        any(issue['status'] == 'failed' for issue in item['case_issues'])
        for item in comparisons.values())
    return {'schema_version': 1, 'comparisons': comparisons,
        'strict_qualification_status': 'failed' if observed_failure else 'incomplete', 'promotion_authorized': False,
        'unmeasured_required_dimensions': ['scan_context_bytes', 'scan_scratch_bytes', 'builder_scratch_bytes'],
        'required_independent_evidence': ['all ten source-bound correctness properties',
            'source-bound complexity/resource bounds', 'all-fields/names hydration coverage',
            'declared maximum-concurrency coverage', 'changed-generation reload when required'],
        'scope': 'whole-engine paired observations only; unknown properties are never zero or passed; source-relative equality requires separate explicit adjudication'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', nargs=4, action='append', metavar=('ROLE', 'PROBE', 'LIBRARY', 'SOURCE_ROOT'), required=True)
    parser.add_argument('--runtime-dir', nargs=2, action='append', default=[], metavar=('ROLE', 'DIRECTORY'))
    parser.add_argument('--freshclam', nargs=2, action='append', default=[], metavar=('ROLE', 'LIBRARY'))
    for name in ('database', 'certs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--reload-database', type=Path)
    parser.add_argument('--correctness-report', type=Path)
    parser.add_argument('--resource-audit', type=Path)
    parser.add_argument('--build-cache', nargs=2, action='append', default=[], metavar=('ROLE', 'CACHE_FILE'))
    parser.add_argument('--archive', type=Path, default=ROOT / 'docs/subset-selector-results/three-way-performance/corpus.tar.gz')
    parser.add_argument('--stage', choices=('smoke', 'full'), default='smoke')
    parser.add_argument('--cases', nargs='+', choices=('scan', 'reload', 'update', 'concurrency'), default=['scan', 'reload'])
    parser.add_argument('--workloads', nargs='+', choices=('combined', 'accepted', 'positive', 'adverse'), default=['combined'])
    parser.add_argument('--rounds', type=int, default=1)
    parser.add_argument('--minimum-qualification-rounds', type=int, default=3)
    parser.add_argument('--scan-repeats', type=int, default=1)
    parser.add_argument('--database-cache', choices=('empty', 'hydrated', 'both'), default='hydrated')
    parser.add_argument('--concurrency', type=int, default=4)
    parser.add_argument('--concurrency-cpus', nargs='+', type=int,
                        help='allowed CPUs for shared-engine worker test; ordinary cases remain pinned to --cpu')
    parser.add_argument('--allmatch', type=int, choices=(0, 1), default=1)
    parser.add_argument('--update-member', default='daily.cvd')
    parser.add_argument('--cpu', type=int, default=min(os.sched_getaffinity(0)))
    parser.add_argument('--cpu-seconds', type=int, default=240)
    parser.add_argument('--wall-seconds', type=int, default=300)
    parser.add_argument('--address-space-bytes', type=int, default=6 * 1024**3)
    parser.add_argument('--seed', type=int, default=20261106)
    args = parser.parse_args()
    available = sorted(os.sched_getaffinity(0))
    if args.concurrency_cpus is None:
        args.concurrency_cpus = available[:min(args.concurrency, len(available))]
    if (not 1 <= args.rounds <= 10 or not 1 <= args.scan_repeats <= 20 or
            not 1 <= args.concurrency <= 64 or not 1 <= args.minimum_qualification_rounds <= 10 or
            min(args.cpu_seconds, args.wall_seconds, args.address_space_bytes) <= 0 or args.cpu not in os.sched_getaffinity(0)):
        parser.error('invalid rounds, resource bounds, concurrency or allowed CPU')
    if not args.concurrency_cpus or len(set(args.concurrency_cpus)) != len(args.concurrency_cpus) or any(cpu not in available for cpu in args.concurrency_cpus):
        parser.error('concurrency CPUs must be unique members of the available affinity set')
    if len(set(args.cases)) != len(args.cases) or len(set(args.workloads)) != len(args.workloads):
        parser.error('cases and workloads must be unique')
    roles = [v[0] for v in args.variant]
    if any(role not in ROLES for role in roles) or len(set(roles)) != len(roles):
        parser.error('each variant role must be unique and one of upstream/retained/candidate')
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('output must be absent or empty; changed experiments cannot resume stale evidence')
    args.output = args.output.resolve(); args.database = args.database.resolve(); args.certs = args.certs.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    private = args.output / 'private-inputs'; private.mkdir()
    variants = {}
    for role, probe, library, source in args.variant:
        variants[role] = {'probe': str(Path(probe).resolve()), 'library': str(Path(library).resolve()),
                          'probe_sha256': sha(probe), 'library_sha256': sha(library),
                          'source': source_identity(source), 'runtime_dirs': []}
    for role, directory in args.runtime_dir:
        if role not in variants:
            parser.error('runtime directory names an absent variant')
        variants[role]['runtime_dirs'].append(str(Path(directory).resolve()))
    for role, library in args.freshclam:
        if role not in variants or 'freshclam' in variants[role]:
            parser.error('freshclam must bind one present variant')
        variants[role].update(freshclam=str(Path(library).resolve()), freshclam_sha256=sha(library))
    for role, cache in args.build_cache:
        if role not in variants or 'build_cache' in variants[role]:
            parser.error('build cache must bind one present variant')
        entries = {}
        for line in Path(cache).read_text().splitlines():
            if line.startswith(('ENABLE_', 'CMAKE_BUILD_TYPE:', 'CMAKE_C_FLAGS:', 'CMAKE_C_FLAGS_RELEASE:', 'MAINTAINER_MODE:', 'BYTECODE_RUNTIME:')):
                key, value = line.split('=', 1); entries[key] = value
        variants[role]['build_cache'] = {'sha256': sha(cache), 'recorded_flags': entries}
    for variant in variants.values():
        variant['runtime_modules'] = module_identities(variant['runtime_dirs'])
    attachments = attach_evidence(args, variants)
    if 'update' in args.cases and any('freshclam' not in v for v in variants.values()):
        parser.error('update cases require a matching --freshclam for every variant')
    db = private / 'database'; database = copy_database(args.database, db)
    if 'update' in args.cases and not (db / args.update_member).is_file():
        parser.error('update member must name a copied database file')
    db_list = private / 'database-files.txt'; db_list.write_text(''.join(str(p.resolve()) + '\n' for p in sorted(db.iterdir())))
    changed = None; changed_identity = None
    if args.reload_database:
        changed = private / 'replacement-database'; changed_identity = copy_database(args.reload_database, changed)
        if hash_json(changed_identity) == hash_json(database):
            parser.error('changed-generation input is byte-identical to the base database')
    fixtures = prepare_corpus(args, private)
    fixtures['empty'] = []
    bound_inputs = {str(db / row['name']): row['sha256'] for row in database}
    if changed:
        bound_inputs.update({str(changed / row['name']): row['sha256'] for row in changed_identity})
    bound_inputs.update({row['path']: row['sha256'] for rows in fixtures.values() for row in rows})
    for variant in variants.values():
        bound_inputs[variant['probe']] = variant['probe_sha256']
        bound_inputs[variant['library']] = variant['library_sha256']
        for module in variant['runtime_modules'].values(): bound_inputs[module['path']] = module['sha256']
        if variant.get('freshclam'): bound_inputs[variant['freshclam']] = variant['freshclam_sha256']
    lists = {}
    for name, entries in fixtures.items():
        lists[name] = private / (name + '.txt')
        lists[name].write_text(''.join(row['path'] + '\n' for row in entries))
    plan = []
    caches = ('empty', 'hydrated') if args.database_cache == 'both' else (args.database_cache,)
    for round_number in range(args.rounds):
        block = [{'variant': role, 'operation': operation, 'workload': workload,
                  'database_cache': cache, 'round': round_number}
                 for role in variants for operation in args.cases for cache in caches
                 for workload in (args.workloads if operation in ('scan', 'concurrency') else ['empty'])]
        random.Random(args.seed + round_number).shuffle(block); plan.extend(block)
    plan = [{'ordinal': i, **case} for i, case in enumerate(plan)]
    sources = [Path(__file__), Path(__file__).with_name('probe.c'),
               ROOT / 'tools/subset-selector/performance/performance_probe.c',
               ROOT / 'tools/subset-selector/scan_probe.c', CONTRACT]
    manifest = {'schema_version': 1, 'variants': variants, 'database': database, 'attached_evidence': attachments,
        'replacement_database': changed_identity, 'fixtures': fixtures, 'plan': plan,
        'sources': {str(p.relative_to(ROOT)): sha(p) for p in sources}, 'policy': vars(args),
        'hardware': {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine(),
                     'cpu': args.cpu, 'available_affinity': sorted(os.sched_getaffinity(0))},
        'certificate_files': [{'name': str(p.relative_to(args.certs)), 'sha256': sha(p)} for p in sorted(args.certs.rglob('*')) if p.is_file()],
        'cache_control_scope': 'only separate-inode private copies of database and fixture file pages; no global drop_caches'}
    manifest['policy'] = {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}
    write(args.output / 'plan.json', manifest)
    results = []
    for case in plan:
        result = execute(case, args, variants, args.output, db, db_list, lists, fixtures, changed, bound_inputs)
        results.append(result)
        print(json.dumps({k: result[k] for k in ('ordinal', 'variant', 'operation', 'status', 'process_wall_seconds')}), flush=True)
    summary = {'schema_version': 1, 'plan_sha256': sha(args.output / 'plan.json'), 'cases': results,
               'complete': all(r['status'] == 'complete' for r in results),
               'qualification': compare(results, variants, args.minimum_qualification_rounds)}
    write(args.output / 'summary.json', summary)
    raise SystemExit(0 if summary['complete'] else 1)


if __name__ == '__main__':
    main()
