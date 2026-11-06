#!/usr/bin/env python3
"""Serial, bounded allocation-perturbation experiments. GPL-2.0-only.

The experiment measures sensitivity to added bytes. It cannot identify bytes
that are safe to remove. Injection counters are cumulative requests, not live
allocation extents, allocator waste, or a whole-program memory census.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import statistics
import subprocess
import time

GROUPS = ('names', 'patterns', 'candidates', 'tokens', 'nodes', 'transitions', 'hashes',
          'logical', 'scanstate', 'build_scratch', 'pool_other', 'heap_other')
SEMANTIC_KEYS = ('phase', 'round', 'allmatch', 'return_code', 'verdict', 'final_name',
                 'root_type', 'sha256', 'after_sha256', 'hold_bits', 'candidate_outcome',
                 'scanned_bytes', 'input_bytes', 'events')


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def semantic_digest(rows, expected_scans):
    scans = [r for r in rows if r.get('kind') == 'scan']
    if len(scans) != expected_scans:
        raise ValueError('incomplete scan records')
    if any(r.get('sha256') != r.get('after_sha256') for r in scans):
        raise ValueError('input changed during scan')
    semantics = [{k: r[k] for k in SEMANTIC_KEYS} for r in scans]
    # Full ordered callbacks, final names and parser traversal are included.
    return hashlib.sha256(json.dumps(semantics, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate(rows, perturb, case, args, fixture_count, expected_library):
    snapshots = {r['phase']: r for r in rows if r.get('kind') == 'memory_snapshot'}
    required = {'initial', 'loaded', 'compiled', 'scanned', 'all_freed'}
    if args.reload:
        required |= {'reload_loaded', 'reload_compiled', 'reload_old_freed'}
    if set(snapshots) != required or sum(r.get('kind') == 'memory_snapshot' for r in rows) != len(required):
        raise ValueError('missing or duplicate/malformed lifecycle snapshots')
    runtime = [r for r in rows if r.get('kind') == 'runtime']
    if len(runtime) != 1 or runtime[0].get('engine_sha256') != expected_library:
        raise ValueError('runtime library identity mismatch')
    if not runtime[0].get('unrar_modules_verified'):
        raise ValueError('missing runtime unrar modules')
    loads = [r for r in rows if r.get('kind') == 'engine_load']
    if len(loads) != (2 if args.reload else 1) or any(r['return_code'] != 0 for r in loads):
        raise ValueError('failed/incomplete engine load')
    if case['variant'] == 'instrumented':
        if len(perturb) != len(required) or {r.get('phase') for r in perturb} != required:
            raise ValueError('missing perturbation snapshots; instrumentation not demonstrated')
        if any(not r.get('instrumentation_enabled') or not r.get('configuration_valid') for r in perturb):
            raise ValueError('instrumentation rejected configuration')
        if any(r.get('configured_group') != case['group'] or r.get('pad_bytes') != case['dose'] for r in perturb):
            raise ValueError('instrumentation configuration mismatch')
    digest = semantic_digest(rows, fixture_count * args.scan_passes)
    last = next((r for r in perturb if r.get('phase') == 'all_freed'), None)
    totals = last.get('groups', {}) if last else {}
    return {'semantic_sha256': digest, 'signatures': [r['signatures'] for r in loads],
            'snapshots': snapshots, 'perturb_totals': totals,
            'failed_fixture_scans': sum(r.get('kind') == 'scan' and r.get('candidate_outcome') == 'failed' for r in rows),
            'dose_censored_by_cap': any(v.get('skipped_cap_calls', 0) > 0 for v in totals.values()),
            'injected_calls': sum(v.get('injected_calls', 0) for v in totals.values()),
            'cumulative_added_bytes': sum(v.get('added_bytes', 0) for v in totals.values()),
            'timings': [{k: r[k] for k in ('kind', 'wall_seconds', 'cpu_seconds')}
                        for r in rows if r.get('kind') in ('engine_load', 'engine_compile', 'batch')]}


def execute(case, args, output, fixture_count, identities):
    stem = f"{case['ordinal']:03d}-{case['variant']}-{case['group']}-{case['dose']}-r{case['repetition']}"
    stdout, stderr, log = (output / (stem + suffix) for suffix in ('.jsonl', '.stderr', '-perturb.jsonl'))
    stock = case['variant'] == 'stock'
    probe = args.stock_probe if stock else args.probe
    library = args.stock_library if stock else args.library
    command = [str(probe), str(args.database), str(args.certs), str(args.files),
               str(int(args.reload)), str(args.scan_passes), '0' if stock else '1']
    env = os.environ.copy()
    for key in ('CM_PAD_GROUP', 'CM_PAD_BYTES', 'CM_PAD_MAX_BYTES', 'CM_PAD_LOG'):
        env.pop(key, None)
    env.update(CM_PAD_GROUP=case['group'], CM_PAD_BYTES=str(case['dose']),
               CM_PAD_MAX_BYTES=str(args.max_added_bytes), CM_PAD_LOG=str(log))
    directories = [library.parent] + args.runtime_dir
    env['LD_LIBRARY_PATH'] = ':'.join(str(p) for p in directories)

    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (args.address_space_bytes, args.address_space_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (args.cpu_seconds, args.cpu_seconds + 5))
        if args.cpu is not None:
            os.sched_setaffinity(0, {args.cpu})

    started = time.monotonic()
    result = {**case, 'status': 'failed', 'timeout': False}
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(command, env=env, stdout=out, stderr=err, preexec_fn=limits)
        try:
            process.wait(timeout=args.wall_seconds)
        except subprocess.TimeoutExpired:
            result['timeout'] = True
            process.kill()
            process.wait()
    result.update(return_code=process.returncode, wall_seconds=time.monotonic() - started,
                  stdout=stdout.name, stderr=stderr.name, perturb_log=log.name,
                  stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
                  perturb_log_sha256=sha(log) if log.exists() else None)
    try:
        if process.returncode or result['timeout']:
            raise ValueError('process failed or exceeded resource/time limit')
        result.update(validate(read_jsonl(stdout), read_jsonl(log), case, args,
                               fixture_count, identities[case['variant']]['library_sha256']))
        result['status'] = 'complete'
    except (KeyError, ValueError, TypeError) as exc:
        result['validation_error'] = str(exc)
    (output / (stem + '-process.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result


def summarize(results):
    controls = {(r['group'], r['repetition']): r for r in results
                if r['variant'] == 'instrumented' and r['dose'] == 0 and r['status'] == 'complete'}
    stock = {r['repetition']: r for r in results if r['variant'] == 'stock' and r['status'] == 'complete'}
    stock_consistent = (not stock or all(r['semantic_sha256'] == next(iter(stock.values()))['semantic_sha256']
                                        and r['signatures'] == next(iter(stock.values()))['signatures']
                                        for r in stock.values()))
    shared = [r for r in results if r.get('shared_zero_control') and r['status'] == 'complete']
    shared_consistent = bool(shared) and all(r['semantic_sha256'] == shared[0]['semantic_sha256']
                                           and r['signatures'] == shared[0]['signatures'] for r in shared)
    for r in results:
        if r['status'] != 'complete':
            continue
        control = controls.get((r['group'], r['repetition'])) if r['variant'] == 'instrumented' else r
        if r['variant'] == 'instrumented' and shared:
            control = shared[0] if shared_consistent else None
        r['semantics_match_zero_dose'] = bool(control and r['semantic_sha256'] == control['semantic_sha256']
                                            and r['signatures'] == control['signatures'])
        reference_stock = stock.get(r['repetition']) or next(iter(stock.values()), None)
        r['semantics_match_stock'] = (None if reference_stock is None else stock_consistent and
                                     r['semantic_sha256'] == reference_stock['semantic_sha256']
                                     and r['signatures'] == reference_stock['signatures'])
        if control:
            reference = ({phase: statistics.median(x['snapshots'][phase]['rss_kib'] for x in shared)
                          for phase in control['snapshots']} if shared and r['variant'] == 'instrumented' else
                         {phase: m['rss_kib'] for phase, m in control['snapshots'].items()})
            r['rss_reference'] = ('median of interleaved shared zero-dose controls' if shared and r['variant'] == 'instrumented'
                                  else 'same-group/same-repetition zero-dose control')
            r['rss_delta_vs_zero_bytes'] = {phase: (m['rss_kib'] - reference[phase]) * 1024
                                           for phase, m in r['snapshots'].items()}
    aggregates = []
    for group, dose in sorted({(r['group'], r['dose']) for r in results if r['variant'] == 'instrumented'}):
        cells = [r for r in results if r['variant'] == 'instrumented' and r['group'] == group and r['dose'] == dose]
        qualified = [r for r in cells if r['status'] == 'complete' and r.get('semantics_match_zero_dose')
                     and r.get('semantics_match_stock') is not False and not r.get('dose_censored_by_cap')]
        row = {'group': group, 'dose_bytes_per_matching_request': dose, 'planned': len(cells),
               'completed': sum(r['status'] == 'complete' for r in cells),
               'uncensored_semantically_matching': len(qualified)}
        if qualified:
            row['median_rss_delta_bytes'] = {phase: statistics.median(r['rss_delta_vs_zero_bytes'][phase] for r in qualified)
                                            for phase in qualified[0]['snapshots']}
            row['median_cumulative_added_bytes'] = statistics.median(r['cumulative_added_bytes'] for r in qualified)
            row['median_injected_calls'] = statistics.median(r['injected_calls'] for r in qualified)
        aggregates.append(row)
    return aggregates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'library', 'database', 'certs', 'files', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--stock-probe', type=Path)
    parser.add_argument('--stock-library', type=Path)
    parser.add_argument('--runtime-dir', type=Path, action='append', default=[])
    parser.add_argument('--groups', nargs='+', choices=GROUPS, default=list(GROUPS))
    parser.add_argument('--doses', nargs='+', type=int, default=[0, 8, 32])
    parser.add_argument('--repetitions', type=int, default=2)
    parser.add_argument('--zero-controls', type=int, default=0,
                        help='use N interleaved shared zero-dose controls instead of one per group/repetition (screening only)')
    parser.add_argument('--seed', type=int, default=20261106)
    parser.add_argument('--scan-passes', type=int, default=1)
    parser.add_argument('--reload', action='store_true')
    parser.add_argument('--address-space-bytes', type=int, default=4 * 1024**3)
    parser.add_argument('--cpu-seconds', type=int, default=120)
    parser.add_argument('--wall-seconds', type=int, default=150)
    parser.add_argument('--max-added-bytes', type=int, default=512 * 1024**2)
    parser.add_argument('--cpu', type=int, default=0)
    args = parser.parse_args()
    if (not 1 <= args.repetitions <= 20 or not 0 <= args.scan_passes <= 5 or
            not 0 <= args.zero_controls <= 20 or not args.doses or 0 not in args.doses or
            any(d < 0 or d > 4096 or d % 8 for d in args.doses) or
            len(set(args.doses)) != len(args.doses) or len(set(args.groups)) != len(args.groups)):
        parser.error('use unique groups/doses including zero and multiples of 8, 1..20 repetitions, 0..20 shared controls and 0..5 scan passes')
    if bool(args.stock_probe) != bool(args.stock_library):
        parser.error('stock-probe and stock-library must be supplied together')
    if min(args.cpu_seconds, args.wall_seconds, args.address_space_bytes, args.max_added_bytes) <= 0:
        parser.error('resource limits must be positive')
    if args.cpu not in os.sched_getaffinity(0):
        parser.error('requested CPU is not available')
    for name in ('probe', 'library', 'database', 'certs', 'files', 'output', 'stock_probe', 'stock_library'):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).resolve())
    args.runtime_dir = [p.resolve() for p in args.runtime_dir]
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('output must be absent or empty; changed matrices cannot resume old evidence')
    fixtures = [Path(line) for line in args.files.read_text().splitlines() if line]
    if any(not p.is_absolute() or not p.is_file() for p in fixtures):
        parser.error('fixture list must contain existing absolute regular file paths')
    identities = {'instrumented': {'probe_sha256': sha(args.probe), 'library_sha256': sha(args.library)}}
    if args.stock_probe:
        identities['stock'] = {'probe_sha256': sha(args.stock_probe), 'library_sha256': sha(args.stock_library)}
    args.output.mkdir(parents=True, exist_ok=True)
    plan = [{'variant': 'instrumented', 'group': group, 'dose': dose, 'repetition': rep}
            for rep in range(args.repetitions) for group in args.groups for dose in args.doses
            if dose != 0 or not args.zero_controls]
    if args.stock_probe:
        plan += [{'variant': 'stock', 'group': 'disabled', 'dose': 0, 'repetition': rep}
                 for rep in range(args.repetitions)]
    random.Random(args.seed).shuffle(plan)
    if args.zero_controls:
        controls = [{'variant': 'instrumented', 'group': args.groups[0], 'dose': 0,
                     'repetition': 0, 'shared_zero_control': True, 'control_index': i}
                    for i in range(args.zero_controls)]
        # Include a control at each end and spread remaining controls evenly.
        original = plan
        plan = []
        for i, control in enumerate(controls):
            boundary = round(i * len(original) / (len(controls) - 1)) if len(controls) > 1 else 0
            previous = round((i - 1) * len(original) / (len(controls) - 1)) if i and len(controls) > 1 else 0
            plan.extend(original[previous:boundary])
            plan.append(control)
        plan.extend(original[boundary:])
    plan = [{'ordinal': i, **case} for i, case in enumerate(plan)]
    sources = [Path(__file__), Path(__file__).with_name('probe.c'),
               Path(__file__).parents[2] / 'subset-selector/performance/performance_probe.c',
               Path(__file__).parents[2] / 'subset-selector/scan_probe.c']
    manifest = {'schema_version': 1, 'identities': identities, 'seed': args.seed, 'plan': plan,
                'experiment_source_sha256': {p.name: sha(p) for p in sources},
                'fixture_list_sha256': sha(args.files),
                'fixtures': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in fixtures],
                'database': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)}
                             for p in sorted(args.database.iterdir()) if p.is_file()],
                'certificates': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)}
                                 for p in sorted(args.certs.iterdir()) if p.is_file()],
                'resource_limits': {'address_space_bytes': args.address_space_bytes, 'cpu_seconds': args.cpu_seconds,
                                    'wall_seconds': args.wall_seconds, 'cpu': args.cpu,
                                    'max_cumulative_added_bytes': args.max_added_bytes},
                'reload': args.reload, 'scan_passes': args.scan_passes, 'shared_zero_controls': args.zero_controls,
                'scope': 'allocation sensitivity of annotated paths; cumulative injection totals are not live allocation sizes'}
    (args.output / 'plan.json').write_text(json.dumps(manifest, indent=2) + '\n')
    results = []
    for case in plan:
        result = execute(case, args, args.output, len(fixtures), identities)
        results.append(result)
        print(json.dumps({k: result[k] for k in ('ordinal', 'group', 'dose', 'status', 'wall_seconds')}), flush=True)
    aggregates = summarize(results)
    summary = {'schema_version': 1, 'cases': results, 'aggregates': aggregates,
               'complete': all(r['status'] == 'complete' for r in results),
               'all_semantics_match': all(r.get('semantics_match_zero_dose') and r.get('semantics_match_stock') is not False for r in results),
               'interpretation': 'Added-byte response and allocation-frequency evidence, not proof of removable memory or performance parity.'}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    raise SystemExit(0 if summary['complete'] and summary['all_semantics_match'] else 1)


if __name__ == '__main__':
    main()
