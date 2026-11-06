#!/usr/bin/env python3
"""Independently audit a completed perturbation matrix's saved evidence.

Does not import the runner or trust its semantic/counter summaries. This checks
artifact integrity and consistency, not authenticity of a modified reporter,
allocator coverage, scanner correctness or whether memory can safely be removed.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics


SEMANTIC_FIELDS = ('phase', 'round', 'allmatch', 'return_code', 'verdict', 'final_name',
                   'root_type', 'sha256', 'after_sha256', 'hold_bits', 'candidate_outcome',
                   'scanned_bytes', 'input_bytes', 'events')
COUNTER_FIELDS = ('calls', 'requested_bytes', 'successful_calls', 'failed_calls',
                  'added_bytes', 'injected_calls', 'skipped_cap_calls', 'overflow_failures')


class AuditError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def semantic_hash(scans):
    records = [{field: scan[field] for field in SEMANTIC_FIELDS} for scan in scans]
    return sha(json.dumps(records, sort_keys=True, separators=(',', ':')).encode())


def read_records(raw):
    return [json.loads(line) for line in raw.decode().splitlines() if line.strip()]


def artifact(directory, name):
    require(isinstance(name, str) and name and Path(name).name == name,
            'artifact must be one local filename')
    path = directory / name
    require(path.is_file() and not path.is_symlink(), 'artifact missing or symlink: ' + name)
    return path.read_bytes()


def audit(directory):
    directory = Path(directory)
    plan_raw, summary_raw = artifact(directory, 'plan.json'), artifact(directory, 'summary.json')
    plan, summary = json.loads(plan_raw), json.loads(summary_raw)
    cases = summary['cases']
    require(plan['schema_version'] == summary['schema_version'] == 1, 'unsupported evidence schema')
    require(len(cases) == len(plan['plan']) and len(cases) > 0, 'incomplete case list')
    require(summary['complete'] is True and summary['all_semantics_match'] is True,
            'runner did not report a completed, semantically matching matrix')
    phases = ['initial', 'loaded', 'compiled', 'scanned']
    if plan['reload']:
        phases += ['reload_loaded', 'reload_compiled', 'reload_old_freed']
    phases += ['all_freed']
    expected_hashes = [f['sha256'] for f in plan['fixtures']] * plan['scan_passes']
    expected_sizes = [f['bytes'] for f in plan['fixtures']] * plan['scan_passes']
    artifact_hashes = {'plan.json': sha(plan_raw), 'summary.json': sha(summary_raw)}
    verified = []
    signatures = None
    for ordinal, (case, scheduled) in enumerate(zip(cases, plan['plan'])):
        label = 'case ' + str(ordinal) + ': '
        require(scheduled['ordinal'] == ordinal, label + 'plan ordinals are not consecutive')
        require(all(case.get(key) == value for key, value in scheduled.items()), label + 'case differs from plan')
        require(case['status'] == 'complete' and case['return_code'] == 0 and not case['timeout'],
                label + 'process did not complete normally')
        raw = {}
        for field in ('stdout', 'stderr', 'perturb_log'):
            expected = case[field + '_sha256']
            if expected is None:
                require(field == 'perturb_log' and case['variant'] == 'stock' and
                        not (directory / case[field]).exists(), label + 'unexpected absent artifact hash')
                raw[field] = b''
            else:
                raw[field] = artifact(directory, case[field])
                require(sha(raw[field]) == expected, label + 'artifact hash mismatch: ' + field)
                artifact_hashes[case[field]] = expected
        records = read_records(raw['stdout'])
        runtime = [row for row in records if row.get('kind') == 'runtime']
        require(len(runtime) == 1 and runtime[0].get('engine_sha256') ==
                plan['identities'][case['variant']]['library_sha256'] and
                runtime[0].get('unrar_modules_verified'), label + 'runtime identity mismatch')
        snapshot_rows = [row for row in records if row.get('kind') == 'memory_snapshot']
        require([row['phase'] for row in snapshot_rows] == phases, label + 'lifecycle snapshot ordering mismatch')
        snapshots = {row['phase']: row for row in snapshot_rows}
        require(snapshots == case['snapshots'], label + 'snapshot summary differs from raw records')
        for snapshot in snapshot_rows:
            require(snapshot.get('address_space_limit_bytes') == plan['resource_limits']['address_space_bytes']
                    and snapshot.get('cpu_limit_seconds') == plan['resource_limits']['cpu_seconds'],
                    label + 'observed resource limit mismatch')
        engine_count = 2 if plan['reload'] else 1
        loads = [row for row in records if row.get('kind') == 'engine_load']
        compiles = [row for row in records if row.get('kind') == 'engine_compile']
        require(len(loads) == len(compiles) == engine_count and
                all(row['return_code'] == 0 for row in loads + compiles), label + 'engine lifecycle failure')
        loaded_counts = [row['signatures'] for row in loads]
        require(loaded_counts == case['signatures'] and len(set(loaded_counts)) == 1,
                label + 'signature count mismatch')
        if signatures is None:
            signatures = loaded_counts[0]
        require(loaded_counts[0] == signatures, label + 'signature selection differs between cases')
        scans = [row for row in records if row.get('kind') == 'scan']
        require([row['sha256'] for row in scans] == expected_hashes,
                label + 'ordered scan inputs differ from plan fixture hashes')
        require([row['input_bytes'] for row in scans] == expected_sizes,
                label + 'scan input sizes differ from plan')
        require(all(row['sha256'] == row['after_sha256'] for row in scans), label + 'scan input changed')
        require(all(row['allmatch'] == 1 and row['phase'] == 'fixture_scan' and
                    row['round'] == i // len(plan['fixtures']) for i, row in enumerate(scans)),
                label + 'scan options, ordering or rounds differ')
        digest = semantic_hash(scans)
        require(digest == case['semantic_sha256'], label + 'semantic summary differs from raw records')
        totals = {}
        if case['variant'] == 'instrumented':
            perturb = read_records(raw['perturb_log'])
            require([row['phase'] for row in perturb] == phases, label + 'perturbation snapshot ordering mismatch')
            previous = {}
            for row in perturb:
                require(row.get('instrumentation_enabled') is True and row.get('configuration_valid') is True,
                        label + 'instrumentation not enabled or configuration invalid')
                require(row['configured_group'] == case['group'] and row['pad_bytes'] == case['dose'] and
                        row['max_added_bytes'] == plan['resource_limits']['max_cumulative_added_bytes'],
                        label + 'perturbation parameters differ from plan')
                require('not live' in row['scope'], label + 'counter scope lost cumulative qualification')
                require(not previous or set(previous) == set(row['groups']), label + 'counter groups changed')
                for group, stats in row['groups'].items():
                    require(all(type(stats[field]) is int and stats[field] >= 0 for field in COUNTER_FIELDS),
                            label + 'invalid counter type or sign')
                    require(stats['calls'] == stats['successful_calls'] + stats['failed_calls'],
                            label + 'request outcome counter mismatch')
                    require(stats['injected_calls'] <= stats['successful_calls'] and
                            stats['skipped_cap_calls'] <= stats['failed_calls'] and
                            stats['overflow_failures'] <= stats['failed_calls'], label + 'counter outcome bounds fail')
                    expected_added = case['dose'] * stats['injected_calls']
                    require(stats['added_bytes'] == expected_added, label + 'injected byte/dose counter mismatch')
                    if group != case['group'] or case['dose'] == 0:
                        require(stats['added_bytes'] == stats['injected_calls'] == 0,
                                label + 'padding charged outside the selected group')
                    require(not stats['skipped_cap_calls'], label + 'dose was capped')
                    if previous:
                        require(all(stats[field] >= previous[group][field] for field in COUNTER_FIELDS),
                                label + 'cumulative counters decreased')
                require(sum(stats['added_bytes'] for stats in row['groups'].values()) <=
                        row['max_added_bytes'], label + 'cumulative padding cap exceeded')
                previous = row['groups']
            totals = perturb[-1]['groups']
        else:
            require(not raw['perturb_log'], label + 'stock control emitted perturbation records')
        require(case['perturb_totals'] == totals, label + 'counter summary differs from raw records')
        require(case['cumulative_added_bytes'] == sum(s['added_bytes'] for s in totals.values()) and
                case['injected_calls'] == sum(s['injected_calls'] for s in totals.values()) and
                case['dose_censored_by_cap'] is False, label + 'total padding summary mismatch')
        verified.append({'ordinal': ordinal, 'variant': case['variant'], 'group': case['group'],
                         'dose': case['dose'], 'semantic_sha256': digest,
                         'signatures': loaded_counts, 'scan_records': len(scans)})
    zero = [row for row in verified if row['variant'] == 'instrumented' and row['dose'] == 0]
    require(zero, 'no instrumented zero-dose reference')
    reference = zero[0]['semantic_sha256']
    require(all(row['semantic_sha256'] == reference for row in verified),
            'ordered scan semantics differ between cases or controls')
    shared = [row for row in cases if row.get('shared_zero_control')]
    for case in cases:
        if case['variant'] == 'stock':
            control_rows = [case]
        elif shared:
            control_rows = shared
        else:
            control_rows = [other for other in cases if other['variant'] == 'instrumented' and
                            other['group'] == case['group'] and other['repetition'] == case['repetition'] and
                            other['dose'] == 0]
        require(control_rows, 'missing same-group/repetition zero-dose control')
        expected_delta = {phase: (case['snapshots'][phase]['rss_kib'] -
                          statistics.median(row['snapshots'][phase]['rss_kib'] for row in control_rows)) * 1024
                          for phase in phases}
        require(case['rss_delta_vs_zero_bytes'] == expected_delta, 'case RSS delta summary mismatch')
    expected_cells = sorted({(row['group'], row['dose']) for row in cases if row['variant'] == 'instrumented'})
    require([(row['group'], row['dose_bytes_per_matching_request']) for row in summary['aggregates']] == expected_cells,
            'aggregate cell list differs from cases')
    for aggregate, (group, dose) in zip(summary['aggregates'], expected_cells):
        cell = [row for row in cases if row['variant'] == 'instrumented' and row['group'] == group and row['dose'] == dose]
        require(aggregate['planned'] == aggregate['completed'] == aggregate['uncensored_semantically_matching'] == len(cell),
                'aggregate completed/qualified counts differ from audited cases')
        require(aggregate['median_cumulative_added_bytes'] == statistics.median(row['cumulative_added_bytes'] for row in cell)
                and aggregate['median_injected_calls'] == statistics.median(row['injected_calls'] for row in cell),
                'aggregate padding median mismatch')
        require(aggregate['median_rss_delta_bytes'] ==
                {phase: statistics.median(row['rss_delta_vs_zero_bytes'][phase] for row in cell) for phase in phases},
                'aggregate RSS median mismatch')
    return {'schema_version': 1, 'status': 'passed', 'audit_source_sha256': sha(Path(__file__).read_bytes()),
            'plan_sha256': artifact_hashes['plan.json'], 'summary_sha256': artifact_hashes['summary.json'],
            'validated_cases': len(cases), 'validated_scan_records': sum(row['scan_records'] for row in verified),
            'all_ordered_input_hashes_match_plan': True, 'all_ordered_semantics_match_controls': True,
            'all_dose_counters_and_rss_summaries_match_raw': True,
            'artifact_sha256': artifact_hashes, 'cases': verified,
            'limitations': ['Integrity and internal consistency checks do not authenticate a modified reporter.',
                            'Counters remain cumulative requests, not live memory or removable overhead.',
                            'If reload was enabled, replacement-engine scan semantics were not exercised by this harness.',
                            'No claim of complete allocator coverage or performance parity is established.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.results)
    except (AuditError, KeyError, TypeError, ValueError, OSError) as error:
        result = {'schema_version': 1, 'status': 'failed', 'reason': str(error),
                  'audit_source_sha256': sha(Path(__file__).read_bytes())}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('status', 'validated_cases', 'validated_scan_records', 'reason') if key in result}))
    raise SystemExit(0 if result['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
