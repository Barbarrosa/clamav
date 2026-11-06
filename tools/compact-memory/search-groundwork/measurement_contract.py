#!/usr/bin/env python3
"""Fail-closed checks of paired, artifact-bound scanner measurements.

This validates reported evidence. It neither executes the scanner nor proves
that the reporter measured honestly. Passing means no regression was observed
in the declared pairs; it is not a statistical or all-input timing guarantee.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import copy
import json
import math
from pathlib import Path
import re


SHA256 = re.compile(r'^[0-9a-f]{64}$')
HASH_BINDINGS = (
    'baseline_artifact_sha256', 'candidate_artifact_sha256', 'database_sha256',
    'corpus_sha256', 'configuration_sha256', 'hardware_sha256', 'policy_sha256',
    'semantic_contract_sha256',
)
SEMANTIC_CONTRACTS = ('ordered-observables-v1', 'detection-multiset-and-outcomes-v1')
SUPPORTED_METRICS = (
    'scan_cpu_seconds', 'scan_wall_seconds', 'scan_latency_p95_ms',
    'scan_latency_p99_ms', 'startup_cpu_seconds', 'startup_wall_seconds',
    'reload_cpu_seconds', 'reload_wall_seconds', 'update_cpu_seconds',
    'update_wall_seconds', 'resident_bytes_cold', 'resident_bytes_hydrated',
    'construction_peak_bytes', 'reload_peak_bytes', 'update_overlap_peak_bytes',
    'scan_context_bytes',
    'scan_scratch_bytes', 'builder_scratch_bytes',
)
DEFAULT_REQUIRED_METRICS = SUPPORTED_METRICS
PERCENTILE_SAMPLES = {'scan_latency_p95_ms': 20, 'scan_latency_p99_ms': 100}
CASE_BINDINGS = ('workload_sha256', 'cache_state', 'workload_class', 'concurrency')


def _sha(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _positive(value):
    if type(value) not in (int, float):
        return False
    try:
        return value > 0 and math.isfinite(value)
    except OverflowError:
        return False


def _nonnegative(value):
    if type(value) not in (int, float):
        return False
    try:
        return value >= 0 and math.isfinite(value)
    except OverflowError:
        return False


def _observed_ratio(baseline, candidate):
    if baseline == 0:
        return (1.0, None) if candidate == 0 else (None, 'positive candidate cost against zero baseline')
    ratio = candidate / baseline
    if not math.isfinite(ratio):
        return None, 'metric ratio is outside the finite numeric range'
    return ratio, None


def _mean(values):
    scale = max(values)
    if scale == 0:
        return 0.0
    return scale * (math.fsum(value / scale for value in values) / len(values))


def _validate_expected(expected, required_metrics, max_ratio):
    if not isinstance(expected, dict):
        raise ValueError('expected_binding must be a separately supplied object')
    if set(expected) != set(HASH_BINDINGS) | {'semantic_contract', 'cases'}:
        raise ValueError('expected_binding has missing or unknown fields')
    if any(not _sha(expected[key]) for key in HASH_BINDINGS):
        raise ValueError('expected artifact/workload/policy bindings must be SHA-256 strings')
    if expected['semantic_contract'] not in SEMANTIC_CONTRACTS:
        raise ValueError('unknown semantic transcript contract')
    if not _positive(max_ratio) or max_ratio > 1:
        raise ValueError('max_ratio must be positive and at most 1; regressions cannot be permitted')
    if not isinstance(required_metrics, (list, tuple)) or not required_metrics:
        raise ValueError('required_metrics must be a nonempty list or tuple')
    if (any(not isinstance(metric, str) or metric not in SUPPORTED_METRICS
            for metric in required_metrics) or
            len(set(required_metrics)) != len(required_metrics)):
        raise ValueError('required_metrics contains duplicate or unknown metrics')
    cases = expected['cases']
    if not isinstance(cases, list) or not cases:
        raise ValueError('expected_binding must declare its required cases')
    result = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {'id', *CASE_BINDINGS, 'minimum_pairs'}:
            raise ValueError('each expected case must bind its workload, cache, class and pair count')
        if not isinstance(case['id'], str) or not case['id'] or case['id'] in result:
            raise ValueError('expected case identifiers must be nonempty and unique')
        if (not _sha(case['workload_sha256']) or case['cache_state'] not in ('cold', 'warm') or
                case['workload_class'] not in ('ordinary', 'adversarial') or
                type(case['concurrency']) is not int or case['concurrency'] < 1 or
                type(case['minimum_pairs']) is not int or case['minimum_pairs'] < 1):
            raise ValueError('invalid expected case binding')
        result[case['id']] = case
    if ({case['cache_state'] for case in cases} != {'cold', 'warm'} or
            'adversarial' not in {case['workload_class'] for case in cases}):
        raise ValueError('expected cases must cover cold, warm and adversarial workloads')
    return result


def evaluate_measurements(bundle, expected_binding, required_metrics=DEFAULT_REQUIRED_METRICS,
                          max_ratio=1.0):
    """Check complete, paired observations against an external binding.

    Malformed trusted configuration raises ValueError. Missing or invalid
    measurement evidence returns a non-passing report. Every required pair and
    metric must be within the bound; a favorable mean cannot hide a slow pair.
    p95/p99 values must come from declared per-file distributions with at least
    20/100 samples on each side. They are never estimated from paired CPU values.
    """
    expected_cases = _validate_expected(expected_binding, required_metrics, max_ratio)
    issues, summaries = [], []

    def issue(kind, location, message):
        issues.append({'kind': kind, 'location': location, 'message': message})

    def finish():
        status = ('failed' if any(item['kind'] == 'failed' for item in issues) else
                  'missing' if issues else 'passed_observed')
        return {
            'schema_version': 1, 'status': status, 'empirical_only': True,
            'formal_performance_proof': False, 'all_input_guarantee': False,
            'statistical_confidence_established': False,
            'measurement_scope_required': 'whole_scanner',
            'threshold_candidate_over_baseline': max_ratio,
            'zero_baseline_ratio_policy': 'zero/zero is 1; positive/zero has no finite ratio and fails',
            'required_metrics': list(required_metrics), 'cases': summaries,
            'issues': issues,
            'interpretation': 'reported paired observations only; no untested workload, hardware or implementation is qualified',
            'binding': copy.deepcopy(expected_binding),
        }

    if bundle is None:
        issue('missing', 'bundle', 'no measurement bundle supplied')
        return finish()
    if not isinstance(bundle, dict):
        issue('failed', 'bundle', 'measurement bundle must be an object')
        return finish()
    unknown = set(bundle) - {'schema_version', 'scope', 'binding', 'cases', 'provenance'}
    if unknown:
        issue('failed', 'bundle', 'unknown fields: ' + ', '.join(sorted(map(str, unknown))))
    if bundle.get('schema_version') != 1 or type(bundle.get('schema_version')) is not int:
        issue('missing' if 'schema_version' not in bundle else 'failed',
              'schema_version', 'schema_version must be integer 1')
    if bundle.get('scope') != 'whole_scanner':
        issue('missing' if bundle.get('scope') is None else 'failed', 'scope',
              'component microbenchmarks cannot establish whole-scanner parity')
    binding = bundle.get('binding')
    if not isinstance(binding, dict):
        issue('missing' if binding is None else 'failed', 'binding', 'missing measurement binding')
    else:
        allowed = set(HASH_BINDINGS) | {'semantic_contract'}
        if set(binding) - allowed:
            issue('failed', 'binding', 'unknown binding fields')
        for key in allowed:
            if binding.get(key) is None:
                issue('missing', 'binding.' + key, 'missing required binding')
            elif binding.get(key) != expected_binding[key]:
                issue('failed', 'binding.' + key, 'measurement binding does not match expected artifact/workload/policy')
    cases = bundle.get('cases')
    if not isinstance(cases, list):
        issue('missing' if cases is None else 'failed', 'cases', 'cases must be an explicit list')
        return finish()
    seen = set()
    for index, case in enumerate(cases):
        location = f'cases[{index}]'
        if not isinstance(case, dict):
            issue('failed', location, 'case must be an object')
            continue
        if set(case) - {'id', *CASE_BINDINGS, 'trials'}:
            issue('failed', location, 'unknown case fields')
        name = case.get('id')
        if not isinstance(name, str) or name not in expected_cases or name in seen:
            issue('failed', location, 'unknown or duplicate case identifier')
            continue
        seen.add(name)
        expected = expected_cases[name]
        for key in CASE_BINDINGS:
            if case.get(key) is None:
                issue('missing', location + '.' + key, 'missing required case binding')
            elif case.get(key) != expected[key] or (
                    key == 'concurrency' and type(case.get(key)) is not int):
                issue('failed', location + '.' + key, 'case workload/configuration binding mismatch')
        trials = case.get('trials')
        if not isinstance(trials, list):
            issue('missing' if trials is None else 'failed', location + '.trials', 'paired trials must be a list')
            continue
        if len(trials) < expected['minimum_pairs']:
            issue('missing', location + '.trials', 'insufficient paired trials')
        pair_ids, values = set(), {metric: [] for metric in required_metrics}
        for trial_index, trial in enumerate(trials):
            at = location + f'.trials[{trial_index}]'
            if not isinstance(trial, dict):
                issue('failed', at, 'trial must be an object')
                continue
            if set(trial) - {'pair_id', 'baseline', 'candidate', 'correctness', 'metric_provenance'}:
                issue('failed', at, 'unknown trial fields')
            pair_id = trial.get('pair_id')
            if not isinstance(pair_id, str) or not pair_id or pair_id in pair_ids:
                issue('failed', at + '.pair_id', 'pair identifiers must be nonempty and unique within a case')
            else:
                pair_ids.add(pair_id)
            correctness = trial.get('correctness')
            if not isinstance(correctness, dict):
                issue('missing' if correctness is None else 'failed', at + '.correctness', 'missing correctness observations')
            else:
                required = {'baseline_status', 'candidate_status', 'baseline_transcript_sha256',
                            'candidate_transcript_sha256', 'baseline_policy_sha256', 'candidate_policy_sha256'}
                if set(correctness) - required:
                    issue('failed', at + '.correctness', 'unknown correctness fields')
                for side in ('baseline', 'candidate'):
                    if correctness.get(side + '_status') is None:
                        issue('missing', at + '.correctness', 'missing completion status')
                    elif correctness[side + '_status'] != 'completed':
                        issue('failed', at + '.correctness', 'failed, timed-out or incomplete trial cannot qualify')
                    key = side + '_transcript_sha256'
                    if correctness.get(key) is None:
                        issue('missing', at + '.' + key, 'missing semantic transcript digest')
                    elif not _sha(correctness[key]):
                        issue('failed', at + '.' + key, 'invalid semantic transcript digest')
                    key = side + '_policy_sha256'
                    if correctness.get(key) is None:
                        issue('missing', at + '.' + key, 'missing effective policy digest')
                    elif correctness[key] != expected_binding['policy_sha256']:
                        issue('failed', at + '.' + key, 'effective policy differs from required limits/parsers/rules/concurrency')
                if (correctness.get('baseline_transcript_sha256') is not None and
                        correctness.get('candidate_transcript_sha256') is not None and
                        correctness['baseline_transcript_sha256'] != correctness['candidate_transcript_sha256']):
                    issue('failed', at + '.correctness', 'semantic transcripts differ under the declared contract')
            sides = [trial.get(side) for side in ('baseline', 'candidate')]
            for side, metrics in zip(('baseline', 'candidate'), sides):
                if not isinstance(metrics, dict):
                    issue('missing' if metrics is None else 'failed', at + '.' + side, 'metric object missing')
                    continue
                if set(metrics) - set(SUPPORTED_METRICS):
                    issue('failed', at + '.' + side, 'unknown metric names')
                for key, value in metrics.items():
                    if value is not None and not _nonnegative(value):
                        issue('failed', at + '.' + side + '.' + key, 'metric must be a nonnegative finite number')
            for metric in required_metrics:
                pair = [metrics.get(metric) if isinstance(metrics, dict) else None for metrics in sides]
                if any(value is None for value in pair):
                    issue('missing', at + '.' + metric, 'both paired metric observations are required')
                    continue
                if not all(_nonnegative(value) for value in pair):
                    continue
                baseline, candidate = pair
                ratio, ratio_reason = _observed_ratio(baseline, candidate)
                values[metric].append((float(baseline), float(candidate), ratio, ratio_reason))
                if ratio_reason is not None:
                    issue('failed', at + '.' + metric, ratio_reason)
                elif candidate > baseline * max_ratio:
                    issue('failed', at + '.' + metric, 'candidate exceeds the no-regression bound in this pair')
                if metric in PERCENTILE_SAMPLES:
                    provenance = trial.get('metric_provenance', {})
                    provenance = provenance.get(metric) if isinstance(provenance, dict) else None
                    if provenance is None:
                        issue('missing', at + '.metric_provenance', metric + ' needs an externally measured per-file distribution')
                    elif (not isinstance(provenance, dict) or
                          set(provenance) != {'source', 'quantile_method', 'baseline_samples', 'candidate_samples'} or
                          provenance.get('source') != 'per_file_latency_distribution' or
                          provenance.get('quantile_method') != 'nearest_rank' or
                          any(type(provenance.get(side + '_samples')) is not int or
                              provenance[side + '_samples'] < PERCENTILE_SAMPLES[metric] for side in ('baseline', 'candidate'))):
                        issue('failed', at + '.metric_provenance', metric + ' requires nearest-rank per-file distributions with at least ' + str(PERCENTILE_SAMPLES[metric]) + ' samples per side')
        metrics_summary = {}
        for metric, rows in values.items():
            if rows:
                # Normalize by the largest observation to avoid overflow and
                # underflow caused by dividing tiny observations before adding.
                baseline = _mean([row[0] for row in rows])
                candidate = _mean([row[1] for row in rows])
                ratio, reason = _observed_ratio(baseline, candidate)
                unavailable = [row[3] for row in rows if row[2] is None]
                metrics_summary[metric] = {'pairs': len(rows), 'baseline_mean': baseline,
                    'candidate_mean': candidate, 'ratio_of_means': ratio,
                    'maximum_paired_ratio': None if unavailable else max(row[2] for row in rows)}
                if reason is not None:
                    metrics_summary[metric]['ratio_of_means_unavailable_reason'] = reason
                if unavailable:
                    metrics_summary[metric]['unavailable_paired_ratios'] = len(unavailable)
                    metrics_summary[metric]['ratio_unavailable_reasons'] = sorted(set(unavailable))
        summaries.append({'id': name, 'paired_trials': len(trials), 'metrics': metrics_summary})
    for name in sorted(set(expected_cases) - seen):
        issue('missing', 'cases.' + name, 'required workload case is absent')
    return finish()


def expected_binding_template():
    """Trusted-side skeleton; null hashes must be supplied from real artifacts."""
    expected = {key: None for key in HASH_BINDINGS}
    expected['semantic_contract'] = 'ordered-observables-v1'
    expected['cases'] = [
        {'id': name, 'workload_sha256': None, 'cache_state': cache,
         'workload_class': kind, 'concurrency': 1, 'minimum_pairs': 3}
        for name, cache, kind in [('cold', 'cold', 'ordinary'),
                                  ('warm', 'warm', 'ordinary'),
                                  ('adversarial', 'warm', 'adversarial')]]
    return expected


def measurement_template():
    """Unfilled evidence cannot be mistaken for measured baseline parity."""
    expected = expected_binding_template()
    binding = {key: value for key, value in expected.items() if key != 'cases'}
    cases = []
    for expected_case in expected['cases']:
        case = {key: value for key, value in expected_case.items() if key != 'minimum_pairs'}
        case['trials'] = [{'pair_id': 'pair-001',
            'baseline': {metric: None for metric in DEFAULT_REQUIRED_METRICS},
            'candidate': {metric: None for metric in DEFAULT_REQUIRED_METRICS},
            'correctness': {key: None for key in ('baseline_status', 'candidate_status',
                'baseline_transcript_sha256', 'candidate_transcript_sha256',
                'baseline_policy_sha256', 'candidate_policy_sha256')},
            'metric_provenance': {metric: {'source': 'per_file_latency_distribution',
                'quantile_method': 'nearest_rank', 'baseline_samples': None, 'candidate_samples': None}
                for metric in PERCENTILE_SAMPLES}}]
        cases.append(case)
    return {'schema_version': 1, 'scope': 'whole_scanner', 'binding': binding, 'cases': cases}


def _strict_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError('nonfinite JSON constant: ' + value)

    return json.loads(Path(path).read_text(), object_pairs_hook=pairs, parse_constant=constant)


def _write(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-template', type=Path)
    parser.add_argument('--write-binding-template', type=Path)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--expected-binding', type=Path)
    parser.add_argument('--required-metric', choices=SUPPORTED_METRICS, action='append')
    parser.add_argument('--max-ratio', type=float, default=1.0)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.write_template or args.write_binding_template:
        if args.bundle or args.expected_binding or args.output or args.required_metric:
            parser.error('template writing is separate from evidence evaluation')
        if args.write_template:
            _write(args.write_template, measurement_template())
        if args.write_binding_template:
            _write(args.write_binding_template, expected_binding_template())
        return 0
    if not args.bundle or not args.expected_binding:
        parser.error('--bundle and separately supplied --expected-binding are required')
    try:
        report = evaluate_measurements(_strict_json(args.bundle), _strict_json(args.expected_binding),
            args.required_metric or DEFAULT_REQUIRED_METRICS, args.max_ratio)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    if args.output:
        _write(args.output, report)
    else:
        print(json.dumps(report, indent=2, allow_nan=False))
    return {'passed_observed': 0, 'missing': 2, 'failed': 3}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
