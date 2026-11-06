"""Meaningful rejection checks for empirical performance qualification.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from measurement_contract import (DEFAULT_REQUIRED_METRICS, HASH_BINDINGS,
    evaluate_measurements, expected_binding_template, measurement_template)


def observations():
    expected = expected_binding_template()
    for index, key in enumerate(HASH_BINDINGS):
        expected[key] = f'{index + 1:064x}'
    for index, case in enumerate(expected['cases']):
        case['workload_sha256'] = f'{index + 100:064x}'
    bundle = measurement_template()
    bundle['binding'] = {key: value for key, value in expected.items() if key != 'cases'}
    for case, declared in zip(bundle['cases'], expected['cases']):
        case['workload_sha256'] = declared['workload_sha256']
        trial = case['trials'][0]
        trial['baseline'] = {key: 10.0 for key in DEFAULT_REQUIRED_METRICS}
        trial['candidate'] = {key: 9.0 for key in DEFAULT_REQUIRED_METRICS}
        trial['correctness'] = {
            'baseline_status': 'completed', 'candidate_status': 'completed',
            'baseline_transcript_sha256': 'a' * 64, 'candidate_transcript_sha256': 'a' * 64,
            'baseline_policy_sha256': expected['policy_sha256'],
            'candidate_policy_sha256': expected['policy_sha256']}
        for metric in ('scan_latency_p95_ms', 'scan_latency_p99_ms'):
            trial['metric_provenance'][metric].update(baseline_samples=1000, candidate_samples=1000)
        case['trials'] = [copy.deepcopy(trial) for _ in range(declared['minimum_pairs'])]
        for index, item in enumerate(case['trials']):
            item['pair_id'] = f'pair-{index}'
    return bundle, expected


class MeasurementContractTests(unittest.TestCase):
    def setUp(self):
        self.bundle, self.expected = observations()

    def evaluate(self, bundle=None, **kwargs):
        return evaluate_measurements(self.bundle if bundle is None else bundle,
                                     self.expected, **kwargs)

    def test_complete_observations_pass_without_claiming_a_proof(self):
        before = copy.deepcopy(self.bundle)
        result = self.evaluate()
        self.assertEqual(result['status'], 'passed_observed')
        self.assertTrue(result['empirical_only'])
        self.assertFalse(result['formal_performance_proof'])
        self.assertFalse(result['all_input_guarantee'])
        self.assertFalse(result['statistical_confidence_established'])
        self.assertEqual(result['cases'][0]['metrics']['scan_cpu_seconds']['maximum_paired_ratio'], 0.9)
        self.assertEqual(self.bundle, before)

    def test_one_slow_pair_fails_even_when_mean_improves(self):
        trials = self.bundle['cases'][0]['trials']
        for trial, value in zip(trials, (1.0, 1.0, 11.0)):
            trial['candidate']['scan_cpu_seconds'] = value
        result = self.evaluate()
        self.assertEqual(result['status'], 'failed')
        metrics = result['cases'][0]['metrics']['scan_cpu_seconds']
        self.assertLess(metrics['ratio_of_means'], 1)
        self.assertGreater(metrics['maximum_paired_ratio'], 1)

    def test_missing_case_pair_or_metric_cannot_pass(self):
        variants = []
        missing_case = copy.deepcopy(self.bundle); missing_case['cases'].pop(); variants.append(missing_case)
        missing_pair = copy.deepcopy(self.bundle); missing_pair['cases'][0]['trials'].pop(); variants.append(missing_pair)
        missing_metric = copy.deepcopy(self.bundle)
        del missing_metric['cases'][0]['trials'][0]['candidate']['update_cpu_seconds']
        variants.append(missing_metric)
        for bundle in variants:
            with self.subTest(bundle=bundle):
                self.assertEqual(self.evaluate(bundle)['status'], 'missing')

    def test_each_binding_is_checked_not_just_candidate_name(self):
        for key in (*HASH_BINDINGS, 'semantic_contract'):
            bundle = copy.deepcopy(self.bundle); bundle['binding'][key] = 'wrong'
            with self.subTest(key=key):
                self.assertEqual(self.evaluate(bundle)['status'], 'failed')
        for key, value in [('workload_sha256', 'f' * 64), ('cache_state', 'warm'),
                           ('workload_class', 'adversarial'), ('concurrency', 2)]:
            bundle = copy.deepcopy(self.bundle); bundle['cases'][0][key] = value
            with self.subTest(key=key):
                self.assertEqual(self.evaluate(bundle)['status'], 'failed')

    def test_microbenchmarks_do_not_qualify_whole_scanner_parity(self):
        self.bundle['scope'] = 'field_microbenchmark'
        self.assertEqual(self.evaluate()['status'], 'failed')

    def test_semantic_difference_or_changed_policy_fails_even_if_faster(self):
        for field, value in [('candidate_transcript_sha256', 'b' * 64),
                             ('candidate_policy_sha256', 'b' * 64),
                             ('candidate_status', 'timeout')]:
            bundle = copy.deepcopy(self.bundle)
            bundle['cases'][0]['trials'][0]['correctness'][field] = value
            with self.subTest(field=field):
                self.assertEqual(self.evaluate(bundle)['status'], 'failed')

    def test_missing_semantics_or_completion_never_becomes_a_pass(self):
        for key in ('candidate_transcript_sha256', 'candidate_status', 'candidate_policy_sha256'):
            bundle = copy.deepcopy(self.bundle)
            del bundle['cases'][0]['trials'][0]['correctness'][key]
            with self.subTest(key=key):
                self.assertEqual(self.evaluate(bundle)['status'], 'missing')

    def test_p99_requires_latency_distributions_not_few_cpu_trials(self):
        for change in ('absent', 'small', 'wrong_source'):
            bundle = copy.deepcopy(self.bundle); trial = bundle['cases'][0]['trials'][0]
            if change == 'absent':
                del trial['metric_provenance']
            elif change == 'small':
                trial['metric_provenance']['scan_latency_p99_ms']['candidate_samples'] = 3
            else:
                trial['metric_provenance']['scan_latency_p99_ms']['source'] = 'paired_cpu_mean'
            with self.subTest(change=change):
                self.assertNotEqual(self.evaluate(bundle)['status'], 'passed_observed')

    def test_unknown_metric_boolean_nonfinite_and_negative_rejected(self):
        for value in (True, float('nan'), float('inf'), -1, '9.0'):
            bundle = copy.deepcopy(self.bundle)
            bundle['cases'][0]['trials'][0]['candidate']['scan_cpu_seconds'] = value
            with self.subTest(value=value):
                self.assertEqual(self.evaluate(bundle)['status'], 'failed')
        self.bundle['cases'][0]['trials'][0]['candidate']['scan_cup_seconds'] = 9
        self.assertEqual(self.evaluate()['status'], 'failed')

    def test_zero_cpu_and_no_scratch_allocations_are_observations_not_missing(self):
        metrics = ('scan_cpu_seconds', 'scan_context_bytes', 'scan_scratch_bytes', 'builder_scratch_bytes')
        for case in self.bundle['cases']:
            for trial in case['trials']:
                for side in ('baseline', 'candidate'):
                    for metric in metrics:
                        trial[side][metric] = 0
        report = self.evaluate()
        self.assertEqual(report['status'], 'passed_observed')
        self.assertEqual(report['issues'], [])
        for case in report['cases']:
            for metric in metrics:
                self.assertEqual(case['metrics'][metric]['baseline_mean'], 0)
                self.assertEqual(case['metrics'][metric]['ratio_of_means'], 1)
                self.assertEqual(case['metrics'][metric]['maximum_paired_ratio'], 1)
        json.dumps(report, allow_nan=False)

    def test_adding_cost_to_zero_baseline_fails_with_explicit_finite_json_report(self):
        for case in self.bundle['cases']:
            for trial in case['trials']:
                trial['baseline']['builder_scratch_bytes'] = 0
                trial['candidate']['builder_scratch_bytes'] = 64
        report = self.evaluate()
        self.assertEqual(report['status'], 'failed')
        summary = report['cases'][0]['metrics']['builder_scratch_bytes']
        self.assertIsNone(summary['ratio_of_means'])
        self.assertIsNone(summary['maximum_paired_ratio'])
        self.assertIn('zero baseline', summary['ratio_of_means_unavailable_reason'])
        self.assertEqual(summary['unavailable_paired_ratios'], 3)
        json.dumps(report, allow_nan=False)

    def test_one_zero_baseline_increase_cannot_hide_behind_mean_improvement(self):
        trial = self.bundle['cases'][0]['trials'][0]
        trial['baseline']['scan_cpu_seconds'] = 0
        trial['candidate']['scan_cpu_seconds'] = 1
        report = self.evaluate()
        self.assertEqual(report['status'], 'failed')
        summary = report['cases'][0]['metrics']['scan_cpu_seconds']
        self.assertLess(summary['ratio_of_means'], 1)
        self.assertIsNone(summary['maximum_paired_ratio'])
        self.assertEqual(summary['unavailable_paired_ratios'], 1)

    def test_duplicate_cases_and_pairs_rejected(self):
        bundle = copy.deepcopy(self.bundle); bundle['cases'].append(copy.deepcopy(bundle['cases'][0]))
        self.assertEqual(self.evaluate(bundle)['status'], 'failed')
        self.bundle['cases'][0]['trials'][1]['pair_id'] = self.bundle['cases'][0]['trials'][0]['pair_id']
        self.assertEqual(self.evaluate()['status'], 'failed')

    def test_extreme_finite_measurements_do_not_break_report_serialization(self):
        for value in (5e-324, 1.7e308):
            bundle = copy.deepcopy(self.bundle)
            for case in bundle['cases']:
                for trial in case['trials']:
                    for side in ('baseline', 'candidate'):
                        trial[side]['scan_cpu_seconds'] = value
            with self.subTest(value=value):
                report = self.evaluate(bundle)
                self.assertEqual(report['status'], 'passed_observed')
                json.dumps(report, allow_nan=False)

    def test_trusted_configuration_cannot_relax_parity_or_omit_coverage(self):
        for ratio in (True, 0, -1, 1.01, float('nan')):
            with self.subTest(ratio=ratio), self.assertRaises(ValueError):
                self.evaluate(max_ratio=ratio)
        with self.assertRaises(ValueError):
            self.evaluate(required_metrics=['scan_cpu_seconds', 'unknown'])
        expected = copy.deepcopy(self.expected); expected['cases'].pop()
        with self.assertRaises(ValueError):
            evaluate_measurements(self.bundle, expected)

    def test_unfilled_template_is_missing_evidence(self):
        self.assertEqual(evaluate_measurements(None, self.expected)['status'], 'missing')
        self.assertEqual(evaluate_measurements(measurement_template(), self.expected)['status'], 'missing')

    def test_cli_templates_and_duplicate_json_rejection(self):
        script = Path(__file__).with_name('measurement_contract.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bundle = root / 'bundle.json'; binding = root / 'binding.json'
            subprocess.run([sys.executable, str(script), '--write-template', str(bundle),
                '--write-binding-template', str(binding)], check=True)
            self.assertIsNone(json.loads(bundle.read_text())['binding']['baseline_artifact_sha256'])
            binding.write_text(json.dumps(self.expected))
            bundle.write_text('{"schema_version":1,"schema_version":1}')
            result = subprocess.run([sys.executable, str(script), '--bundle', str(bundle),
                '--expected-binding', str(binding)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('duplicate JSON key', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
