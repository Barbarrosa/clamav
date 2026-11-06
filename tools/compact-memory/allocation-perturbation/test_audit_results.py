"""Adversarial saved-evidence checks, independent of the matrix runner.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from audit_results import AuditError, audit, semantic_hash


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value) + '\n')


def write_records(path, values):
    path.write_text(''.join(json.dumps(value) + '\n' for value in values))
    return digest(path.read_bytes())


def matrix(directory):
    """Small complete matrix with independent raw, summary and manifest copies."""
    phases = ['initial', 'loaded', 'compiled', 'scanned', 'all_freed']
    fixtures = [{'name': 'first', 'bytes': 7, 'sha256': 'b' * 64},
                {'name': 'second', 'bytes': 9, 'sha256': 'c' * 64}]
    scheduled, cases, aggregates = [], [], []
    for ordinal, dose in enumerate((0, 8)):
        case = {'ordinal': ordinal, 'variant': 'instrumented', 'group': 'names',
                'dose': dose, 'repetition': 0}
        scheduled.append(dict(case))
        rows = [{'kind': 'runtime', 'engine_sha256': 'a' * 64, 'unrar_modules_verified': 1},
                {'kind': 'engine_load', 'return_code': 0, 'signatures': 123},
                {'kind': 'engine_compile', 'return_code': 0}]
        snapshots, perturb = {}, []
        for phase in phases:
            snapshot = {'kind': 'memory_snapshot', 'phase': phase, 'rss_kib': 100 + 2 * dose,
                        'address_space_limit_bytes': 4096, 'cpu_limit_seconds': 120}
            snapshots[phase] = snapshot
            rows.append(snapshot)
            started = phase != 'initial'
            count = 2 if started else 0
            counter = {'calls': count, 'requested_bytes': 16 if started else 0,
                       'successful_calls': count, 'failed_calls': 0,
                       'added_bytes': dose * count, 'injected_calls': count if dose else 0,
                       'skipped_cap_calls': 0, 'overflow_failures': 0}
            perturb.append({'phase': phase, 'instrumentation_enabled': True,
                            'configuration_valid': True, 'configured_group': 'names',
                            'pad_bytes': dose, 'max_added_bytes': 512,
                            'scope': 'cumulative, not live', 'groups': {'names': counter}})
        scans = []
        for fixture in fixtures:
            scans.append({'kind': 'scan', 'phase': 'fixture_scan', 'round': 0,
                          'allmatch': 1, 'return_code': 0, 'verdict': 0,
                          'final_name': None, 'root_type': 'CL_TYPE_PDF',
                          'sha256': fixture['sha256'], 'after_sha256': fixture['sha256'],
                          'hold_bits': 0, 'candidate_outcome': 'clean', 'scanned_bytes': 0,
                          'input_bytes': fixture['bytes'],
                          'events': [{'event': 'pre_scan'}, {'event': 'post_scan'}]})
        rows.extend(scans)
        names = {field: f'{ordinal}-{field}.jsonl' for field in ('stdout', 'stderr', 'perturb_log')}
        hashes = {'stdout_sha256': write_records(directory / names['stdout'], rows),
                  'stderr_sha256': write_records(directory / names['stderr'], []),
                  'perturb_log_sha256': write_records(directory / names['perturb_log'], perturb)}
        delta = {phase: 2 * dose * 1024 for phase in phases}
        case.update(names, **hashes, status='complete', return_code=0, timeout=False,
                    snapshots=snapshots, semantic_sha256=semantic_hash(scans), signatures=[123],
                    perturb_totals=copy.deepcopy(perturb[-1]['groups']),
                    cumulative_added_bytes=dose * 2, injected_calls=2 if dose else 0,
                    dose_censored_by_cap=False, rss_delta_vs_zero_bytes=delta)
        cases.append(case)
        aggregates.append({'group': 'names', 'dose_bytes_per_matching_request': dose,
                           'planned': 1, 'completed': 1, 'uncensored_semantically_matching': 1,
                           'median_cumulative_added_bytes': dose * 2,
                           'median_injected_calls': 2 if dose else 0,
                           'median_rss_delta_bytes': delta})
    write_json(directory / 'plan.json', {'schema_version': 1, 'plan': scheduled,
               'identities': {'instrumented': {'library_sha256': 'a' * 64}},
               'fixtures': fixtures, 'reload': False, 'scan_passes': 1,
               'resource_limits': {'address_space_bytes': 4096, 'cpu_seconds': 120,
                                   'max_cumulative_added_bytes': 512}})
    write_json(directory / 'summary.json', {'schema_version': 1, 'cases': cases,
               'aggregates': aggregates, 'complete': True, 'all_semantics_match': True})


class AuditResultsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='perturb-audit-tests-')
        self.root = Path(self.temporary.name)
        matrix(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_evidence_is_independently_checked(self):
        result = audit(self.root)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['validated_cases'], 2)
        self.assertEqual(result['validated_scan_records'], 4)
        self.assertTrue(result['all_ordered_input_hashes_match_plan'])
        self.assertEqual(len(result['artifact_sha256']), 8)

    def test_artifact_tampering_fails_even_when_semantics_unchanged(self):
        path = self.root / '1-stdout.jsonl'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(AuditError, 'artifact hash mismatch'):
            audit(self.root)

    def test_scan_hashes_are_bound_to_ordered_manifest(self):
        plan = json.loads((self.root / 'plan.json').read_text())
        plan['fixtures'].reverse()
        write_json(self.root / 'plan.json', plan)
        with self.assertRaisesRegex(AuditError, 'ordered scan inputs differ'):
            audit(self.root)

    def test_padding_counter_tampering_fails_after_rehashing(self):
        path = self.root / '1-perturb_log.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[-1]['groups']['names']['added_bytes'] += 1
        summary = json.loads((self.root / 'summary.json').read_text())
        summary['cases'][1]['perturb_log_sha256'] = write_records(path, rows)
        write_json(self.root / 'summary.json', summary)
        with self.assertRaisesRegex(AuditError, 'byte/dose counter mismatch'):
            audit(self.root)

    def test_changed_callback_order_fails_after_rehashing_and_recounting(self):
        path = self.root / '1-stdout.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        scans = [row for row in rows if row.get('kind') == 'scan']
        scans[0]['events'].reverse()
        summary = json.loads((self.root / 'summary.json').read_text())
        summary['cases'][1]['stdout_sha256'] = write_records(path, rows)
        summary['cases'][1]['semantic_sha256'] = semantic_hash(scans)
        write_json(self.root / 'summary.json', summary)
        with self.assertRaisesRegex(AuditError, 'ordered scan semantics differ'):
            audit(self.root)

    def test_aggregate_rss_claim_is_checked_against_raw_cases(self):
        summary = json.loads((self.root / 'summary.json').read_text())
        summary['aggregates'][1]['median_rss_delta_bytes']['compiled'] += 1
        write_json(self.root / 'summary.json', summary)
        with self.assertRaisesRegex(AuditError, 'aggregate RSS median mismatch'):
            audit(self.root)


if __name__ == '__main__':
    unittest.main()
