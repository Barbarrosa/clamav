"""Evidence-integrity tests, not tests that merely repeat runtime implementations.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from runner import (attach_evidence, compare, copy_database, extract, quantile,
                    semantic_transcript, verify_inputs)


def fixture(path='/private/fixture', identity='a' * 64):
    return {'path': path, 'bytes': 7, 'sha256': identity}


def scan(record, phase='file_cache_empty', round_number=0):
    return {'kind': 'scan', 'path': record['path'], 'phase': phase, 'round': round_number,
            'allmatch': 1, 'return_code': 0, 'verdict': 0, 'final_name': None,
            'root_type': 'CL_TYPE_PDF', 'sha256': record['sha256'], 'after_sha256': record['sha256'],
            'hold_bits': 0, 'candidate_outcome': 'clean', 'scanned_bytes': 7,
            'input_bytes': record['bytes'], 'events': [{'event': 'pre_scan', 'depth': 0}],
            'engine_scan_wall_seconds': .002, 'engine_scan_cpu_seconds': .001}


def baseline_rows(case='scan'):
    rows = [{'kind': 'runtime', 'engine_sha256': 'b' * 64, 'unrar_modules_verified': 1},
            {'kind': 'resource_limits', 'address_space_bytes': 4096, 'cpu_soft_seconds': 10, 'cpu_hard_seconds': 15, 'cpu_affinity': [0]},
            {'kind': 'runtime_modules', 'modules': [{'kind': kind, 'path': '/' + kind, 'sha256': 'd' * 64} for kind in ('iface', 'unrar')]},
            {'kind': 'engine', 'skipped': 0, 'signatures': 123, 'construction_hwm_kib': 12},
            {'kind': 'startup', 'cpu_seconds': 1, 'wall_seconds': 2, 'rss_kib': 10,
             'result_cache_enabled': 0, 'metadata': 1},
            {'kind': 'page_cache', 'requested_warm': 1, 'pages': 3, 'resident_pages': 3},
            {'kind': 'all_engines_freed'}]
    f = fixture()
    if case == 'scan':
        rows += [scan(f), scan(f, 'file_cache_hydrated', 1),
                 {'kind': 'batch', 'rss_kib': 11}, {'kind': 'batch', 'rss_kib': 12}]
    else:
        rows += [scan(f, 'concurrent_scan', 0), scan(f, 'concurrent_scan', 1),
                 {'kind': 'concurrency', 'workers': 2, 'cpu_seconds': .003,
                  'wall_seconds': .004, 'rss_kib': 13}]
    return rows


class QualificationRunnerTests(unittest.TestCase):
    def test_nearest_rank_quantiles_and_bad_measurements(self):
        self.assertEqual(quantile(list(range(1, 101)), .95), 95)
        self.assertEqual(quantile(list(range(1, 101)), .99), 99)
        self.assertEqual(quantile([.7], .99), .7)
        for values, p in (([], .95), ([float('nan')], .95), ([True], .95), ([-1], .99), ([1], 0)):
            with self.assertRaises(ValueError): quantile(values, p)

    def test_exact_ordered_manifest_and_callback_multiplicity(self):
        fixtures = [fixture(), fixture('/private/second', 'c' * 64)]
        rows = [scan(f) for f in fixtures] + [scan(f, 'file_cache_hydrated', 1) for f in fixtures]
        expected, _ = semantic_transcript(rows, 'scan', fixtures, 1, 1)
        changed = copy.deepcopy(rows); changed[0]['events'].append(changed[0]['events'][0])
        self.assertNotEqual(expected, semantic_transcript(changed, 'scan', fixtures, 1, 1)[0])
        changed = rows[1:2] + rows[:1] + rows[2:]
        with self.assertRaisesRegex(ValueError, 'manifest'): semantic_transcript(changed, 'scan', fixtures, 1, 1)
        with self.assertRaisesRegex(ValueError, 'incomplete'): semantic_transcript(rows[:-1], 'scan', fixtures, 1, 1)

    def test_expected_error_is_compared_instead_of_discarded(self):
        f = fixture(); rows = [scan(f), scan(f, 'file_cache_hydrated', 1)]
        expected = semantic_transcript(rows, 'scan', [f], 1, 1)[0]
        rows[0].update(return_code=20, candidate_outcome='failed', hold_bits=32)
        self.assertNotEqual(expected, semantic_transcript(rows, 'scan', [f], 1, 1)[0])

    def test_runtime_limits_and_incomplete_cache_control_cannot_pass(self):
        args = SimpleNamespace(address_space_bytes=4096, cpu_seconds=10, scan_repeats=1, concurrency=2, cpu=0, concurrency_cpus=[0])
        identity = {'library_sha256': 'b' * 64, 'runtime_modules': {kind: {'path': '/' + kind, 'sha256': 'd' * 64} for kind in ('iface', 'unrar')}}
        result = extract(baseline_rows(), 'scan', [fixture()], args, identity)
        latencies = [r for r in result['observations'] if r['metric'].startswith('scan_latency')]
        self.assertTrue(all(not r['eligible'] for r in latencies))
        self.assertTrue(all(r['value'] == 2 for r in latencies))
        for kind, key, value in (('runtime', 'engine_sha256', 'd' * 64),
                                 ('resource_limits', 'cpu_soft_seconds', 11),
                                 ('page_cache', 'resident_pages', 2)):
            rows = baseline_rows(); next(r for r in rows if r['kind'] == kind)[key] = value
            with self.assertRaises(ValueError): extract(rows, 'scan', [fixture()], args, identity)

    def test_concurrent_process_cpu_is_not_summed_across_overlapping_files(self):
        args = SimpleNamespace(address_space_bytes=4096, cpu_seconds=10, scan_repeats=1, concurrency=2, cpu=0, concurrency_cpus=[0])
        rows = baseline_rows('concurrency')
        for row in rows:
            if row['kind'] == 'scan': row['engine_scan_cpu_seconds'] = 10
        identity = {'library_sha256': 'b' * 64, 'runtime_modules': {kind: {'path': '/' + kind, 'sha256': 'd' * 64} for kind in ('iface', 'unrar')}}
        result = extract(rows, 'concurrency', [fixture()], args, identity)
        cpu = next(r for r in result['observations'] if r['metric'] == 'scan_cpu_seconds')
        self.assertEqual(cpu['value'], .003)

    def test_favorable_average_does_not_hide_a_regressing_pair(self):
        rows = []
        for round_number, value in enumerate((8, 11, 7)):
            for variant, cost in (('retained', 10), ('candidate', value)):
                rows.append({'variant': variant, 'operation': 'scan', 'workload': 'combined',
                             'database_cache': 'hydrated', 'round': round_number, 'status': 'complete',
                             'semantic_sha256': 'a' * 64, 'signatures': [123],
                             'observations': [{'metric': 'scan_wall_seconds', 'subcase': 'cold',
                                               'value': cost, 'eligible': True, 'provenance': {}}]})
        result = compare(rows, {}, 3)
        self.assertEqual(result['comparisons']['retained']['metrics']['scan_wall_seconds']['status'], 'failed')
        self.assertEqual(result['strict_qualification_status'], 'failed')
        self.assertFalse(result['promotion_authorized'])

    def test_unknowns_and_missing_upstream_are_not_numeric_zero_or_passes(self):
        result = compare([], {}, 3)
        self.assertEqual(result['strict_qualification_status'], 'incomplete')
        self.assertFalse(result['promotion_authorized'])
        for row in result['comparisons']['upstream']['metrics'].values():
            self.assertEqual(row['status'], 'unknown')
            self.assertEqual(row['pairs'], [])

    def test_cache_control_copy_is_not_a_hard_link_and_preserves_all_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir()
            (source / 'main.cvd').write_bytes(b'fake signed fixture')
            (source / 'custom.ndb').write_bytes(b'custom rules must not be silently dropped')
            records = copy_database(source, root / 'copy')
            self.assertEqual({r['name'] for r in records}, {'main.cvd', 'custom.ndb'})
            self.assertNotEqual((source / 'main.cvd').stat().st_ino, (root / 'copy/main.cvd').stat().st_ino)
            (source / 'alias').symlink_to(source / 'main.cvd')
            with self.assertRaisesRegex(ValueError, 'symlinks'): copy_database(source, root / 'unsafe')

    def test_inputs_rechecked_after_execution_detect_same_length_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture'; path.write_bytes(b'abcdef')
            identities = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}
            verify_inputs(identities)
            path.write_bytes(b'abcdeg')
            with self.assertRaisesRegex(ValueError, 'changed'): verify_inputs(identities)

    def test_runtime_module_identity_is_verified_in_the_child_report(self):
        args = SimpleNamespace(address_space_bytes=4096, cpu_seconds=10, scan_repeats=1, concurrency=2, cpu=0, concurrency_cpus=[0])
        rows = baseline_rows()
        next(r for r in rows if r['kind'] == 'runtime_modules')['modules'][0]['sha256'] = 'e' * 64
        identity = {'library_sha256': 'b' * 64, 'runtime_modules': {kind: {'path': '/' + kind, 'sha256': 'd' * 64} for kind in ('iface', 'unrar')}}
        with self.assertRaisesRegex(ValueError, 'unrar'): extract(rows, 'scan', [fixture()], args, identity)

    def test_correctness_and_resource_reports_cannot_bind_to_other_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); correctness = root / 'correctness.json'; audit = root / 'audit.json'
            correctness.write_text(json.dumps({'status': 'passed', 'qualifying_comparison': True,
                'binding': {'libraries': {'baseline': {'library_sha256': 'a' * 64},
                                          'candidate': {'library_sha256': 'b' * 64}}}}))
            audit.write_text(json.dumps({'observed_mpool_sha256': 'c' * 64, 'resource_deltas': {}}))
            args = SimpleNamespace(correctness_report=correctness, resource_audit=audit)
            variants = {'retained': {'library_sha256': 'a' * 64},
                        'candidate': {'library_sha256': 'b' * 64,
                                      'source': {'source_files': {'libclamav/mpool.c': 'c' * 64}}}}
            attached = attach_evidence(args, variants)
            self.assertTrue(attached['correctness']['qualifying_comparison'])
            self.assertTrue(attached['resource_audit']['source_binding_verified'])
            variants['candidate']['source']['source_files']['libclamav/mpool.c'] = 'd' * 64
            with self.assertRaisesRegex(ValueError, 'stale'): attach_evidence(args, variants)
            variants['candidate']['library_sha256'] = 'e' * 64
            with self.assertRaisesRegex(ValueError, 'library binding'): attach_evidence(args, variants)


if __name__ == '__main__': unittest.main()
