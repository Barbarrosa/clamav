"""Adversarial checks of synthetic semantic evidence and fixture coverage.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

import correctness as c


class CorrectnessEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.case = {'name': 'test', 'repeats': 1, 'reject_load': False,
                     'inputs': [{'path': '/test/file.bin', 'sha256': 'input-hash'}],
                     'predicate': {'kind': 'strong', 'expected': 'Strong.Test'}}
        self.limits = {'address_space_bytes': 1024, 'cpu_seconds': 10}
        self.rows = [{'kind': 'runtime', 'engine_sha256': 'library-hash', 'unrar_modules_verified': 1},
                     {'kind': 'qualification_limits', **self.limits},
                     {'kind': 'engine', 'signatures': 1}]
        for allmatch in (0, 1):
            self.rows.append({'kind': 'scan', 'path': '/test/file.bin', 'round': 0,
                              'allmatch': allmatch, 'return_code': 1, 'verdict': 2,
                              'final_name': 'Strong.Test', 'root_type': 'CL_TYPE_ASCII',
                              'sha256': 'input-hash', 'after_sha256': 'input-hash',
                              'hold_bits': 2, 'candidate_outcome': 'held', 'scanned_bytes': 8,
                              'events': [{'event': 'alert', 'name': 'Strong.Test'}]})

    def validate(self, rows=None, case=None, returncode=0):
        return c.validate_run(case or self.case, rows or self.rows, returncode, 'library-hash', self.limits)

    def test_same_multiset_with_changed_callback_order_is_distinct(self):
        left = copy.deepcopy(self.rows[-1])
        left['events'] += [{'event': 'alert', 'name': 'Strong.Second'}]
        right = copy.deepcopy(left)
        right['events'].reverse()
        self.assertEqual(sorted(c.alerts(left)), sorted(c.alerts(right)))
        self.assertNotEqual(c.digest(c.semantic([left])), c.digest(c.semantic([right])))

    def test_missing_or_wrong_library_and_changed_limits_are_rejected(self):
        for mutate in ('library', 'limit', 'missing-runtime'):
            rows = copy.deepcopy(self.rows)
            if mutate == 'library': rows[0]['engine_sha256'] = 'wrong-library'
            elif mutate == 'limit': rows[1]['cpu_seconds'] = 20
            else: rows.pop(0)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.validate(rows)

    def test_changed_input_missing_scans_and_swapped_modes_are_rejected(self):
        for mutate in ('input', 'missing', 'mode'):
            rows = copy.deepcopy(self.rows)
            if mutate == 'input': rows[-1]['after_sha256'] = 'modified'
            elif mutate == 'missing': rows.pop()
            else: rows[-1]['allmatch'] = 0
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.validate(rows)

    def test_stop_trust_and_severity_have_independent_predicates(self):
        row = copy.deepcopy(self.rows[-1])
        for kind in ('stop', 'trust'):
            case = copy.deepcopy(self.case)
            case['predicate'] = {'kind': kind}
            self.assertTrue(c.predicate_failures(case, [row]))
        row['events'] = [{'event': 'alert', 'name': 'Weak.Only'}]
        self.assertTrue(c.predicate_failures(self.case, [row]))
        weak = copy.deepcopy(self.case)
        weak['predicate'] = {'kind': 'no_strong'}
        self.assertTrue(c.predicate_failures(weak, [row]))  # A strong verdict is not weak-only.
        row['verdict'] = 0
        row['final_name'] = None
        self.assertFalse(c.predicate_failures(weak, [row]))

    def test_load_failure_requires_a_clean_exit_and_no_scan(self):
        case = copy.deepcopy(self.case)
        case['reject_load'] = True
        rows = copy.deepcopy(self.rows[:2])
        self.assertEqual(self.validate(rows, case, returncode=2)['scan_records'], 0)
        for code in (0, -11):
            with self.assertRaises(ValueError): self.validate(rows, case, returncode=code)
        with self.assertRaises(ValueError): self.validate(self.rows, case, returncode=2)

    def test_fixture_bytes_and_required_cases_are_independently_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = c.generate_fixtures(root, rules=2, hash_distractors=3)
            names = {case['name'] for case in cases}
            self.assertTrue({'duplicate-order', 'macro-fallback', 'invalid-macro', 'file-limit',
                             'missing-file', 'callback-stop', 'callback-trust', 'custom-logical'} <= names)
            self.assertEqual((root / 'marker.bin').read_bytes(), b'\0' * 1024 + b'ABCDEFGH' + b'\0' * 1024)
            order = root / 'duplicate-order/ordering.ndb'
            lines = order.read_text().splitlines()
            self.assertEqual(len(lines), 4)
            self.assertEqual(lines[0], 'Foundations.Order.00000:0:*:41424344??464748')
            self.assertEqual(lines[2], 'Foundations.Order.00001:0:*:41424344??464748')
            records = (root / 'duplicate-order/preload.hdb').read_text().splitlines()
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0], hashlib.md5(b'hash-distractor/0').hexdigest() + ':1:Foundations.Hash.0')
            macro = next(case for case in cases if case['name'] == 'macro-fallback')
            self.assertIn('${4-16}0$', (Path(macro['database']) / 'rules.ldb').read_text())
            self.assertEqual(len(macro['inputs']), 2)


if __name__ == '__main__':
    unittest.main()
