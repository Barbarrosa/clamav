"""Independent bit/list reference checks of the nonmaterializing input view.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from canonical_input import canonical_formula, canonical_bits
from lazy_canonical import LazyCanonicalInput
from test_canonical_input import reference


class LazyCanonicalTests(unittest.TestCase):
    def check_formula(self, n, clauses):
        formula = canonical_formula(n, clauses)
        view = LazyCanonicalInput(formula)
        expected = reference(n, clauses)
        self.assertEqual(view.logical_bits, len(expected))
        self.assertEqual(list(view.iter_bits()), expected)
        self.assertEqual([view.bit_at(i) for i in range(len(expected))], expected)
        runs = list(view.iter_runs())
        self.assertTrue(all(length > 0 for _, length in runs))
        self.assertTrue(all(a[0] != b[0] for a, b in zip(runs, runs[1:])))
        self.assertEqual([bit for bit, length in runs for _ in range(length)], expected)
        for start in range(len(expected) + 1):
            for end in range(start, min(len(expected), start + 7) + 1):
                self.assertEqual(view.window(start, end - start), tuple(expected[start:end]))
            if start < len(expected):
                bit, end = view.run_at(start)
                self.assertTrue(end > start)
                self.assertTrue(all(value == bit for value in expected[start:end]))
                self.assertTrue(end == len(expected) or expected[end] != bit)
                self.assertEqual(view.skip_run(start), end)

    def test_all_small_formulas_match_independent_recursive_reference(self):
        atoms = [[], [1], [-1], [2], [-2], [1, -1], [2, -1], [1, -2, 2]]
        for clauses in itertools.chain(([],), itertools.product(atoms, repeat=1),
                                      itertools.product(atoms, repeat=2)):
            with self.subTest(clauses=clauses):
                self.check_formula(2, clauses)

    def test_empty_ambient_universe_and_empty_clause(self):
        self.check_formula(0, [])
        self.check_formula(0, [[]])

    def test_declared_free_variables_and_duplicates_preserved(self):
        view = LazyCanonicalInput(canonical_formula(15, [[1, 1], [1], [-2]]))
        self.assertEqual(view.window(0, 16), tuple([True] * 15 + [False]))
        self.assertEqual(view.window(0, view.logical_bits), tuple(canonical_bits(15, [[1], [-2]])))

    def test_huge_unary_values_are_not_materialized(self):
        n = 10**30
        view = LazyCanonicalInput(canonical_formula(n, [[n, -n]]), max_read_bits=128)
        self.assertLess(view.index_storage_bytes, 1024)
        self.assertEqual(view.run_at(0), (True, n))
        self.assertFalse(view.bit_at(n))
        self.assertTrue(view.bit_at(n + 1))
        self.assertEqual(view.window(n - 3, 7), (True, True, True, False, True, True, True))
        self.assertEqual(view.window(view.logical_bits - 3, 3), (False, False, False))
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            view.window(0, 129)

    def test_bounds_and_read_limits_fail_before_expansion(self):
        formula = canonical_formula(3, [[1, -3]])
        view = LazyCanonicalInput(formula, max_read_bits=3)
        for value in (-1, True, 1.5, view.logical_bits):
            with self.subTest(value=value), self.assertRaises(ValueError):
                view.bit_at(value)
        self.assertEqual(view.window(view.logical_bits, 0), ())
        for start, count in [(0, 4), (0, -1), (view.logical_bits, 1), (True, 0)]:
            with self.subTest(start=start, count=count), self.assertRaises(ValueError):
                view.window(start, count)
        with self.assertRaises(ValueError):
            list(view.iter_runs(4, 3))
        with self.assertRaises(ValueError):
            LazyCanonicalInput(formula, max_read_bits=True)
        with self.assertRaises(ValueError):
            LazyCanonicalInput('not canonical')

    def test_cli_only_writes_small_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cnf, report = root / 'query.cnf', root / 'report.json'
            cnf.write_text('p cnf 1000000000000 1\n1000000000000 0\n')
            subprocess.run([sys.executable, str(Path(__file__).with_name('lazy_canonical.py')),
                            '--cnf', str(cnf), '--report', str(report), '--random-reads', '50',
                            '--run-limit', '100'], check=True, capture_output=True, timeout=5)
            data = json.loads(report.read_text())
            self.assertGreater(data['canonical_logical_bits'], 10**12)
            self.assertFalse(data['full_input_materialized'])
            self.assertFalse(data['linked_counting_algorithm_executed'])
            self.assertEqual(len(data['adapter_source_sha256']), 64)
            self.assertEqual(len(data['canonical_codec_source_sha256']), 64)
            if sys.platform.startswith('linux'):
                self.assertIn('address_space_bytes', data['observed_resource_limits'])
                self.assertIn('cpu_seconds', data['observed_resource_limits'])
            self.assertEqual(set(p.name for p in root.iterdir()), {'query.cnf', 'report.json'})


if __name__ == '__main__':
    unittest.main()
