"""Budget-query status and independent witness checks on an exact small model.
SPDX-License-Identifier: GPL-2.0-only
"""
import json
from pathlib import Path
import tempfile
import unittest

from pysat.formula import WCNF

from run_budget_query import append_witness, run, verify_witness, weighted_costs


class BudgetQueryTests(unittest.TestCase):
    def test_exact_boundary_and_private_dimacs(self):
        formula = WCNF()
        formula.append([1, 2])
        formula.append([-1], weight=3)
        formula.append([-2], weight=5)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'model.wcnf'
            formula.to_file(str(path))
            report = run(path, [3, 2], root / 'private', root / 'report.json', timeout=5)
            self.assertEqual([q['status'] for q in report['queries']], ['sat', 'unsat'])
            sat = report['queries'][0]
            self.assertEqual(sat['verified_weighted_byte_cost'], 3)
            self.assertTrue(sat['all_original_and_encoded_hard_clauses_verified'])
            self.assertLessEqual(sat['maximum_clause_width'], 3)
            self.assertTrue((root / 'private' / sat['dimacs_private_file']).exists())
            model = json.loads((root / 'private' / sat['witness_private_file']).read_text())
            self.assertEqual(verify_witness(model, formula.hard, [(1, 3), (2, 5)], 3), 3)

    def test_false_or_overbudget_witness_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_witness([-1, -2], [[1, 2]], [(1, 3), (2, 5)], 3)
        with self.assertRaises(ValueError):
            verify_witness([-1, 2], [[1, 2]], [(1, 3), (2, 5)], 3)
        with self.assertRaises(ValueError):
            verify_witness([1, -1], [[1]], [(1, 3)], 3)

    def test_unsupported_weighted_clause_does_not_change_meaning(self):
        formula = WCNF()
        formula.append([-1, -2], weight=3)
        with self.assertRaises(ValueError):
            weighted_costs(formula)

    def test_known_witness_extension_is_separate_and_hash_bound(self):
        formula = WCNF()
        formula.append([1, 2])
        formula.append([-1], weight=3)
        formula.append([-2], weight=5)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wcnf = root / 'model.wcnf'
            formula.to_file(str(wcnf))
            witness = root / 'known.json'
            witness.write_text('[1,-2]\n')
            report_path = root / 'report.json'
            initial = run(wcnf, [3, 2], root / 'private', report_path, timeout=5)
            extended = append_witness(wcnf, 3, root / 'private', report_path, witness, timeout=5)
            self.assertEqual(extended['queries'], initial['queries'])
            check = extended['known_witness_extension']
            self.assertEqual(check['status'], 'sat')
            self.assertEqual(check['verified_weighted_byte_cost'], 3)
            self.assertIn('not unassisted', check['scope'])
            self.assertTrue((root / 'private' / check['witness_private_file']).exists())
            wcnf.write_text(wcnf.read_text() + 'c changed\n')
            with self.assertRaisesRegex(ValueError, 'WCNF changed'):
                append_witness(wcnf, 3, root / 'private', report_path, witness)


if __name__ == '__main__':
    unittest.main(verbosity=2)
