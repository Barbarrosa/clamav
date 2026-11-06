"""Independent tiny oracles for count units, gates and lifecycle budgets.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import json
import unittest
from types import SimpleNamespace

from pysat.solvers import Solver
from search_model import SearchModel, catalog_audit
from field_synthesis import Candidate, STORE_XOR, ALIAS_ADD
from choice_cnf import Formula
from run_search import enumerate_bounded

HERE = Path(__file__).parent


def example(**kwargs):
    raw = Candidate(STORE_XOR, 1, 8, increment=1, payload_bytes=16)
    a = Candidate(ALIAS_ADD, 0, 8, parent=1, increment=1)
    b = Candidate(ALIAS_ADD, 0, 8, parent=0, increment=1)
    problem = SimpleNamespace(names=['a', 'b'], nrows=2, candidates=[[raw, a], [raw, b]])
    catalog = json.loads((HERE / 'catalog.json').read_text())
    contract = json.loads((HERE / 'baseline-contract.json').read_text())
    settings = dict(policy='explore', query_units=16, dependency_depth=2,
                    allow_log_lookup=True, allow_component_regression=True, reader_lines=1)
    settings.update(kwargs)
    return SearchModel([dict(name='tiny', problem=problem, native_bytes=256, identity_objects=2)],
                       catalog, contract, **settings)


def models(problem):
    result = []
    with Solver(name='m22', bootstrap_with=problem.formula.clauses) as solver:
        while solver.solve():
            raw = solver.get_model()
            assignment = {abs(v): v > 0 for v in raw}
            primary = {name: assignment[v] for name, v in problem.formula.primary.items()}
            if problem.formula.extend(primary) != assignment:
                raise AssertionError('auxiliary extension is not canonical')
            result.append(assignment)
            solver.add_clause([-v for v in raw])
            if len(result) > 20:
                raise AssertionError('unexpected assignment multiplicity')
    return result


class SearchTests(unittest.TestCase):
    def test_native_plus_three_acyclic_configurations_have_one_extension_each(self):
        problem = example()
        answers = models(problem)
        self.assertEqual(len(answers), 4)
        signatures = {tuple(a[v] for v in problem.formula.primary.values()) for a in answers}
        self.assertEqual(len(signatures), 4)
        self.assertEqual(sorted(problem.costs(a)['steady_bytes'] for a in answers), [136, 136, 152, 256])

    def test_budgets_count_actual_configurations_at_boundary(self):
        self.assertEqual(len(models(example(budgets={'steady_bytes': 135}))), 0)
        self.assertEqual(len(models(example(budgets={'steady_bytes': 136}))), 2)
        self.assertEqual(len(models(example(budgets={'steady_bytes': 152}))), 3)

    def test_conditioned_queries_and_free_declared_variables(self):
        self.assertEqual(len(models(example(fixed_choices={'catalog/field_provider/native': True}))), 1)
        self.assertEqual(len(models(example(fixed_choices={'catalog/field_provider/native': False}))), 3)
        with self.assertRaises(ValueError):
            example(fixed_choices={'nonexistent': True})
        formula = Formula()
        formula.new_primary('free')
        counted = enumerate_bounded(formula, 4, 2)
        self.assertTrue(counted['complete'])
        self.assertEqual(counted['configurations_counted'], 2)

    def test_feedback_blocks_only_the_complete_measured_configuration(self):
        original = example()
        answers = models(original)
        one = {name: answers[0][v] for name, v in original.formula.primary.items()}
        self.assertEqual(len(models(example(blocked_configurations=[one]))), 3)
        with self.assertRaisesRegex(ValueError, 'every primary'):
            example(blocked_configurations=[{'catalog/field_provider/native': False}])

    def test_default_growth_guard_and_preserve_policy_leave_one_control(self):
        for settings in (dict(allow_log_lookup=False), dict(policy='preserve', allow_component_regression=False)):
            problem = example(**settings)
            answers = models(problem)
            self.assertEqual(len(answers), 1)
            self.assertEqual(problem.public_choices(answers[0])['field_provider'], 'native')
            self.assertFalse(answers[0][problem.any_encoded])

    def test_dependency_and_opcode_budgets_remove_only_matching_choices(self):
        self.assertEqual(len(models(example(allow_component_regression=False))), 2)
        self.assertEqual(len(models(example(dependency_depth=0))), 2)
        self.assertEqual(len(models(example(max_new_opcodes=1))), 2)
        self.assertEqual(len(models(example(max_new_indices=0))), 1)
        self.assertEqual(len(models(example(max_reader_lines=0))), 1)
        self.assertEqual(len(models(example(max_new_formats=0))), 1)
        self.assertEqual(len(models(example(max_decoder_cases=6))), 1)
        self.assertEqual(len(models(example(query_units=7))), 1)
        self.assertEqual(len(models(example(query_units=0))), 0)

    def test_lifetime_counts_do_not_double_count_native_or_hide_conversion(self):
        problem = example(retained_bytes=1000, scan_tracking_bytes=10)
        for assignment in models(problem):
            costs = problem.costs(assignment)
            native = assignment[problem.families[0]['native']]
            provider = costs['steady_bytes'] - 1010
            added = 0 if native else provider
            self.assertEqual(costs['conversion_peak_bytes'], 1010 + 256 + added)
            self.assertEqual(costs['reload_peak_bytes'], 2010 + provider + 256 + added)

    def test_catalog_cannot_reuse_rejected_or_unimplemented_alternatives(self):
        problem = example()
        for assignment in models(problem):
            selected = problem.public_choices(assignment)
            self.assertEqual(selected['logical_descriptors'], 'native')
            self.assertEqual(selected['routing'], 'native_currentdense')
        audit = {x['choice']: x for x in problem.audit}
        self.assertIn('known rejected implementation', audit['cyclic_rank']['strict_qualification_blockers'])
        self.assertIn('implementation missing', audit['exactintern_postorder']['strict_qualification_blockers'])


if __name__ == '__main__':
    unittest.main()
