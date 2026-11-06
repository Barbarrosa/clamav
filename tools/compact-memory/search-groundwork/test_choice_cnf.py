"""Independent truth-table checks of count-faithful choice constraints.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
import json
from pathlib import Path
import tempfile
import unittest

from choice_cnf import Formula


def assignments(variables):
    for values in itertools.product((False, True), repeat=len(variables)):
        yield dict(zip(variables, values))


def satisfied(clauses, values):
    return all(any(values[abs(literal)] == (literal > 0) for literal in clause)
               for clause in clauses)


class ChoiceCNFTests(unittest.TestCase):
    def assert_unique_extensions(self, formula, predicate):
        primary = formula.primary
        auxiliaries = formula.mapping()['auxiliary']
        self.assertLessEqual(len(auxiliaries), 17, 'exhaustive test was accidentally made too large')
        self.assertEqual(set(primary.values()) | set(auxiliaries), set(range(1, formula.nv + 1)))
        self.assertTrue(all(len(clause) <= 3 for clause in formula.clauses))
        for named in assignments(list(primary)):
            fixed = {primary[name]: value for name, value in named.items()}
            witnesses = [fixed | helper for helper in assignments(auxiliaries)
                         if satisfied(formula.clauses, fixed | helper)]
            expected = bool(predicate(named))
            self.assertEqual(len(witnesses), int(expected), named)
            extension = formula.extend(named)
            self.assertEqual(extension is not None, expected, named)
            if expected:
                self.assertEqual(extension, witnesses[0], named)

    def test_full_equivalence_gates_including_unconstrained_outputs(self):
        formula = Formula()
        a, b = formula.new_primary('a'), formula.new_primary('b')
        formula.and_(a, b)
        formula.xor(a, b)
        formula.or_(a, b)
        self.assert_unique_extensions(formula, lambda values: True)

    def test_gate_complement_constants_and_caching_do_not_free_helpers(self):
        formula = Formula()
        a, b = formula.new_primary('a'), formula.new_primary('b')
        self.assertEqual(formula.and_(a, b), formula.and_(b, a))
        self.assertEqual(formula.xor(a, b), formula.xor(b, a))
        self.assertIs(formula.and_(a, -a), False)
        self.assertIs(formula.or_(a, -a), True)
        self.assertIs(formula.xor(a, -a), True)
        self.assertEqual(formula.and_(True, a), a)
        self.assertEqual(formula.xor(True, a), -a)
        formula.force(formula.xor(a, b))
        self.assert_unique_extensions(formula, lambda values: values['a'] != values['b'])

    def test_long_clause_has_one_extension_not_a_split_clause_multiplicity(self):
        formula = Formula()
        variables = [formula.new_primary(str(i)) for i in range(5)]
        formula.clause(*variables)
        self.assert_unique_extensions(formula, lambda values: any(values.values()))

    def test_exactly_one_prefixes_are_uniquely_defined(self):
        formula = Formula()
        variables = [formula.new_primary(str(i)) for i in range(4)]
        formula.exactly_one(variables)
        self.assert_unique_extensions(formula, lambda values: sum(values.values()) == 1)
        empty = Formula()
        empty.exactly_one([])
        self.assert_unique_extensions(empty, lambda values: False)
        complementary = Formula()
        x = complementary.new_primary('x')
        complementary.exactly_one([x, -x])
        self.assert_unique_extensions(complementary, lambda values: True)

    def test_requirements_conflicts_and_conditional_budget(self):
        formula = Formula()
        mode = formula.new_primary('mode')
        x, y = formula.new_primary('x'), formula.new_primary('y')
        formula.imply(x, -y)
        formula.at_most_weighted([(x, 2), (y, 3)], 2, condition=mode)
        self.assert_unique_extensions(formula, lambda a:
            not (a['x'] and a['y']) and (not a['mode'] or 2*a['x'] + 3*a['y'] <= 2))

    def test_binary_adder_all_budgets_have_unique_extensions(self):
        for limit in range(-1, 7):
            with self.subTest(limit=limit):
                formula = Formula()
                a, b, c = [formula.new_primary(name) for name in ('a', 'b', 'c')]
                formula.at_most_weighted([(a, 1), (b, 2), (c, 3)], limit)
                self.assert_unique_extensions(formula, lambda values:
                    values['a'] + 2*values['b'] + 3*values['c'] <= limit)

    def test_signed_constants_repeated_terms_and_huge_weights(self):
        formula = Formula()
        x, y = formula.new_primary('x'), formula.new_primary('y')
        formula.at_most_weighted([(True, 2), (False, 99), (x, 2), (x, 1),
                                 (-x, 2), (y, 10**100)], 5)
        self.assert_unique_extensions(formula, lambda a: 2 + 3*a['x'] + 2*(not a['x']) +
                                     10**100*a['y'] <= 5)
        self.assertLess(formula.nv, 10)

    def test_multiple_budgets_and_interleaved_primary_declarations(self):
        formula = Formula()
        x, y = formula.new_primary('x'), formula.new_primary('y')
        formula.at_most_weighted([(x, 2), (y, 3)], 4)
        z = formula.new_primary('z')
        formula.at_most_weighted([(y, 1), (z, 2)], 2)
        self.assert_unique_extensions(formula, lambda a:
            2*a['x'] + 3*a['y'] <= 4 and a['y'] + 2*a['z'] <= 2)

    def test_pure_weighted_predicate_can_be_reused_conditionally(self):
        formula = Formula()
        x, y, permitted = [formula.new_primary(name) for name in ('x', 'y', 'permitted')]
        predicate = formula.weighted_le([(x, 1), (y, 2)], 1)
        formula.equivalent(permitted, predicate)
        self.assert_unique_extensions(formula, lambda a: a['permitted'] == (a['x'] + 2*a['y'] <= 1))

    def test_invalid_literals_weights_names_and_partial_evaluation_rejected(self):
        formula = Formula()
        x = formula.new_primary('x')
        for name in ('', 'x', 3):
            with self.subTest(name=name), self.assertRaises(ValueError):formula.new_primary(name)
        for literal in (0, 2, -2, 1.0, '1', None):
            with self.subTest(literal=literal), self.assertRaises(ValueError):formula.force(literal)
        for weight in (-1, True, 1.5):
            with self.subTest(weight=weight), self.assertRaises(ValueError):
                formula.at_most_weighted([(x, weight)], 1)
        with self.assertRaises(ValueError):formula.at_most_weighted([(x, 1)], True)
        with self.assertRaises(ValueError):formula.at_most_weighted([(x,)], 1)
        for partial in ({}, {'x': 1}, {'x': True, 'extra': False}, None):
            with self.subTest(partial=partial), self.assertRaises(ValueError):formula.extend(partial)

    def test_serialization_mapping_and_hash_are_deterministic_and_immutable(self):
        def build():
            f = Formula()
            a, b = f.new_primary('a'), f.new_primary('b')
            f.exactly_one([a, b])
            f.at_most_weighted([(a, 2), (b, 3)], 2)
            return f
        left, right = build(), build()
        self.assertEqual(left.dimacs(), right.dimacs())
        self.assertEqual(left.mapping(), right.mapping())
        self.assertEqual(left.digest(), right.digest())
        self.assertEqual(json.loads(json.dumps(left.mapping())), left.mapping())
        left.clauses.append([999])
        left.primary['rogue'] = 999
        self.assertEqual(left.dimacs(), right.dimacs())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'model.cnf'
            left.to_file(path)
            self.assertEqual(path.read_text(), left.dimacs())


if __name__ == '__main__':
    unittest.main(verbosity=2)
