#!/usr/bin/env python3
"""Exhaustive primary-assignment checks for the offline weighted CNF exporter.

Requires python-sat, only for these tests; the exporter has no dependencies.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
import random
import unittest

from pysat.solvers import Solver

from joint_budget_cnf import budget_cnf


class BudgetCNFTests(unittest.TestCase):
    def check_instance(self, hard, costs, budget, count):
        saved_hard = [list(clause) for clause in hard]
        saved_costs = list(costs)
        # Declare the full test primary universe, including variables not
        # otherwise used in this random instance, before allocating auxiliaries.
        clauses = budget_cnf(hard, costs + [(count, 0)], budget)
        self.assertTrue(all(len(clause) <= 3 for clause in clauses))
        self.assertTrue(all(type(v) is int and v != 0 for c in clauses for v in c))
        self.assertEqual(hard, saved_hard)
        self.assertEqual(costs, saved_costs)
        with Solver(bootstrap_with=clauses) as solver:
            for bits in itertools.product((False, True), repeat=count):
                expected = all(any(bits[abs(v)-1] == (v > 0) for v in clause)
                               for clause in hard)
                expected &= sum(weight for variable, weight in costs
                                if bits[variable-1]) <= budget
                assumptions = [i if enabled else -i
                               for i, enabled in enumerate(bits, 1)]
                self.assertEqual(solver.solve(assumptions=assumptions), expected,
                                 (hard, costs, budget, bits, clauses))

    def test_random_tiny_budgets(self):
        rng = random.Random(20261031)
        for _ in range(120):
            count = rng.randint(1, 6)
            costs = [(rng.randint(1, count), rng.randint(0, 19))
                     for _ in range(rng.randint(0, count * 2))]
            hard = [[rng.choice((-1, 1)) * rng.randint(1, count)
                     for _ in range(rng.randint(0, 8))]
                    for _ in range(rng.randint(0, 3))]
            for budget in (-1, 0, rng.randint(1, 35), sum(w for _, w in costs)):
                self.check_instance(hard, costs, budget, count)

    def test_boundaries_and_large_weights(self):
        for costs in ([], [(1, 0)], [(1, 3), (1, 4), (2, 2)],
                      [(1, 2**150), (2, 2**151), (3, 2**152)]):
            total = sum(w for _, w in costs)
            for budget in (-1, 0, 1, total // 2, total - 1, total, total + 1):
                self.check_instance([], costs, budget, 3)

    def test_long_hard_clauses_and_gapped_primary_ids(self):
        self.check_instance([[1, -2, 3, -4, 5, -6]], [(6, 0)], 0, 6)
        self.check_instance([[1, 1, -1, 3, 5, -6], [-3]], [(6, 0)], 0, 6)
        # Variable 20 must remain a primary even though it appears only in a
        # zero-weight cost; all splitting auxiliaries have IDs strictly above it.
        clauses = budget_cnf([[1, 2, 3, 4, 5]], [(20, 0)], 0)
        self.assertTrue(all(v <= 5 or v > 20 for c in clauses for v in map(abs, c)))

    def test_invalid_inputs(self):
        for hard, costs, budget in (([[0]], [], 0), ([[True]], [], 0),
                                    ([], [(0, 1)], 0), ([], [(-1, 1)], 0),
                                    ([], [(1, -1)], 0), ([], [(True, 1)], 0),
                                    ([], [(1, 1.5)], 0), ([], [], 1.0)):
            with self.assertRaises(ValueError):
                budget_cnf(hard, costs, budget)


if __name__ == '__main__':
    unittest.main(verbosity=2)
