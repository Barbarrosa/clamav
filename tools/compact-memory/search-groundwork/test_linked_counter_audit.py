"""Independent finite checks of source-derived parameter/size arithmetic.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
import unittest
from canonical_input import canonical_bit_length
from linked_counter_audit import (ceil_log2, schedule, maximal_canonical_input,
                                  fallback_size, cutoff_witness, dispatch_observation)


class ParameterAuditTests(unittest.TestCase):
    def test_integer_ceiling_log_and_natural_division_boundaries(self):
        for n in range(1, 1000):
            result = ceil_log2(n)
            self.assertGreaterEqual(1 << result, n)
            if result:
                self.assertLess(1 << (result - 1), n)
        self.assertEqual(ceil_log2(0), 0)
        self.assertEqual(schedule(1)['schedule'], 0)
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError): schedule(value)

    def test_actual_and_fixture_counts_force_fallback(self):
        for n in (97, 114, 115, 117, 295443):
            self.assertEqual(schedule(n)['schedule'], 0)
            self.assertFalse(dispatch_observation(n)['proved_large_branch_eligible'])
        self.assertEqual(schedule(295443)['lambda'], 19)
        self.assertEqual(schedule(295443)['nu'], 5)

    def test_all_ordinary_ceiling_log_intervals_have_zero_schedule(self):
        for exponent in range(3, 65):
            for n in ((1 << (exponent - 1)) + 1, 1 << exponent):
                self.assertEqual(schedule(n)['schedule'], 0)

    def test_eventual_threshold_witness_and_nonmonotonic_schedule(self):
        self.assertEqual(cutoff_witness()['exact_parameters']['schedule'], 1)
        self.assertEqual(schedule(1 << 521284)['schedule'], 2)
        self.assertEqual(schedule(1 << 524289)['schedule'], 1)
        self.assertEqual(schedule(1 << 640000)['schedule'], 2)

    def test_finite_input_bound_matches_all_clause_universes(self):
        for n in range(4):
            literals = [v for i in range(1, n + 1) for v in (-i, i)]
            clauses = [list(combination) for size in range(len(literals) + 1)
                       for combination in itertools.combinations(literals, size)]
            # The fallback ranges over all CNFs, not just width-three formulas.
            from canonical_input import canonical_formula
            formula = canonical_formula(n, clauses, maximum_width=max(3, 2 * n))
            self.assertEqual(canonical_bit_length(formula), maximal_canonical_input(n))

    def test_literal_state_cardinality_and_large_exponents_are_symbolic(self):
        for maximum in range(12):
            self.assertEqual(1 + sum(2 ** length for length in range(maximum + 1)), 2 ** (maximum + 1))
        self.assertEqual(fallback_size(1)['scanner_state_count_log2'], 60)
        self.assertEqual(fallback_size(2)['scanner_state_count_log2'], 517)
        self.assertEqual(maximal_canonical_input(20), 1895558046285846)


if __name__ == '__main__':
    unittest.main()
