"""Independent recursive reference checks of the canonical Lean input encoding.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from canonical_input import (CanonicalCNF, canonical_formula, canonical_bit_length,
                             canonical_bits, parse_dimacs, write_packed)


def reference(n, clauses):
    """Literal translation of Lean's definitions, separate from streaming code."""
    def natural(value):
        return [True] * value + [False]

    def framed(bits):
        result = [False]
        for bit in reversed(bits):
            result = [True, bit] + result
        return result

    def listed(encode, values):
        if not values:
            return [False]
        return [True] + framed(encode(values[0])) + listed(encode, values[1:])

    codes = sorted({tuple(sorted({2 * (abs(v) - 1) + int(v > 0) for v in clause}))
                    for clause in clauses})
    return natural(n) + listed(lambda values: listed(natural, list(values)), codes)


class CanonicalInputTests(unittest.TestCase):
    def test_empty_formula_and_empty_clause_are_distinct(self):
        self.assertEqual(list(canonical_bits(0, [])), [False, False])
        self.assertEqual(list(canonical_bits(0, [[]])), reference(0, [[]]))
        self.assertNotEqual(list(canonical_bits(0, [])), list(canonical_bits(0, [[]])))

    def test_all_small_formulas_match_independent_reference_and_length(self):
        atoms = [[], [1], [-1], [2], [-2], [1, -1], [2, -1], [1, -2, 2]]
        for clauses in itertools.chain(([],), itertools.product(atoms, repeat=1),
                                      itertools.product(atoms, repeat=2)):
            with self.subTest(clauses=clauses):
                expected = reference(2, clauses)
                self.assertEqual(list(canonical_bits(2, clauses)), expected)
                self.assertEqual(canonical_bit_length(2, clauses), len(expected))

    def test_literal_code_order_and_finite_sets(self):
        a = canonical_formula(3, [[2, -1, 2], [1, -1], [2, -1]])
        b = canonical_formula(3, [[-1, 1], [-1, 2]])
        self.assertEqual(a.clauses, ((0, 1), (0, 3)))
        self.assertEqual(a.clauses, b.clauses)
        self.assertEqual(list(canonical_bits(a)), list(canonical_bits(b)))
        self.assertEqual(a.source_clause_count, 3)
        self.assertEqual(a.source_literal_occurrences, 7)
        # A tautology is still represented, as in the formal finite-set input.
        self.assertIn((0, 1), a.clauses)

    def test_declared_unused_variables_preserve_the_universe(self):
        a = parse_dimacs('p cnf 1 1\n1 0\n')
        b = parse_dimacs('p cnf 5 1\n1 0\n')
        self.assertEqual(a.clauses, b.clauses)
        self.assertEqual(b.num_variables, 5)
        self.assertEqual(canonical_bit_length(b) - canonical_bit_length(a), 4)
        self.assertEqual(list(canonical_bits(b))[:6], [True] * 5 + [False])

    def test_parser_handles_multiline_and_same_line_clauses(self):
        formula = parse_dimacs('c comment\np cnf 4 3\n1 -2\n3 0 0\nc between\n4 0\n')
        self.assertEqual(formula.num_variables, 4)
        self.assertEqual(formula.source_clause_count, 3)
        self.assertEqual(formula.maximum_clause_width, 3)
        self.assertIn((), formula.clauses)

    def test_width_is_canonical_finite_set_width(self):
        self.assertEqual(parse_dimacs('p cnf 1 1\n1 1 1 1 0\n').maximum_clause_width, 1)
        with self.assertRaisesRegex(ValueError, 'width'):
            parse_dimacs('p cnf 4 1\n1 2 3 4 0\n')

    def test_bad_headers_literals_counts_and_truncation_rejected(self):
        cases = ['', '1 0\n', 'p sat 1 1\n1 0\n', 'p cnf -1 0\n',
                 'p cnf 1 1 extra\n1 0\n', 'p cnf 1 1\np cnf 1 1\n1 0\n',
                 'p cnf 1 1\n2 0\n', 'p cnf 1 0\n1 0\n', 'p cnf 1 1\n',
                 'p cnf 1 1\n1\n', 'p cnf 1 1\nx 0\n', 'p cnf 0 1\n-1 0\n']
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_dimacs(text)

    def test_direct_api_rejects_bad_literal_and_dimensions(self):
        for n, clauses in [(True, []), (-1, []), (1, [[0]]), (1, [[True]]), (1, [[2]])]:
            with self.subTest(n=n, clauses=clauses), self.assertRaises(ValueError):
                canonical_formula(n, clauses)
        for clauses in (((0, 0),), ((2,),), ((1,), (0,)), ((-1,),)):
            with self.subTest(codes=clauses), self.assertRaises(ValueError):
                CanonicalCNF(1, clauses, 2, 4, 3)

    def test_huge_length_is_computed_without_unary_materialization(self):
        n = 10**30
        formula = canonical_formula(n, [[n, -n]])
        self.assertEqual(canonical_bit_length(formula), n + 2 + 4 + 16 * n + 4)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'do-not-create.bits'
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                write_packed(path, formula, max_bits=100)
            self.assertFalse(path.exists())
            path.write_bytes(b'preserved')
            with self.assertRaises(ValueError):
                write_packed(path, formula, max_bits=100)
            self.assertEqual(path.read_bytes(), b'preserved')

    def test_packed_transport_roundtrip_and_zero_padding(self):
        formula = canonical_formula(3, [[1, -2], [-1, 3]])
        expected = reference(3, [[1, -2], [-1, 3]])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.bits'
            report = write_packed(path, formula, max_bits=len(expected))
            unpacked = [bool((byte >> bit) & 1) for byte in path.read_bytes()
                        for bit in range(7, -1, -1)]
            self.assertEqual(unpacked[:len(expected)], expected)
            self.assertFalse(any(unpacked[len(expected):]))
            self.assertEqual(report['logical_bits'], len(expected))
            self.assertEqual(report['transport_bytes'], (len(expected) + 7) // 8)

    def test_cli_length_only_does_not_write_a_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cnf = root / 'input.cnf'
            output = root / 'report.json'
            cnf.write_text('p cnf 1000000000000 1\n1000000000000 0\n')
            run = subprocess.run([sys.executable, str(Path(__file__).with_name('canonical_input.py')),
                                  '--cnf', str(cnf), '--report', str(output)],
                                 check=True, capture_output=True, text=True, timeout=5)
            self.assertIn('length_only', run.stdout)
            self.assertEqual({p.name for p in root.iterdir()}, {'input.cnf', 'report.json'})


if __name__ == '__main__':
    unittest.main()
