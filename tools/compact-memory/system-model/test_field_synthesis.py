"""Independent cost/dependency oracles and complete field-store roundtrips.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
import random
import struct
import unittest
from unittest.mock import patch

import numpy as np
from pysat.solvers import Solver

from field_synthesis import (ALIAS_ADD, ALIAS_XOR, CONST, DESC, FieldProblem,
                             FieldStore, HEADER, NIL, ROW_AFFINE, SPARSE,
                             STORE_BASE_NULL, STORE_XOR, pack_values,
                             packed_get, packed_size, synthesize, unpack_values)
from joint_budget_cnf import budget_cnf


def oracle_depths(programs, rows):
    def depth(i, visiting):
        if i in visiting:
            raise ValueError('cycle')
        c = programs[i]
        if c.op == CONST:
            return 0
        if c.op == ROW_AFFINE:
            return 1 + int(c.count not in (0, 1)) + int(c.arg != 0)
        if c.op in (STORE_XOR, STORE_BASE_NULL):
            reads = max((1 + int((r * c.width) % 64 + c.width > 64)
                         for r in range(rows)), default=0)
            return reads + (int(c.arg != 0) if c.op == STORE_XOR else 2)
        overhead = 13 if c.op == SPARSE else 1 + int(c.arg != 0)
        return depth(c.parent, visiting | {i}) + overhead
    return [depth(i, set()) for i in range(len(programs))]


def oracle_payload(c, rows):
    def packed(n, w):
        return ((n * w + 63) // 64) * 8 + 8 if w else 0
    if c.op in (STORE_XOR, STORE_BASE_NULL):
        return packed(rows, c.width)
    if c.op == SPARSE:
        bitmap = ((rows + 63) // 64) * 8 + 8
        rank = ((((rows + 511) // 512 + 1) * 4 + 7) // 8) * 8
        return bitmap + rank + packed(c.count, c.width)
    return 0


class FieldSynthesisTests(unittest.TestCase):
    def test_all_unsigned_widths_and_word_boundaries(self):
        rng = random.Random(378)
        for width in range(1, 65):
            mask = (1 << width) - 1
            values = np.array([rng.getrandbits(width) for _ in range(137)] + [0, mask], dtype=np.uint64)
            image = pack_values(values, width)
            self.assertEqual(len(image), packed_size(len(values), width))
            np.testing.assert_array_equal(unpack_values(image, width, len(values)), values)
            self.assertEqual([packed_get(image, 0, width, i) for i in range(len(values))],
                             [int(x) for x in values])

    def test_chunk_boundary_pack(self):
        values = np.arange(65539, dtype=np.uint64) * np.uint64(13)
        image = pack_values(values, 21)
        np.testing.assert_array_equal(unpack_values(image, 21, len(values)), values)
        for i in [0, 65535, 65536, 65538]:
            self.assertEqual(packed_get(image, 0, 21, i), int(values[i]))

    def test_scalar_get_reads_second_word_only_when_straddling(self):
        values = np.arange(20, dtype=np.uint64)
        image = pack_values(values, 13)
        original = struct.unpack_from
        for row, expected_reads in [(0, 1), (3, 1), (4, 2), (9, 2), (10, 1)]:
            with patch('field_synthesis.struct.unpack_from', wraps=original) as reads:
                self.assertEqual(packed_get(image, 0, 13, row), int(values[row]))
            self.assertEqual(reads.call_count, expected_reads)
            self.assertTrue(all(call.args[0] == '<Q' for call in reads.call_args_list))
        empty = pack_values(np.zeros(20, dtype=np.uint64), 0)
        with patch('field_synthesis.struct.unpack_from', wraps=original) as reads:
            self.assertEqual(packed_get(empty, 0, 0, 0), 0)
        self.assertEqual(reads.call_count, 0)

    def test_pointer_words_null_and_full_u64_preserved(self):
        pointers = np.array([0, 0x7fff12345000, 0x7fff12346000, 0,
                             0x7fff12345000, 0x7fff12347000] * 16, dtype=np.uint64)
        result = synthesize({'pointer': pointers}, {'pointer': 64}, max_depth=4)
        np.testing.assert_array_equal(result.reconstruct('pointer'), pointers)
        self.assertEqual([result.get('pointer', i) for i in range(len(pointers))],
                         [int(v) for v in pointers])
        maximum = np.array([0, (1 << 64) - 1, (1 << 63), 7, 99], dtype=np.uint64)
        result = synthesize({'values': maximum}, 64, max_depth=4)
        np.testing.assert_array_equal(result.reconstruct('values'), maximum)

    def test_global_alias_selection_has_no_cycles(self):
        values = np.array([9, 2, 11, 5, 7, 3, 10, 1] * 64, dtype=np.uint64)
        columns = {'a': values, 'b': values.copy(), 'c': values.copy()}
        low = synthesize(columns, 16, max_depth=1)
        high = synthesize(columns, 16, max_depth=2)
        self.assertLess(high.total_bytes, low.total_bytes)
        self.assertTrue(any(c.parent != NIL for c in high.selected))
        self.assertLessEqual(max(oracle_depths(high.selected, len(values))), 2)
        for name in columns:
            np.testing.assert_array_equal(high.reconstruct(name), values)

    def test_sampling_never_accepts_false_alias(self):
        rng = np.random.default_rng(380)
        values = rng.integers(0, 4096, 2048, dtype=np.uint64)
        other = values.copy()
        sample = set(np.linspace(0, len(values) - 1, 64, dtype=np.int64))
        changed = next(i for i in range(len(values)) if i not in sample)
        other[changed] ^= np.uint64(1)
        problem = FieldProblem({'a': values, 'b': other}, 16, max_depth=3)
        self.assertFalse(any(c.parent == 0 for c in problem.candidates[1]))
        result = problem.solve()
        np.testing.assert_array_equal(result.reconstruct('b'), other)

    def test_sparse_rank_boundaries_and_depth(self):
        rng = np.random.default_rng(381)
        values = rng.integers(0, 1024, 2055, dtype=np.uint64)
        altered = values.copy()
        positions = [0, 63, 64, 511, 512, 1023, 1024, 2048, 2054]
        altered[positions] = np.uint64(0xfffffff0)
        result = synthesize({'base': values, 'different': altered}, 32, max_depth=16)
        self.assertTrue(any(c.op == SPARSE for c in result.selected))
        for name, expected in [('base', values), ('different', altered)]:
            np.testing.assert_array_equal(result.reconstruct(name), expected)
            self.assertEqual([result.get(name, i) for i in range(len(values))], [int(v) for v in expected])
        self.assertLessEqual(max(result.store.depths.values()), 16)
        with self.assertRaises(ValueError):
            FieldStore(result.image, result.problem.names, max_depth=2)

    def test_sparse_override_can_use_constant_parent(self):
        zero = np.zeros(4096, dtype=np.uint64)
        rare = zero.copy()
        rare[[1, 63, 512, 2047, 4095]] = np.array(
            [0xffff, 0x80000000, 0xffffffff, 0x100000, 0xdeadbeef], dtype=np.uint64)
        result = synthesize({'zero': zero, 'rare': rare}, 32, max_depth=16)
        self.assertEqual(result.selected[1].op, SPARSE)
        self.assertEqual(result.selected[1].parent, 0)
        np.testing.assert_array_equal(result.reconstruct('rare'), rare)
        for row in [0, 1, 63, 64, 512, 513, 2047, 4095]:
            self.assertEqual(result.get('rare', row), int(rare[row]))

    def test_tiny_models_against_independent_program_graph_enumeration(self):
        rng = random.Random(382)
        for _ in range(15):
            a = np.array([rng.randrange(16) for _ in range(6)], dtype=np.uint64)
            b = a ^ np.uint64(rng.randrange(16)) if rng.randrange(2) else np.array([rng.randrange(16) for _ in range(6)], dtype=np.uint64)
            depth = rng.randrange(1, 4)
            problem = FieldProblem({'a': a, 'b': b}, 4, max_depth=depth, allow_sparse=False)
            best = None
            for programs in itertools.product(*problem.candidates):
                try:
                    depths = oracle_depths(programs, len(a))
                except ValueError:
                    continue
                if max(depths, default=0) <= depth:
                    cost = sum(oracle_payload(c, len(a)) for c in programs)
                    best = cost if best is None else min(best, cost)
            result = problem.solve()
            self.assertEqual(result.payload_bytes, best)

    def test_fixed_width_budget_boundary(self):
        values = np.array([3, 1, 7, 2, 6, 0, 4] * 8, dtype=np.uint64)
        result = synthesize({'a': values, 'b': values.copy()}, 8, max_depth=2)
        for budget in [result.payload_bytes - 1, result.payload_bytes]:
            cnf = budget_cnf(result.problem.hard, result.problem.costs, budget)
            self.assertLessEqual(max(map(len, cnf), default=0), 3)
            with Solver(name='m22', bootstrap_with=cnf) as solver:
                self.assertEqual(solver.solve(), budget == result.payload_bytes)

    def test_invalid_images_and_cycle_rejected(self):
        result = synthesize({'a': np.array([2, 5, 1], dtype=np.uint64)}, 8)
        for size in range(len(result.image)):
            with self.assertRaises(ValueError):
                FieldStore(result.image[:size], ['a'])
        with self.assertRaises(ValueError):
            FieldStore(result.image + b'x', ['a'])
        header = HEADER.pack(b'FIELDS1\0', 4, 2)
        c0 = DESC.pack(ALIAS_XOR, 0, 8, 0, 1, 0, 0, 0)
        c1 = DESC.pack(ALIAS_XOR, 0, 8, 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            FieldStore(header + c0 + c1)

    def test_invalid_native_widths_and_empty_family(self):
        with self.assertRaises(ValueError):
            synthesize({'a': np.array([256], dtype=np.uint64)}, 8)
        with self.assertRaises(ValueError):
            synthesize({'a': np.array([-1], dtype=np.int64)}, 8)
        with self.assertRaises(ValueError):
            synthesize({'a': np.array([1]), 'b': np.array([1, 2])}, 8)
        empty = synthesize({'empty': np.array([], dtype=np.uint64)}, 64)
        self.assertEqual(len(empty.reconstruct('empty')), 0)
        self.assertEqual(empty.total_bytes, HEADER.size + DESC.size)

    def test_public_programs_do_not_publish_captured_arguments(self):
        private_pointer = 0x7fff12345678
        result = synthesize({'pointer': np.full(9, private_pointer, dtype=np.uint64)}, 64)
        self.assertEqual(result.programs[0]['argument'], private_pointer)
        self.assertNotIn('argument', result.public_programs[0])
        self.assertEqual(len(result.public_programs[0]['argument_sha256']), 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
