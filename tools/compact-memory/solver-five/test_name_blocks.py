#!/usr/bin/env python3
"""Meaningful bounded-model and independent decoder tests.

SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
import random
import struct
import unittest
from unittest.mock import patch

from name_blocks import (Block, DESCRIPTOR, HEADER, Layout, NameProblem,
                         StableNames, decode_block, decode_image, encode_block,
                         independent_optimum, public_names)


def exhaustive_partition_cost(names, span, work):
    """Enumerate all partitions/mode choices on tiny inputs, without SAT/DP."""
    if not names:
        return 0
    optimum = None
    for breaks in itertools.product([False, True], repeat=len(names) - 1):
        boundaries = [0] + [i + 1 for i, flag in enumerate(breaks) if flag] + [len(names)]
        if any(right - left > span for left, right in zip(boundaries, boundaries[1:])):
            continue
        for modes in itertools.product([False, True], repeat=len(boundaries) - 1):
            cost, feasible = 0, True
            for left, right, mode in zip(boundaries, boundaries[1:], modes):
                group = names[left:right]
                expanded = sum(len(name) + 1 for name in group)
                if expanded + (len(group) if mode else 0) > work:
                    feasible = False
                    break
                payload = expanded
                if mode:
                    payload, previous = 0, b''
                    for name in group:
                        shared = 0
                        while shared < min(len(name), len(previous)) and name[shared] == previous[shared]:
                            shared += 1
                        payload += 4 + len(name) - shared
                        previous = name
                cost += 20 + payload
            if feasible:
                optimum = cost if optimum is None else min(optimum, cost)
    return optimum


class NameBlockTests(unittest.TestCase):
    def check_optimum(self, names, span=4, work=512):
        problem = NameProblem(names, span, work)
        layout, _ = problem.solve()
        self.assertEqual(layout.variable_bytes, independent_optimum(names, span, work))
        self.assertEqual(layout.variable_bytes, exhaustive_partition_cost(names, span, work))
        self.assertEqual(decode_image(layout.image(), work), names)
        self.assertEqual(len(layout.image()), layout.total_bytes)
        return problem, layout

    def test_random_small_instances_against_exhaustive_oracle(self):
        rng = random.Random(378)
        for _ in range(30):
            names = [bytes(rng.choices(b'abc', k=rng.randrange(0, 7))) for _ in range(rng.randrange(1, 6))]
            self.check_optimum(names, span=rng.randrange(1, 5), work=32)

    def test_adaptive_boundaries_beat_fixed_blocks(self):
        names = [bytes([65 + group]) * 24 + ('%03d' % i).encode()
                 for group, count in enumerate([3, 4, 6]) for i in range(count)]
        problem = NameProblem(names, max_span=8)
        layout, _ = problem.solve()
        self.assertLess(layout.total_bytes, problem.fixed(8).total_bytes)
        self.assertEqual(decode_image(layout.image()), names)

    def test_empty_duplicate_and_nonascii_names_preserve_order(self):
        self.check_optimum([b'', b'\xffname', b'\xffname', b'', b'last'])
        problem, empty = self.check_optimum([])
        self.assertEqual(empty.total_bytes, HEADER.size)

    def test_raw_fallback_and_stable_raw_views_add_no_arena(self):
        names = [b'a', b'xyz', b'!']
        _, layout = self.check_optimum(names)
        self.assertTrue(all(not block.front for block in layout.blocks))
        materialized = StableNames(layout.image())
        for row, name in enumerate(names):
            self.assertEqual(bytes(materialized.get(row)), name)
        self.assertEqual(materialized.stable_payload_bytes, len(layout.image()))

    def test_decoded_views_survive_other_block_materialization(self):
        names = [b'a' * 32 + bytes([65 + i]) for i in range(8)]
        problem = NameProblem(names, max_span=4)
        layout, _ = problem.solve()
        holder = StableNames(layout.image())
        borrowed = holder.get(0)
        self.assertTrue(any(block.front for block in layout.blocks))
        for row in reversed(range(len(names))):
            self.assertEqual(bytes(holder.get(row)), names[row])
        self.assertEqual(bytes(borrowed), names[0])
        expected = len(layout.image()) + sum(b.decoded for b in layout.blocks if b.front)
        self.assertEqual(holder.stable_payload_bytes, expected)

    def test_stable_backing_is_immutable_even_with_mutable_input(self):
        names = [b'abc']
        _, layout = self.check_optimum(names)
        mutable = bytearray(layout.image())
        holder = StableNames(mutable)
        borrowed = holder.get(0)
        mutable[-2] ^= 1
        self.assertEqual(bytes(borrowed), names[0])

    def test_work_bound_applies_to_raw_and_compressed(self):
        with self.assertRaises(ValueError):
            NameProblem([b'abcd'], max_work=4).solve()
        raw = encode_block([b'abcd'], 0, 1, False)
        front = encode_block([b'abcd'], 0, 1, True)
        self.assertEqual(raw.work, 5)
        self.assertEqual(front.work, 6)
        with self.assertRaises(ValueError):
            decode_image(Layout((b'abcd',), (front,)).image(), max_work=5)
        self.assertEqual(decode_image(Layout((b'abcd',), (raw,)).image(), max_work=5), [b'abcd'])

    def test_fixed_layout_cannot_bypass_span_bound(self):
        problem = NameProblem([b'a', b'b', b'c'], max_span=2)
        with self.assertRaises(ValueError):
            problem.fixed(3)

    def test_truncation_and_trailing_bytes_rejected(self):
        names = [b'long-prefix-' + b'A', b'long-prefix-' + b'B']
        image = Layout(tuple(names), (encode_block(names, 0, 2, True),)).image()
        for stop in range(len(image)):
            with self.assertRaises(ValueError):
                decode_image(image[:stop])
        with self.assertRaises(ValueError):
            decode_image(image + b'extra')

    def test_corrupt_reference_descriptor_and_prefix_rejected(self):
        names = [b'long-prefix-A', b'long-prefix-B']
        original = Layout(tuple(names), (encode_block(names, 0, 2, True),)).image()
        variants = []
        bad = bytearray(original); struct.pack_into('<I', bad, HEADER.size, 1); variants.append(bad)
        descriptor = HEADER.size + len(names) * 4
        bad = bytearray(original); struct.pack_into('<H', bad, descriptor + 6, 2); variants.append(bad)
        bad = bytearray(original); struct.pack_into('<I', bad, descriptor + 8, 1); variants.append(bad)
        bad = bytearray(original); struct.pack_into('<I', bad, descriptor + 16, 1); variants.append(bad)
        payload = descriptor + DESCRIPTOR.size
        bad = bytearray(original); struct.pack_into('<H', bad, payload, 100); variants.append(bad)
        for bad in variants:
            with self.assertRaises(ValueError):
                decode_image(bad)

    def test_forged_short_decode_budget_rejected_before_suffix_copy(self):
        # One well-framed coded name has a large suffix but lies about its
        # decoded length. A constructor trap proves the check precedes copying.
        payload = struct.pack('<HH', 0, 4096) + b'A' * 4096
        descriptor = (0, 1, True, 0, len(payload), 1)
        with patch('name_blocks.bytes', side_effect=AssertionError('suffix copied'), create=True):
            with self.assertRaisesRegex(ValueError, 'remaining decoded budget'):
                decode_block(memoryview(payload), descriptor, max_work=2)

    def test_cumulative_budget_rejects_later_names_before_copy(self):
        payload = struct.pack('<HH', 0, 1) + b'A' + struct.pack('<HH', 1, 4096) + b'B' * 4096
        descriptor = (0, 2, True, 0, len(payload), 3)
        calls = []
        original_bytes = bytes
        def guarded_copy(value):
            calls.append(len(value))
            self.assertLessEqual(len(value), 1, 'oversize suffix copied')
            return original_bytes(value)
        with patch('name_blocks.bytes', side_effect=guarded_copy, create=True):
            with self.assertRaisesRegex(ValueError, 'remaining decoded budget'):
                decode_block(memoryview(payload), descriptor)
        self.assertEqual(calls, [1])

    def test_forged_short_raw_budget_rejected_before_copy(self):
        payload = b'A' * 4096 + b'\0'
        descriptor = (0, 1, False, 0, len(payload), 1)
        with patch('name_blocks.bytes', side_effect=AssertionError('raw copied'), create=True):
            with self.assertRaisesRegex(ValueError, 'raw block length mismatch'):
                decode_block(memoryview(payload), descriptor)

    def test_inadmissible_name_and_dimensions_rejected(self):
        with self.assertRaises(ValueError):
            NameProblem([b'has\0nul'])
        with self.assertRaises(ValueError):
            NameProblem([b'test'], max_span=65)

    def test_public_fixture_names_preserve_original_order(self):
        names, sources = public_names()
        self.assertGreater(len(names), 10)
        self.assertTrue(sources)
        problem = NameProblem(names)
        layout, _ = problem.solve()
        self.assertEqual(decode_image(layout.image()), names)


if __name__ == '__main__':
    unittest.main(verbosity=2)
