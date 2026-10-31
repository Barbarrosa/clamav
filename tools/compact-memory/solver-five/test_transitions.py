#!/usr/bin/env python3
"""Independent row-choice oracle and exact transition/format checks.
SPDX-License-Identifier: GPL-2.0-only
"""
import itertools
import random
import struct
import unittest

from transitions import HEADER, View, byte_ac, encode, optimize, serialized_cost


def exhaustive(rows):
    """Enumerate row choices; charge actual distinct 16-entry blocks directly."""
    optimum = None
    for flags in itertools.product((False, True), repeat=len(rows)):
        pool = {tuple(row[pos:pos + 16]) for row, shared in zip(rows, flags) if shared
                for pos in range(0, 256, 16)}
        cost = HEADER.size + 4 * (len(rows) + 1) + len(rows) + 64 * len(pool)
        cost += sum(32 if shared else 1024 for shared in flags)
        optimum = cost if optimum is None else min(optimum, cost)
    return optimum


class TransitionTests(unittest.TestCase):
    def test_literal_automaton_against_direct_substring_matching(self):
        patterns = [b'ab', b'b', b'ab', b'aba', b'bc']
        table, outputs = byte_ac(patterns)
        text = b'ababcbaba'
        state = 0
        for i, byte in enumerate(text):
            state = table[state][byte]
            self.assertEqual(sorted(outputs[state]),
                             [j for j, pattern in enumerate(patterns) if text[:i + 1].endswith(pattern)])
        state = table[table[0][ord('a')]][ord('b')]
        self.assertEqual(outputs[state], [0, 2, 1])

    def test_global_block_setup_and_dense_fallback_both_matter(self):
        rows = [list(range(256)), list(range(256)), list(range(256, 512))]
        chosen, cost, _ = optimize(rows)
        self.assertEqual(chosen, {0, 1})
        self.assertEqual(cost, exhaustive(rows))
        self.assertLess(cost, serialized_cost(rows, set(range(3))))
        self.assertLess(cost, serialized_cost(rows, set()))
        self.assertEqual(View(encode(rows, chosen, 512)).decode(), rows)

    def test_random_models_against_independent_exhaustive_oracle(self):
        rng = random.Random(378)
        for _ in range(16):
            blocks = [tuple(rng.randrange(256) for _ in range(16)) for _ in range(20)]
            rows = [sum((list(rng.choice(blocks)) for _ in range(16)), []) for _ in range(5)]
            if rng.randrange(2):
                rows[-1] = rows[0].copy()
            chosen, cost, _ = optimize(rows)
            self.assertEqual(cost, exhaustive(rows))
            self.assertEqual(View(encode(rows, chosen, 256)).decode(), rows)

    def test_all_transitions_empty_table_and_independent_profiles(self):
        rows = [[0] * 256, [1] * 256]
        for chosen in [set(), {0}, {0, 1}]:
            image = encode(rows, chosen, 2)
            view = View(image)
            self.assertEqual(view.decode(), rows)
            self.assertEqual(len(image), serialized_cost(rows, chosen))
            for row in range(2):
                for byte in range(256):
                    self.assertEqual(view.lookup(row, byte), rows[row][byte])
        self.assertEqual(View(encode([], set(), 1)).decode(), [])

    def test_malformed_images_rejected(self):
        image = encode([[0] * 256], {0}, 1)
        for end in range(len(image)):
            with self.assertRaises(ValueError):
                View(image[:end])
        with self.assertRaises(ValueError):
            View(image + b'extra')
        for position, value in [(0, ord('x')), (20 + 64 + 8, 2)]:
            broken = bytearray(image)
            broken[position] = value
            with self.assertRaises(ValueError):
                View(broken)
        # The first payload code must refer to one of the stored microblocks.
        broken = bytearray(image)
        struct.pack_into('<H', broken, 20 + 64 + 8 + 1, 1)
        with self.assertRaises(ValueError):
            View(broken)
        # Dictionary destinations have the independent destination-state bound.
        broken = bytearray(image)
        struct.pack_into('<I', broken, 20, 1)
        with self.assertRaises(ValueError):
            View(broken)
        broken = bytearray(encode([[0] * 256], set(), 1))
        struct.pack_into('<I', broken, 20 + 8 + 1, 1)
        with self.assertRaises(ValueError):
            View(broken)

    def test_inputs_and_lookup_bounds_rejected(self):
        for rows in [[[0]], [[-1] * 256], [[1 << 32] * 256]]:
            with self.assertRaises(ValueError):
                optimize(rows)
        view = View(encode([[0] * 256], set(), 1))
        for row, byte in [(-1, 0), (1, 0), (0, -1), (0, 256)]:
            with self.assertRaises(ValueError):
                view.lookup(row, byte)
        with self.assertRaises(ValueError):
            byte_ac([b''])
        for bound in [0, -1, True, 1 << 32]:
            with self.assertRaises(ValueError):
                encode([[0] * 256], set(), bound)


if __name__ == '__main__':
    unittest.main(verbosity=2)
