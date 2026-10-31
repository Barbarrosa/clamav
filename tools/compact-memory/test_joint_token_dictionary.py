#!/usr/bin/env python3
"""Exact small-instance oracle and format rejection tests for the offline probe.

SPDX-License-Identifier: GPL-2.0-only
The oracle never calls the implementation's parser or fixed-dictionary evaluator.
"""
import random
import struct
import tempfile
import unittest
from pathlib import Path

from joint_token_dictionary import Problem, decode_image, read_token_store


def minimum_codes(row, dictionary):
    """Shortest literal/fragment path, computed independently from the SAT model."""
    distances = [len(row) + 1] * (len(row) + 1)
    distances[0] = 0
    for start in range(len(row)):
        distances[start + 1] = min(distances[start + 1], distances[start] + 1)
        for fragment in dictionary:
            if row.startswith(fragment, start):
                end = start + len(fragment)
                distances[end] = min(distances[end], distances[start] + 1)
    return distances[-1]


def exhaustive_cost(rows, candidates, max_decode_steps=None):
    """Enumerate all shared dictionaries and evaluate every row by independent DP."""
    optimum = None
    for mask in range(1 << len(candidates)):
        dictionary = [fragment for i, fragment in enumerate(candidates) if mask >> i & 1]
        cost = sum(len(fragment) + 4 for fragment in dictionary)
        for row in rows:
            if max_decode_steps is not None and len(row) > max_decode_steps:
                break
            choices = [len(row)]  # raw decode still performs len(row) byte work
            count = minimum_codes(row, dictionary)
            if max_decode_steps is None or len(row) + count <= max_decode_steps:
                choices.append(2 * count)
            cost += min(choices)
        else:
            optimum = cost if optimum is None else min(optimum, cost)
    return optimum


class JointDictionaryTests(unittest.TestCase):
    def assert_optimal(self, rows, candidates, widths=None, max_decode_steps=None):
        problem = Problem(rows, widths=widths, candidates=candidates,
                          max_decode_steps=max_decode_steps)
        layout = problem.solve()
        self.assertEqual(layout.objective_bytes,
                         exhaustive_cost(rows, candidates, max_decode_steps))
        image = layout.to_bytes()
        self.assertEqual(layout.total_bytes, len(image))
        recovered, recovered_widths = decode_image(image, max_decode_steps=max_decode_steps)
        self.assertEqual(list(recovered), rows)
        self.assertEqual(list(recovered_widths), widths or [False] * len(rows))
        return problem, layout

    def test_shared_setup_cost_paid_once(self):
        rows = [b'abcdefgh'] * 4
        _, layout = self.assert_optimal(rows, [b'abcdefgh'])
        self.assertEqual(layout.objective_bytes, 12 + 4 * 2)
        self.assertEqual(tuple(layout.dictionary), (b'abcdefgh',))

    def test_overlapping_occurrences_cannot_both_cover_a_byte(self):
        rows = [b'abababa', b'bababab', b'abababab', b'babababa']
        self.assert_optimal(rows, [b'ababa', b'babab', b'aba', b'bab'])

    def test_joint_selection_beats_positive_gain_greedy(self):
        rows = [b'cbccbccbc', b'cbccbcdaabdba', b'cbcdaabdbacbc',
                b'aabdbaaabdbacbc', b'cbcaabdbacbcd']
        candidates = [b'aabdba', b'aabdbacbc', b'aabdbacb', b'abdba',
                      b'abdbacbc', b'bdbacbc', b'cbc']
        problem, optimum = self.assert_optimal(rows, candidates)
        self.assertEqual(optimum.objective_bytes, 53)
        self.assertEqual(problem.greedy().objective_bytes, 63)

    def test_individually_unprofitable_dictionary_stays_empty(self):
        rows = [b'01234567', b'ABCDEFGH', b'uvwxyz']
        _, layout = self.assert_optimal(rows, [b'01234567', b'ABCDEFGH', b'uvwxyz'])
        self.assertFalse(layout.dictionary)
        self.assertEqual(layout.objective_bytes, sum(map(len, rows)))

    def test_empty_sequences_and_no_dictionary(self):
        self.assert_optimal([b'', b'a', b''], [])

    def test_tagged_tokens_and_width_survive(self):
        tagged = struct.pack('<6H', 0x0001, 0x0102, 0x8000, 0xFFFF, 0x0041, 0x1000)
        rows = [tagged] * 4 + [b'ordinary-byte-row']
        self.assert_optimal(rows, [tagged, tagged[:6]], [True] * 4 + [False])

    def test_decode_bound_includes_output_and_dispatch(self):
        rows = [b'abcdefgh'] * 4
        # A dictionary parse costs 8 output bytes + one dispatch, so D=8 permits raw only.
        _, raw = self.assert_optimal(rows, [b'abcdefgh'], max_decode_steps=8)
        self.assertEqual(raw.objective_bytes, 32)
        _, packed = self.assert_optimal(rows, [b'abcdefgh'], max_decode_steps=9)
        self.assertEqual(packed.objective_bytes, 20)
        with self.assertRaises(ValueError):
            decode_image(packed.to_bytes(), max_decode_steps=8)

    def test_impossible_raw_bound_is_rejected(self):
        with self.assertRaises(ValueError):
            Problem([b'abcdefgh'], candidates=[b'abcdefgh'], max_decode_steps=7).solve()

    def test_random_tiny_instances_against_exhaustive_oracle(self):
        rng = random.Random(378)
        for case in range(30):
            rows = [bytes(rng.choice(b'abc') for _ in range(rng.randrange(3, 15)))
                    for _ in range(rng.randrange(1, 5))]
            pool = sorted({row[i:i + length] for row in rows for length in (3, 4, 5)
                           for i in range(max(0, len(row) - length + 1))})
            rng.shuffle(pool)
            candidates = pool[:rng.randrange(0, min(5, len(pool)) + 1)]
            with self.subTest(case=case, rows=len(rows), candidates=len(candidates)):
                self.assert_optimal(rows, candidates)

    def test_bad_magic_and_every_truncated_prefix_are_rejected(self):
        _, layout = self.assert_optimal([b'abcdefgh'] * 5 + [b'xy'], [b'abcdefgh'])
        image = layout.to_bytes()
        for length in range(len(image)):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    decode_image(image[:length])
        corrupt = bytearray(image)
        corrupt[0] ^= 1
        with self.assertRaises(ValueError):
            decode_image(bytes(corrupt))
        with self.assertRaises(ValueError):
            decode_image(image + b'\x00')

    def test_invalid_offsets_codes_lengths_and_flags_are_rejected(self):
        # Force a one-entry compressed dictionary without depending on solver tie order.
        problem = Problem([b'abcdefgh'] * 5, candidates=[b'abcdefgh'])
        layout = problem.fixed_dictionary([0])
        image = layout.to_bytes()
        nrows, ndict = len(layout.rows), len(layout.dictionary)
        dindex_start = 24
        rindex_start = dindex_start + 4 * (ndict + 1) + sum(map(len, layout.dictionary))
        lengths_start = rindex_start + 4 * (nrows + 1)
        flags_start = lengths_start + 4 * nrows
        payload_start = flags_start + nrows
        mutations = []
        for position, value in [(dindex_start, 1), (dindex_start + 4, 0),
                                (rindex_start, 1), (rindex_start + 4, 0xFFFFFFFF),
                                (lengths_start, 0xFFFFFFFF), (20, 1)]:
            corrupt = bytearray(image)
            struct.pack_into('<I', corrupt, position, value)
            mutations.append(corrupt)
        corrupt = bytearray(image)
        corrupt[flags_start] = 0x80
        mutations.append(corrupt)
        corrupt = bytearray(image)
        struct.pack_into('<H', corrupt, payload_start, 256 + ndict)
        mutations.append(corrupt)
        for index, corrupt in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(ValueError):
                    decode_image(bytes(corrupt))

    def test_existing_flagged_export_reader_preserves_width(self):
        with tempfile.TemporaryDirectory() as directory:
            data, index = Path(directory) / 'data', Path(directory) / 'index'
            rows = [b'ab', struct.pack('<2H', 0xFFFF, 0x0100), b'']
            data.write_bytes(b''.join(rows))
            index.write_bytes(struct.pack('<4I', 0, 0x80000002, 6, 6))
            recovered, widths = read_token_store(data, index)
            self.assertEqual(list(recovered), rows)
            self.assertEqual(list(widths), [False, True, False])
            for values in [(1, 2, 6, 6), (0, 5, 4, 6), (0, 0x80000003, 6, 6),
                           (0, 2, 6, 5)]:
                index.write_bytes(struct.pack('<4I', *values))
                with self.subTest(offsets=values):
                    with self.assertRaises(ValueError):
                        read_token_store(data, index)


if __name__ == '__main__':
    unittest.main(verbosity=2)
