#!/usr/bin/env python3
"""Independent scalar-cost oracle, roundtrip and malformed-image tests.
SPDX-License-Identifier: GPL-2.0-only
"""
from functools import lru_cache
import random
import struct
import unittest

from scalar_blocks import (AFFINE, CONSTANT, FRAME, RAW, SPARSE, U32, Choice,
                           block_choices, decode_image, fixed_layout, lookup_image,
                           serialize, solve_layout)


def oracle_block_costs(values, max_work):
    """Cost formulas independent of serializer or its candidate enumerator."""
    n = len(values)
    result = [12 + 4 * n] if max_work >= 1 else []
    if len(set(values)) == 1 and max_work >= 1:
        result.append(16)
    if n > 1 and max_work >= 2 and all(values[i] - values[i - 1] == values[1] - values[0] for i in range(1, n)):
        result.append(24)
    bits = (max(values) - min(values)).bit_length()
    if bits and max_work >= 2:
        result.append(16 + (n * bits + 7) // 8)
    maximum_frequency = max(values.count(v) for v in values)
    exceptions = n - maximum_frequency
    if exceptions and exceptions + 1 <= max_work:
        result.append(18 + 6 * exceptions)
    return result


def exhaustive_cost(values, span, max_work):
    """Enumerate every boundary sequence and format cost, memoizing suffixes."""
    @lru_cache(None)
    def suffix(at):
        if at == len(values):
            return 0
        stops = set(range(at + 1, min(len(values), at + span) + 1))
        if at == 0:
            stops.add(len(values))
        return min(cost + suffix(stop)
                   for stop in sorted(stops)
                   for cost in oracle_block_costs(values[at:stop], max_work))
    return 20 + suffix(0)


class ScalarBlocksTests(unittest.TestCase):
    def test_every_mode_roundtrips(self):
        cases = [([1, 2, 3, 0x12345678], RAW), ([U32] * 7, CONSTANT),
                 ([U32 - i for i in range(8)], AFFINE), ([3, 7, 4, 6, 5], FRAME),
                 ([17] * 8 + [U32], SPARSE)]
        for values, mode in cases:
            choice = next(c for c in block_choices(values, max_work=65) if c.mode == mode)
            image = serialize(len(values), [choice])
            self.assertEqual(decode_image(image), values)
            self.assertEqual([lookup_image(image, i) for i in reversed(range(len(values)))], list(reversed(values)))

    def test_random_small_models_match_independent_oracle(self):
        rng = random.Random(378)
        for _ in range(35):
            values = [rng.choice([0, 1, 2, 65535, U32, rng.getrandbits(32)]) for _ in range(rng.randrange(1, 10))]
            span, work = rng.randrange(1, 5), rng.randrange(1, 5)
            image, _, _, _ = solve_layout(values, span, work)
            self.assertEqual(len(image), exhaustive_cost(tuple(values), span, work))
            self.assertEqual(decode_image(image, work), values)

    def test_empty_and_non_uint32_inputs(self):
        image, _, _, _ = solve_layout([])
        self.assertEqual(len(image), 20)
        self.assertEqual(decode_image(image), [])
        for values in [[-1], [U32 + 1], [True], [1.0], [0] * 257]:
            with self.assertRaises(ValueError):
                solve_layout(values)

    def test_every_truncated_prefix_and_trailing_byte(self):
        image, _, _, _ = solve_layout([1] * 4 + [U32] * 3 + [18, 21, 24], 4)
        for size in range(len(image)):
            with self.assertRaises(ValueError):
                decode_image(image[:size])
        with self.assertRaises(ValueError):
            decode_image(image + b'\0')

    def test_invalid_directory_mode_and_lengths(self):
        image = bytearray(fixed_layout([4, 5, 6, 7], raw_only=True)[0])
        for offset, replacement in [(0, b'WRONG!!!'), (8, struct.pack('<I', 257)),
                                    (16, struct.pack('<I', 1)), (20, struct.pack('<I', U32)),
                                    (28, struct.pack('<H', 3)), (30, b'\xff'), (31, b'\x01')]:
            damaged = bytearray(image); damaged[offset:offset + len(replacement)] = replacement
            with self.assertRaises(ValueError):
                decode_image(damaged)

    def test_checked_affine_and_frame_overflow(self):
        bad_affine = Choice(0, 3, AFFINE, 2, struct.pack('<HBBIq', 3, AFFINE, 0, U32 - 1, 1))
        with self.assertRaises(ValueError):
            decode_image(serialize(3, [bad_affine]))
        bad_frame = Choice(0, 2, FRAME, 2, struct.pack('<HBBI', 2, FRAME, 1, U32) + b'\x03')
        with self.assertRaises(ValueError):
            decode_image(serialize(2, [bad_frame]))

    def test_sparse_positions_and_decode_bound(self):
        values = [9] * 8 + [1000]
        sparse = next(c for c in block_choices(values) if c.mode == SPARSE)
        image = serialize(len(values), [sparse])
        with self.assertRaises(ValueError):
            decode_image(image, 1)
        damaged = bytearray(image)
        # Payload starts at 28: block header4 + sparse base/count6 + position2.
        damaged[38:40] = struct.pack('<H', 9)
        with self.assertRaises(ValueError):
            decode_image(damaged)
        with self.assertRaises(ValueError):
            lookup_image(image, len(values))

    def test_global_baselines_are_retained_when_extra_boundaries_lose(self):
        values = [7] * 32
        raw, _ = fixed_layout(values, span=32, raw_only=True)
        whole, _ = fixed_layout(values, span=32)
        joint, _, _, _ = solve_layout(values, max_span=16)
        self.assertEqual(len(whole), len(joint))
        self.assertLess(len(joint), len(raw))
        values = [random.Random(i).getrandbits(32) for i in range(32)]
        joint, _, _, _ = solve_layout(values, max_span=16)
        whole, _ = fixed_layout(values, span=32)
        self.assertLessEqual(len(joint), len(whole))


if __name__ == '__main__':
    unittest.main(verbosity=2)
