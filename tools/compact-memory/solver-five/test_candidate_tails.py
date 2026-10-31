#!/usr/bin/env python3
"""Independent oracle and malformed-graph checks for candidate-tail experiment.
SPDX-License-Identifier: GPL-2.0-only
"""
import random
import struct
import unittest

from candidate_tails import (DESCRIPTOR, HEADER, NODE, NIL, Image, Problem,
                             decode_image, exhaustive_minimum, make_records)


def record(identity, flags=0):
    return (identity, identity, flags, NIL)


class CandidateTests(unittest.TestCase):
    def test_shared_tail_wins_with_setup_cost_charged(self):
        tail = (record(10), record(11), record(12))
        lists = [(record(i),) + tail for i in range(5)]
        problem = Problem(lists, 3)
        optimum, _ = problem.solve()
        self.assertEqual(optimum.variable_bytes, exhaustive_minimum(lists, 3))
        self.assertLess(len(optimum.to_bytes()), len(problem.raw().to_bytes()))
        self.assertEqual(decode_image(optimum.to_bytes()), tuple(lists))

    def test_all_distinct_uses_inline(self):
        lists = [(record(i * 10), record(i * 10 + 1)) for i in range(4)]
        problem = Problem(lists)
        optimum, _ = problem.solve()
        self.assertEqual(optimum.lengths, (0, 0, 0, 0))
        self.assertEqual(optimum.variable_bytes, 16 * 8)

    def test_every_tuple_field_is_part_of_sharing_identity(self):
        lists = [((7, i * 10, 1, i * 10 + 1), (7, i * 10 + 1, 3, NIL)) for i in range(4)]
        optimum, _ = Problem(lists).solve()
        self.assertEqual(optimum.lengths, (0,) * 4)
        self.assertEqual(decode_image(optimum.to_bytes()), tuple(lists))

    def test_hop_limit_restricts_shared_suffix(self):
        tail = tuple(record(100 + i) for i in range(5))
        lists = [tail] * 3
        limited, _ = Problem(lists, 2).solve()
        self.assertTrue(all(length <= 2 for length in limited.lengths))
        self.assertEqual(limited.variable_bytes, exhaustive_minimum(lists, 2))
        with self.assertRaises(ValueError):
            decode_image(limited.to_bytes(), max_hops=1)
        raw, _ = Problem(lists, 0).solve()
        self.assertEqual(raw.lengths, (0, 0, 0))

    def test_empty_lists(self):
        optimum, _ = Problem([(), ()], 0).solve()
        self.assertEqual(decode_image(optimum.to_bytes()), ((), ()))

    def test_random_small_problems_match_independent_enumeration(self):
        rng = random.Random(37804)
        pool = [record(i) for i in range(5)]
        for _ in range(40):
            lists = []
            for _ in range(rng.randrange(1, 5)):
                identities = rng.sample(range(5), rng.randrange(0, 4))
                lists.append(tuple(pool[i] for i in identities))
            bound = rng.randrange(4)
            optimum, _ = Problem(lists, bound).solve()
            self.assertEqual(optimum.variable_bytes, exhaustive_minimum(lists, bound))
            self.assertEqual(decode_image(optimum.to_bytes()), tuple(lists))

    def test_public_duplicate_pattern_chain(self):
        patterns = [b'abc', b'xyz', b'abc']
        records = make_records(patterns, [0, 2, 1])
        self.assertEqual(records[0][3], 2)
        self.assertEqual(records[1][3], NIL)
        self.assertNotEqual(records[0][1], records[1][1])

    def test_invalid_next_same_and_duplicate_occurrence_rejected(self):
        with self.assertRaises(ValueError):
            Problem([((1, 0, 0, 99),)])
        with self.assertRaises(ValueError):
            Problem([((1, 0, 0, NIL), (1, 0, 1, NIL))])
        with self.assertRaises(ValueError):
            Problem([((1, 0, 0, 1), (2, 1, 0, NIL))])

    def test_truncation_trailing_bytes_and_cycle_rejected(self):
        tail = (record(10), record(11))
        optimum, _ = Problem([tail] * 3, 2).solve()
        image = optimum.to_bytes()
        for end in range(len(image)):
            with self.assertRaises(ValueError):
                decode_image(image[:end])
        with self.assertRaises(ValueError):
            decode_image(image + b'junk')
        _, count, nodes, inline, _ = HEADER.unpack_from(image)
        node_start = HEADER.size + count * DESCRIPTOR.size + inline * 16
        cyclic = bytearray(image)
        struct.pack_into('<I', cyclic, node_start + 16, 0)
        with self.assertRaises(ValueError):
            decode_image(cyclic)

    def test_invalid_descriptor_and_resource_header_rejected(self):
        image = bytearray(Image(((record(1),),), (0,), 0).to_bytes())
        struct.pack_into('<I', image, HEADER.size, 999)
        with self.assertRaises(ValueError):
            decode_image(image)
        struct.pack_into('<I', image, 8, 100000)
        with self.assertRaises(ValueError):
            decode_image(image)


if __name__ == '__main__':
    unittest.main(verbosity=2)
