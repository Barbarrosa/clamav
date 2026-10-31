"""Checks of the candidate filter and original-reference reconstruction.
SPDX-License-Identifier: GPL-2.0-only
"""
import unittest
from tokens import diverse_candidates, fixture_rows
from joint_token_dictionary import Problem, decode_image


class TokenExperiments(unittest.TestCase):
    def test_filter_is_deterministic_and_respects_bounds(self):
        rows = [b'ababababa', b'abcabcabc', b'abcdabcd']
        for count in [0, 1, 8, 16, 64]:
            pool = diverse_candidates(rows, count)
            self.assertEqual(pool, diverse_candidates(rows, count))
            self.assertLessEqual(len(pool), count)
            self.assertEqual(len(pool), len(set(pool)))
            self.assertTrue(all(3 <= len(f) <= 32 for f in pool))

    def test_public_duplicate_references_remain_exact(self):
        rows, refs, _ = fixture_rows()
        self.assertGreater(len(refs), len(rows))
        layout = Problem(rows, candidates=[]).solve()
        decoded, widths = decode_image(layout.to_bytes())
        self.assertEqual(widths, [False] * len(rows))
        self.assertTrue(all(decoded[i] == original for _, _, i, original in refs))

    def test_zero_work_rejects_nonempty_data(self):
        with self.assertRaises(ValueError):
            Problem([b'abc'], candidates=[], max_decode_steps=0).solve()


if __name__ == '__main__':
    unittest.main(verbosity=2)
