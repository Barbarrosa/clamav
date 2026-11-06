"""Independent evidence-integrity checks; no engine build needed.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import unittest
from run_matrix import semantic_digest, summarize


def scan():
    return {'kind': 'scan', 'path': '/private/local/fixture.pdf', 'phase': 'fixture_scan',
            'round': 0, 'allmatch': 1, 'return_code': 0, 'verdict': 0,
            'final_name': None, 'root_type': 'CL_TYPE_PDF', 'sha256': 'a' * 64,
            'after_sha256': 'a' * 64, 'hold_bits': 0, 'candidate_outcome': 'clean',
            'scanned_bytes': 20, 'input_bytes': 20,
            'events': [{'event': 'pre_scan'}, {'event': 'post_scan'}]}


def case(group='names', dose=0, rss=100, digest='same', shared=False):
    return {'variant': 'instrumented', 'group': group, 'dose': dose, 'repetition': 0,
            'status': 'complete', 'semantic_sha256': digest, 'signatures': [123],
            'snapshots': {'compiled': {'rss_kib': rss}},
            'shared_zero_control': shared, 'dose_censored_by_cap': False,
            'cumulative_added_bytes': dose * 100, 'injected_calls': 100 if dose else 0}


class SemanticEvidenceTests(unittest.TestCase):
    def test_timing_and_local_path_do_not_change_semantic_digest(self):
        a, b = scan(), scan()
        b.update(path='/different/root/fixture.pdf', cpu_seconds=88, wall_seconds=99)
        self.assertEqual(semantic_digest([a], 1), semantic_digest([b], 1))

    def test_ordered_callbacks_and_reporting_changes_are_detected(self):
        original = scan()
        for change in ('events', 'final_name', 'scanned_bytes', 'hold_bits', 'verdict'):
            candidate = copy.deepcopy(original)
            if change == 'events': candidate[change].reverse()
            elif change == 'final_name': candidate[change] = 'Different.Alert'
            else: candidate[change] += 1
            self.assertNotEqual(semantic_digest([original], 1), semantic_digest([candidate], 1))

    def test_incomplete_and_changed_inputs_are_rejected(self):
        with self.assertRaises(ValueError): semantic_digest([], 1)
        altered = scan(); altered['after_sha256'] = 'b' * 64
        with self.assertRaises(ValueError): semantic_digest([altered], 1)
        failed = scan(); failed['candidate_outcome'] = 'failed'; failed['return_code'] = 10
        # Expected malformed-input errors are valid evidence, but must match
        # controls exactly rather than being silently treated as clean.
        self.assertNotEqual(semantic_digest([scan()], 1), semantic_digest([failed], 1))

    def test_shared_controls_use_median_and_detect_inconsistent_semantics(self):
        controls = [case(rss=n, shared=True) for n in (100, 102, 104)]
        candidate = case(group='tokens', dose=8, rss=120)
        aggregates = summarize(controls + [candidate])
        self.assertEqual(candidate['rss_delta_vs_zero_bytes']['compiled'], 18 * 1024)
        self.assertTrue(candidate['semantics_match_zero_dose'])
        self.assertEqual(next(a for a in aggregates if a['group'] == 'tokens')['uncensored_semantically_matching'], 1)
        controls[1]['semantic_sha256'] = 'different'
        summarize(controls + [candidate])
        self.assertFalse(candidate['semantics_match_zero_dose'])

    def test_cap_censoring_and_stock_mismatch_cannot_qualify(self):
        baseline = case()
        candidate = case(dose=32, rss=150)
        candidate['dose_censored_by_cap'] = True
        stock = case(); stock.update(variant='stock', group='disabled', semantic_sha256='different')
        aggregate = summarize([baseline, candidate, stock])
        self.assertFalse(candidate['semantics_match_stock'])
        self.assertEqual(next(a for a in aggregate if a['dose_bytes_per_matching_request'] == 32)['uncensored_semantically_matching'], 0)


if __name__ == '__main__':
    unittest.main()
