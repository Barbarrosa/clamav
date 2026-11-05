"""Checks of combined native/synthesized providers and simultaneous liveness.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import tempfile
import unittest

import numpy as np

from field_synthesis import synthesize
from run_system_model import lifecycle, system_selection, write_locator
from replay_witness import complete_assignment


class SystemModelTests(unittest.TestCase):
    def test_witness_requires_explicit_original_variables_but_allows_cnf_extension(self):
        self.assertEqual(complete_assignment([1, -2, 3, -4], 2),
                         {1: True, 2: False, 3: True, 4: False})
        for model in ([1], [1, -1], [1, 0, -2], [True, -2], [1.0, -2], None):
            with self.subTest(model=model), self.assertRaises(ValueError):
                complete_assignment(model, 2)

    def test_combined_model_has_native_fallback_and_actual_field_variables(self):
        a = synthesize({'value': np.full(64, 7, dtype=np.uint64)}, 8, max_depth=2)
        b = synthesize({'value': np.array([1, 255, 99], dtype=np.uint64)}, 8, max_depth=2)
        families = [dict(family='large', native_record_bytes=64,
                         synthesized_provider_bytes=a.total_bytes + 16,
                         identity_locator_bytes=16),
                    dict(family='tiny', native_record_bytes=3,
                         synthesized_provider_bytes=b.total_bytes,
                         identity_locator_bytes=0)]
        with tempfile.TemporaryDirectory() as folder:
            result = system_selection(families, [a, b], 1000, Path(folder), budget=1100)
            self.assertEqual(result['providers'], {'large': 'synthesized', 'tiny': 'native'})
            self.assertEqual(result['variable_provider_bytes'], a.total_bytes + 16 + 3)
            self.assertTrue(result['within_requested_budget'])
            self.assertTrue(result['all_global_witness_fields_reconstructed'])
            self.assertGreater(result['combined_variables'], a.problem.nv + b.problem.nv)

    def test_liveness_does_not_count_retained_native_providers_twice(self):
        # Native100, final80 = retained-native30 + allocated-new50.
        values = lifecycle(retained=1000, native=100, chosen=80, added=50)
        self.assertEqual(values['in_place_conversion_known_payload_peak_bytes'], 1150)
        self.assertEqual(values['two_ready_generations_known_payload_bytes'], 2160)
        self.assertEqual(values['old_converted_plus_replacement_conversion_known_peak_bytes'], 2230)

    def test_locator_charges_all_identity_support_and_preserves_rows(self):
        addresses = np.array([0x2000, 0x1000, 0x3000], dtype=np.uint64)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'locator'
            report = write_locator(addresses, path)
            self.assertEqual(path.stat().st_size, 16 + 12 * 3)
            self.assertEqual(report['bytes'], path.stat().st_size)
            self.assertEqual(report['identity_queries_verified'], 3)
            with self.assertRaises(ValueError):
                write_locator(np.array([1, 1], dtype=np.uint64), path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
