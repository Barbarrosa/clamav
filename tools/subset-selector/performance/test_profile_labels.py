"""Check descriptive labels without rewriting archived measurement evidence.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from profile_labels import (LEGACY_RESTRICTED_VARIANT, RESTRICTED_VARIANT,
                            VARIANTS, normalize_summary)
from render_tables import HEADERS, build_tables, markdown
from run_matrix import make_plan

HERE = Path(__file__).resolve().parent
ARCHIVED = HERE.parents[2] / 'docs/subset-selector-results/three-way-performance'


class ProfileLabelTests(unittest.TestCase):
    def test_archived_summary_keeps_evidence_but_renders_current_names(self):
        path = ARCHIVED / 'summary.json'
        before = path.read_bytes()
        summary = json.loads(before)
        original = copy.deepcopy(summary)
        current = normalize_summary(summary)
        self.assertEqual(summary, original)
        self.assertEqual(set(current['variants']), set(VARIANTS))
        self.assertEqual(current['variants'][RESTRICTED_VARIANT],
                         summary['variants'][LEGACY_RESTRICTED_VARIANT])
        self.assertIn('upstream-to-' + RESTRICTED_VARIANT, current['comparisons'])
        self.assertIn(RESTRICTED_VARIANT, current['validation']['primary_semantic_comparisons'])
        self.assertNotIn(LEGACY_RESTRICTED_VARIANT, current['validation']['extended_comparisons']['positive'])
        self.assertEqual(build_tables(summary), build_tables(current))
        rendered = markdown(build_tables(summary)['overview'])
        self.assertIn('| Compiled engine RSS (MiB, mean) | 959.6 | 791.2 | 131.1 |', rendered)
        self.assertIn('PDF/JPEG/PNG', rendered)
        self.assertNotIn(LEGACY_RESTRICTED_VARIANT, rendered)
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), hashlib.sha256(before).digest())

    def test_ambiguous_old_and_new_variants_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            normalize_summary({'variants': {LEGACY_RESTRICTED_VARIANT: {}, RESTRICTED_VARIANT: {}}})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            normalize_summary({'variants': {}, 'comparisons': {
                'full-to-' + LEGACY_RESTRICTED_VARIANT: {},
                'full-to-' + RESTRICTED_VARIANT: {}}})

    def test_new_plan_uses_only_current_names_and_keeps_case_order(self):
        args = SimpleNamespace(seed=20261029, rounds=5, repetitions=3, lifecycle_rounds=3,
                               fixtures=Path('/synthetic/accepted.txt'),
                               positive=Path('/synthetic/positive.txt'), adverse=Path('/synthetic/adverse.txt'))
        plan = make_plan(args, Path('/synthetic/empty.txt'))
        self.assertEqual(len(plan), 78)
        self.assertEqual({item['variant'] for item in plan}, set(VARIANTS))
        original = json.loads((ARCHIVED / 'plan.json').read_text())
        # Rename leaves the randomized stage/cache/variant allocation unchanged.
        current_cases = [(item['stage'], item['cache'], item['round'], item['variant'], item.get('database'))
                         for item in plan]
        original_cases = [(item['stage'], item['cache'], item['round'],
                           RESTRICTED_VARIANT if item['variant'] == LEGACY_RESTRICTED_VARIANT else item['variant'],
                           item.get('database')) for item in original]
        self.assertEqual(current_cases, original_cases)

    def test_report_cli_accepts_archived_summary_and_uses_new_option(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report.md'
            subprocess.run([sys.executable, str(HERE / 'build_report.py'),
                            '--summary', str(ARCHIVED / 'summary.json'), '--output', str(output)],
                           check=True, capture_output=True, text=True)
            text = output.read_text()
            self.assertIn('--database-profile=' + RESTRICTED_VARIANT, text)
            self.assertIn('| Compiled engine RSS (MiB, mean) | 959.6 | 791.2 | 131.1 |', text)
            self.assertNotIn(LEGACY_RESTRICTED_VARIANT, text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
