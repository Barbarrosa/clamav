"""Independent boundary checks of resource bounds and lexical source metrics.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import tempfile
import unittest

from complexity_metrics import (analyze_field_programs, measure_source,
                                local_field_bounds, local_query_units,
                                packed_word_reads, source_metrics)


def field(op, width=0, parent=None, count=0, bits=64):
    return dict(operation=op, width=width, native_bits=bits, parent=parent, count=count)


class FieldComplexityTests(unittest.TestCase):
    def test_packed_reads_match_exhaustive_actual_rows(self):
        for rows in (0, 1, 2, 3, 63, 64, 65, 1029):
            for width in range(65):
                expected = max((1 + ((row * width) % 64 + width > 64)
                                for row in range(rows)), default=0) if width else 0
                self.assertEqual(packed_word_reads(rows, width), expected)

    def test_metadata_and_identity_are_not_free(self):
        direct = analyze_field_programs([field('constant'), field('store_xor', 64)], 100)
        self.assertEqual(direct['fields'][0]['bounds']['descriptor_visits'], 1)
        self.assertEqual(direct['fields'][0]['bounds']['payload_read_operations'], 0)
        self.assertEqual(direct['fields'][1]['bounds']['payload_read_operations'], 1)
        binary = analyze_field_programs([field('constant')], 100,
                    identity_strategy='binary_address', identity_objects=100)
        self.assertEqual(binary['identity_lookup_reads_upper'], 15)
        self.assertIn('log N', binary['identity_growth'])
        self.assertEqual(binary['fields'][0]['data_and_identity_reads_upper'], 15)
        boundary = analyze_field_programs([field('constant')], 1,
                    identity_strategy='binary_address', identity_objects=1 << 54)
        self.assertEqual(boundary['identity_search_levels_upper'], 55)
        self.assertEqual(boundary['identity_lookup_reads_upper'], 111)

    def test_dependencies_accumulate_and_cycles_reject(self):
        result = analyze_field_programs([field('store_xor', 13),
            field('alias_xor', parent=0), field('alias_add', parent=1)], 100)
        end = result['fields'][2]
        self.assertEqual(end['bounds']['descriptor_visits'], 3)
        self.assertEqual(end['bounds']['dependency_depth'], 2)
        self.assertEqual(end['bounds']['payload_read_operations'], 2)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            analyze_field_programs([field('alias_add', parent=1),
                                    field('alias_xor', parent=0)], 10)

    def test_sparse_has_bounded_rank_work_and_reuses_bitmap_word(self):
        result = analyze_field_programs([field('constant'),
            field('sparse_override', 9, 0, 100)], 1500)
        sparse = result['fields'][1]['bounds']
        self.assertEqual(sparse['rank_popcounts'], 8)
        self.assertEqual(sparse['rank_loop_iterations'], 7)
        self.assertEqual(sparse['payload_read_operations'], 11)  # bitmap+rank+7words+2packed
        self.assertEqual(sparse['payload_bytes_read'], 8 + 4 + 56 + 16)
        self.assertEqual(sparse['descriptor_visits'], 2)
        for rows in (1, 63, 64, 65, 127, 128, 129):
            report = analyze_field_programs([field('constant'),
                field('sparse_override', 1, 0, 1)], rows)
            self.assertEqual(report['fields'][1]['bounds']['rank_popcounts'],
                             min(8, (rows + 63) // 64))

    def test_sparse_known_empty_and_full_paths(self):
        empty = analyze_field_programs([field('store_xor', 64),
            field('sparse_override', 0, 0, 0)], 512)['fields'][1]['bounds']
        self.assertEqual(empty['rank_popcounts'], 0)
        self.assertEqual(empty['payload_read_operations'], 2)
        full = analyze_field_programs([field('store_xor', 64),
            field('sparse_override', 1, 0, 512)], 512)['fields'][1]['bounds']
        self.assertEqual(full['descriptor_visits'], 1)
        self.assertEqual(full['dependency_depth'], 0)
        self.assertEqual(full['rank_popcounts'], 8)

    def test_additive_local_bounds_dominate_mutually_exclusive_paths(self):
        programs = [field('store_xor', 13), field('alias_add', parent=0),
                    field('sparse_override', 9, 1, 100)]
        actual = analyze_field_programs(programs, 1029)['fields']
        accumulated = {}
        for index, program in enumerate(programs):
            local = local_field_bounds(program, 1029)
            if program['parent'] is not None:
                parent = accumulated[program['parent']]
                local = {key: local[key] + parent[key] for key in local}
            accumulated[index] = local
            for key, value in actual[index]['bounds'].items():
                self.assertGreaterEqual(local[key], value)
        self.assertEqual(local_query_units(field('constant'), 10), 1)
        self.assertEqual(local_query_units(field('alias_add', parent=0), 10), 2)
        self.assertEqual(local_query_units(field('constant'), 0), 1)

    def test_empty_rows_and_invalid_metadata(self):
        report = analyze_field_programs([field('store_xor', 8)], 0)
        self.assertTrue(all(v == 0 for v in report['worst_bounds'].values()))
        for programs, kwargs in [([field('store_xor')], {}),
                ([field('alias_add', parent=4)], {}),
                ([field('sparse_override', 1, 0, 3)], {}),
                ([field('constant', 1)], {}),
                ([field('constant')], {'identity_strategy': 'binary_address'})]:
            with self.subTest(programs=programs, kwargs=kwargs), self.assertRaises(ValueError):
                analyze_field_programs(programs, 2, **kwargs)


class LexicalMetricsTests(unittest.TestCase):
    def test_c_comments_literals_and_preprocessor_are_separate(self):
        text = '''#if FOO
/* if for while malloc( */
const char *s = "if for ? && malloc(";
char c = '\\''; // while calloc(
if (x && y) { for (;;) { malloc(4); } }
#endif
'''
        report = source_metrics(text, 'c')
        self.assertEqual(report['branch_keyword_sites']['if'], 1)
        self.assertEqual(report['loop_keyword_sites']['for'], 1)
        self.assertEqual(report['loop_keyword_sites']['while'], 0)
        self.assertEqual(report['explicit_allocation_or_release_call_sites'], 1)
        self.assertEqual(report['preprocessor_conditional_sites'], 1)
        self.assertEqual(report['short_circuit_or_conditional_operator_sites'], 1)

    def test_python_strings_comments_and_comprehension(self):
        text = '''"""if for malloc("""
def f(xs):
    # if for list(
    message = "if for malloc("
    return list(x for x in xs if x and x.ok)
'''
        report = source_metrics(text, 'python')
        self.assertEqual(report['branch_keyword_sites']['if'], 1)
        self.assertEqual(report['loop_keyword_sites']['for'], 1)
        self.assertEqual(report['short_circuit_or_conditional_operator_sites'], 1)
        self.assertEqual(report['explicit_allocation_or_release_call_sites'], 1)
        self.assertEqual(report['python_function_definitions'], 1)

    def test_malformed_c_is_not_silently_measured(self):
        for text in ('/* unfinished', 'char *x = "unfinished'):
            with self.assertRaises(ValueError):
                source_metrics(text, 'c')

    def test_source_identity_and_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.c'
            path.write_text('if (x) return 1;\n')
            first = measure_source(path)
            second = measure_source(path)
            self.assertEqual(first, second)
            self.assertIn('not cyclomatic', first['scope'])
            path.write_text('if (y) return 2;\n')
            self.assertNotEqual(first['sha256'], measure_source(path)['sha256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
