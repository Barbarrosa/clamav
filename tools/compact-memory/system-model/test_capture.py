"""Independent native-schema, pointer-identity and byte-replay loader checks.
SPDX-License-Identifier: GPL-2.0-only
"""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import numpy as np

from capture import Family, NIL, interval_union_bytes, load_capture, resolve_pointers


def definition(offset, width, count=1):
    return {'native_offset': offset, 'element_bytes': width, 'count': count}


def make_capture(path):
    layout = {
        'schema': 1, 'native_pointer_bytes': 8,
        'pattern_size': 40,
        'pattern_fields': {'pattern': definition(0, 8), 'prefix': definition(8, 8),
                           'ext': definition(16, 8), 'virname': definition(24, 8),
                           'length': definition(32, 2, 2)},
        'candidate_size': 24,
        'candidate_fields': {name: definition(i * 8, 8) for i, name in enumerate(['me', 'next', 'next_same'])},
        'node_size': 24,
        'node_fields': {name: definition(i * 8, 8) for i, name in enumerate(['list', 'trans', 'fail'])},
        'logical_size': 8, 'logical_fields': {'tdb': definition(0, 8)},
        'tdb_fields': {'mempool': definition(0, 8)},
        'extension_size': 16,
        'extension_fields': {'customdata': definition(0, 8), 'mindist': definition(8, 4), 'maxdist': definition(12, 4)},
        'targets': []}
    schema = {'schema': 1, 'endianness': 'little', 'patterns': 2, 'candidate_records': 2,
              'nodes': 1, 'logical_records': 0, 'transition_rows': 1, 'objects': 5,
              'native_sizes': {'pointer': 8, 'pattern': 40, 'candidate': 24, 'node': 24,
                               'logical': 8, 'extension': 16}}
    (path / 'native-layout.json').write_text(json.dumps(layout))
    (path / 'graph-schema.json').write_text(json.dumps(schema))
    objects = [(2, 8, b'01234567', NIL, 0x8000), (2, 4, b'2345', NIL, 0x8002),
               (1, 5, b'Test\0', 0, 0x9000), (1024, 0, b'', NIL, 0xa000),
               (4, 16, b'', NIL, 0xb000)]
    raw = bytearray(struct.pack('<I', len(objects)))
    for kind, extent, payload, name, address in objects:
        raw.extend(struct.pack('<IIIIQ', kind, extent, len(payload), name, address))
        raw.extend(payload)
    (path / 'objects.bin').write_bytes(raw)
    (path / 'native_patterns.bin').write_bytes(
        struct.pack('<QQQQHH4x', 0x8002, 0x8000, 0xb000, 0x9000, 2, 4) +
        struct.pack('<QQQQHH4x', 0x8002, 0, 0, 0x9000, 2, 4))
    (path / 'native_links.bin').write_bytes(struct.pack('<6Q', 0x1000, 0x2018, 0, 0x1028, 0, 0))
    (path / 'native_nodes.bin').write_bytes(struct.pack('<3Q', 0x2000, 0x4000, 0x3000))
    (path / 'native_logical.bin').write_bytes(b'')
    (path / 'native_extensions.bin').write_bytes(struct.pack('<QII', 0xa000, 7, 99))
    for name, values in [('pattern_addresses', [0x1000, 0x1028]),
                         ('link_addresses', [0x2000, 0x2018]), ('node_addresses', [0x3000]),
                         ('transition_addresses', [0x4000]), ('logical_addresses', [])]:
        (path / (name + '.bin')).write_bytes(struct.pack('<' + 'Q' * len(values), *values))
    (path / 'links.bin').write_bytes(struct.pack('<6I', 0, 1, NIL, 1, NIL, NIL))
    (path / 'node_graph.bin').write_bytes(struct.pack('<5I', 0, 1, 0, 0, 0))
    (path / 'pattern_objects.bin').write_bytes(struct.pack('<8I', 1, 0, 4, 2, 1, NIL, NIL, 2))
    (path / 'logical_objects.bin').write_bytes(b'')
    (path / 'transitions.bin').write_bytes(struct.pack('<257I', 0, *([1] * 256)))
    (path / 'targets.bin').write_bytes(struct.pack('<9I', 0, 0, 2, 0, 2, 0, 0, 0, 1))


class Echo:
    def __init__(self, family):
        self.family = family

    def reconstruct(self, name):
        return self.family.columns[name].astype(np.uint64)

    def get(self, name, row):
        return int(self.family.columns[name][row])


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        make_capture(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_native_schema_and_byte_replay(self):
        capture = load_capture(self.path)
        self.assertEqual([f.name for f in capture.families],
                         ['patterns', 'candidates', 'nodes', 'logical', 'extensions', 'transition_values'])
        pattern = capture.families[0]
        self.assertEqual(pattern.rows, 2)
        self.assertEqual(pattern.native_bytes, 80)
        self.assertEqual(pattern.source_bits['pattern'], 64)
        self.assertEqual(pattern.source_bits['length[0]'], 16)
        self.assertNotIn('generated_id', pattern.columns)
        replay = pattern.verify(Echo(pattern))
        self.assertEqual(replay['native_named_bytes_compared'], 72)
        self.assertEqual(replay['native_padding_bytes_outside_get_contract'], 8)
        for family in capture.families:
            self.assertTrue(family.verify(Echo(family))['all_named_fields_equal'])
        self.assertEqual(capture.graph_validation['source_pointer_edges_compared'], 17)
        self.assertEqual(capture.graph_validation['transition_destinations_checked'], 256)

    def test_interior_pointer_spans_are_union_not_duplicate_allocations(self):
        capture = load_capture(self.path)
        self.assertEqual(capture.retained_known_payload_bytes, 13)  # eight shared token bytes + five name bytes
        self.assertEqual(capture.unknown_object_count, 1)
        self.assertTrue(capture.manifest['additional_engine_and_allocator_bytes_unknown'])
        self.assertEqual(interval_union_bytes([100, 102, 108, 200], [8, 4, 2, 0]), 10)
        with self.assertRaises(ValueError):
            interval_union_bytes([(1 << 64) - 2], [3])

    def test_missing_pointer_or_wrong_normalized_identity_rejected(self):
        raw = bytearray((self.path / 'native_links.bin').read_bytes())
        struct.pack_into('<Q', raw, 8, 0x2019)
        (self.path / 'native_links.bin').write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'source pointer'):
            load_capture(self.path)
        make_capture(self.path)
        raw = bytearray((self.path / 'links.bin').read_bytes())
        struct.pack_into('<I', raw, 0, 1)
        (self.path / 'links.bin').write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'candidate source-pointer graph'):
            load_capture(self.path)

    def test_transition_outside_actual_target_is_rejected(self):
        raw = bytearray((self.path / 'transitions.bin').read_bytes())
        struct.pack_into('<I', raw, 4, 2)
        (self.path / 'transitions.bin').write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'outside its target'):
            load_capture(self.path)

    def test_corrupt_native_layout_or_dimensions_are_rejected(self):
        layout = json.loads((self.path / 'native-layout.json').read_text())
        layout['pattern_fields']['prefix']['native_offset'] = 0
        (self.path / 'native-layout.json').write_text(json.dumps(layout))
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            load_capture(self.path)
        make_capture(self.path)
        (self.path / 'native_nodes.bin').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'invalid native record'):
            load_capture(self.path)

    def test_object_truncation_and_identity_duplicates_are_rejected(self):
        original = (self.path / 'objects.bin').read_bytes()
        (self.path / 'objects.bin').write_bytes(original[:-1])
        with self.assertRaisesRegex(ValueError, 'truncated'):
            load_capture(self.path)
        with self.assertRaisesRegex(ValueError, 'not unique'):
            resolve_pointers(np.array([9]), np.array([9, 9]))

    def test_replay_checks_actual_values_not_just_storage_size(self):
        family = load_capture(self.path).families[0]
        class Wrong(Echo):
            def reconstruct(self, name):
                values = super().reconstruct(name)
                if name == 'pattern':
                    values[0] ^= np.uint64(1)
                return values
        with self.assertRaisesRegex(AssertionError, 'complete native field'):
            family.verify(Wrong(family))

    def test_logical_record_identities_cannot_be_merged(self):
        schema = json.loads((self.path / 'graph-schema.json').read_text())
        schema['logical_records'] = 2
        (self.path / 'graph-schema.json').write_text(json.dumps(schema))
        (self.path / 'native_logical.bin').write_bytes(struct.pack('<2Q', 0xbeef, 0xbeef))
        (self.path / 'logical_addresses.bin').write_bytes(struct.pack('<2Q', 0x7000, 0x7000))
        with self.assertRaisesRegex(ValueError, 'identities are null or duplicated'):
            load_capture(self.path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
