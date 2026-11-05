#!/usr/bin/env python3
"""Independently compare source-native scalar fields with the normalized export.

Input is a private compiled-engine graph capture. Output contains counts and
file hashes only, never signature bytes, threat names or pointer values.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np


def verify_capture(capture):
    p = Path(capture)
    schema = json.loads((p / 'graph-schema.json').read_text())
    layout = json.loads((p / 'native-layout.json').read_text())
    comparisons = 0

    def raw(name):
        path = p / name
        return np.memmap(path, dtype='u1', mode='r') if path.stat().st_size else np.empty(0, dtype='u1')

    def view(data, rows, count, width, stride, offset=0):
        if not rows:
            return np.empty((0, count), dtype='<u' + str(width))
        return np.ndarray((rows, count), dtype='<u' + str(width), buffer=data,
                          offset=offset, strides=(stride, width))

    def field(data, rows, stride, description, base=0):
        width, count = description['element_bytes'], description['count']
        offset = base + description['native_offset']
        if offset < 0 or offset + width * count > stride:
            raise ValueError('native field descriptor exceeds record boundary')
        return view(data, rows, count, width, stride, offset)

    def equal(label, left, right):
        nonlocal comparisons
        left, right = np.asarray(left), np.asarray(right)
        if left.shape != right.shape or not np.array_equal(left, right):
            raise AssertionError(label)
        comparisons += left.size

    rows = schema['patterns']
    native, norm = raw('native_patterns.bin'), raw('patterns.bin')
    stride = schema['native_sizes']['pattern']
    u32, u16 = view(norm, rows, 13, 4, 74), view(norm, rows, 10, 2, 74, 52)
    for name, start, count in [('sigid', 3, 1), ('lsigid', 4, 3), ('offdata', 7, 4),
                               ('offset_min', 11, 1), ('offset_max', 12, 1)]:
        equal('pattern.' + name, field(native, rows, stride, layout['pattern_fields'][name]),
              u32[:, start:start + count])
    for name, start, count in [('length', 0, 3), ('prefix_length', 3, 3), ('parts', 6, 1),
                               ('partno', 7, 1), ('rtype', 8, 1), ('type', 9, 1)]:
        equal('pattern.' + name, field(native, rows, stride, layout['pattern_fields'][name]),
              u16[:, start:start + count])
    for name, offset in [('depth', 72), ('sigopts', 73)]:
        equal('pattern.' + name, field(native, rows, stride, layout['pattern_fields'][name]),
              view(norm, rows, 1, 1, 74, offset))
    equal('generated pattern row IDs (NOT native stored field)', u32[:, 0], np.arange(rows, dtype='u4'))

    rows = schema['logical_records']
    native, norm = raw('native_logical.bin'), raw('logical.bin')
    stride = schema['native_sizes']['logical']
    logical = view(norm, rows, 7, 4, 28)
    for name, column in [('id', 0), ('bc_idx', 1), ('type', 2), ('flag', 3)]:
        equal('logical.' + name, field(native, rows, stride, layout['logical_fields'][name]),
              logical[:, column:column + 1])
    refs = np.fromfile(p / 'logical_objects.bin', dtype='<u4').reshape(rows, 34)
    base = layout['logical_fields']['tdb']['native_offset']
    for name, column, count in [('subsigs', 9, 1), ('cnt', 10, 3)]:
        equal('logical.tdb.' + name, field(native, rows, stride, layout['tdb_fields'][name], base),
              refs[:, column:column + count])

    norm = np.fromfile(p / 'extensions.bin', dtype='<u4').reshape(-1, 14)
    rows, native = len(norm), raw('native_extensions.bin')
    stride = schema['native_sizes']['extension']
    for name, column, count in [('mindist', 3, 1), ('maxdist', 4, 1), ('boundary', 5, 1),
                                ('special', 6, 1), ('special_pattern', 7, 1), ('ch', 8, 2),
                                ('ch_mindist', 10, 2), ('ch_maxdist', 12, 2)]:
        equal('extension.' + name, field(native, rows, stride, layout['extension_fields'][name]),
              norm[:, column:column + count])
    return {'pattern_records': schema['patterns'], 'logical_records': schema['logical_records'],
            'extension_records': rows,
            'exact_native_scalar_comparisons': comparisons - schema['patterns'],
            'generated_row_id_checks': schema['patterns'],
            'all_native_scalar_fields_match_export': True,
            'generated_row_ids_excluded_from_native_savings': True}


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify_capture(args.capture)
    result['checked_table_sha256'] = {
        name: file_hash(args.capture / name)
        for name in ['graph-schema.json', 'native-layout.json', 'patterns.bin',
                     'native_patterns.bin', 'logical.bin', 'logical_objects.bin',
                     'native_logical.bin', 'extensions.bin', 'native_extensions.bin']}
    result['scope'] = 'exact source-native scalar getter values; graph references checked separately'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items()
                      if key != 'checked_table_sha256'}))


if __name__ == '__main__':
    main()
