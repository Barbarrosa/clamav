#!/usr/bin/env python3
"""Portable exact-value and malformed-image checks of a supplied C probe.

Build probe_field_store.c with ASan/UBSan to make this a sanitizer run. This
script validates its behavior but does not infer compiler instrumentation from
the executable name. It uses only synthetic data and temporary private files.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

import numpy as np

from field_synthesis import (ALIAS_XOR, Candidate, DESC, FieldProblem, HEADER,
                             SPARSE, STORE_XOR, build_image, packed_size,
                             synthesize)


def check_probe(probe, directory):
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')

    def check(image, native, spec, success=True):
        image_path = directory / 'test.fields'
        native_path = directory / 'native.bin'
        schema_path = directory / 'schema.txt'
        image_path.write_bytes(image)
        native_path.write_bytes(native)
        schema_path.write_text(spec)
        command = [str(probe), str(image_path), str(native_path), str(schema_path), '1']
        run = subprocess.run(command, env=environment, capture_output=True,
                             text=True, timeout=30)
        if success:
            if run.returncode:
                raise AssertionError('valid image rejected: ' + run.stderr)
            result = json.loads(run.stdout)
            if result['all_values_verified'] < 1:
                raise AssertionError('valid input was not compared with native values')
        elif run.returncode != 2:
            raise AssertionError('malformed input did not fail with exit 2: ' + run.stderr)
        if 'AddressSanitizer' in run.stderr or 'runtime error:' in run.stderr:
            raise AssertionError('sanitizer finding: ' + run.stderr)

    rng = np.random.default_rng(378)
    rows = 1029
    base = rng.integers(0, 4096, rows, dtype=np.uint64)
    sparse = base.copy()
    sparse[[0, 63, 64, 511, 512, 1023, 1028]] = np.uint64(0xfffffff0)
    pointers = np.arange(rows, dtype=np.uint64) * 32 + np.uint64(0x7fff12345000)
    pointers[::11] = 0
    columns = {'base': base, 'xor': base ^ np.uint64(13),
               'add': base + np.uint64(19), 'zero': np.zeros(rows, np.uint64),
               'row': np.arange(rows, dtype=np.uint64), 'ptr': pointers, 'sparse': sparse}
    result = synthesize(columns, 64, max_depth=16)
    native = np.stack(list(columns.values()), axis=1).astype('<u8').tobytes()
    spec = f'{rows} 56 7\n' + ''.join(f'{i * 8} 8\n' for i in range(7))
    check(result.image, native, spec)
    valid = 1
    for width in [1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64]:
        native_width = next(w for w in [1, 2, 4, 8] if width <= w * 8)
        values = np.array([int(x) & ((1 << width) - 1)
                           for x in rng.integers(0, 2**64 - 1, 139, dtype=np.uint64)],
                          dtype=np.uint64)
        problem = FieldProblem({'x': values}, native_width * 8, max_depth=2)
        candidate = Candidate(STORE_XOR, width, native_width * 8,
                              payload_bytes=packed_size(len(values), width))
        image = build_image(problem, [candidate])
        check(image, values.astype('<u' + str(native_width)).tobytes(),
              f'{len(values)} {native_width} 1\n0 {native_width}\n')
        valid += 1

    malformed = []
    for at, value in [(0, ord('X')), (16, 7), (17, 65), (18, 0), (19, 1)]:
        image = bytearray(result.image)
        image[at] = value
        malformed.append(bytes(image))
    for size in list(range(0, min(200, len(result.image)), 3)) + [len(result.image) - 1]:
        malformed.append(result.image[:size])
    malformed.append(result.image + b'x')
    for index, (candidate, offset) in enumerate(result.store.programs):
        if candidate.op == SPARSE:
            image = bytearray(result.image)
            struct.pack_into('<Q', image, 16 + 32 * index + 24, rows + 1)
            malformed.append(bytes(image))
            image = bytearray(result.image)
            bitmap = (((rows + 7) // 8 + 7) // 8) * 8 + 8
            struct.pack_into('<I', image, offset + bitmap, 1)
            malformed.append(bytes(image))
            break
    cycle = (HEADER.pack(b'FIELDS1\0', 2, 2) +
             DESC.pack(ALIAS_XOR, 0, 64, 0, 1, 0, 0, 0) +
             DESC.pack(ALIAS_XOR, 0, 64, 0, 0, 0, 0, 0))
    check(cycle, bytes(32), '2 16 2\n0 8\n8 8\n', False)
    for image in malformed:
        check(image, native, spec, False)
    return {'valid_cases': valid, 'rejected_malformed_cases': len(malformed) + 1,
            'all_valid_exact_native_fields': True, 'leak_checking': False,
            'instrumentation': 'provided executable; build with ASan/UBSan for a sanitizer run',
            'probe_sha256': hashlib.sha256(probe.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--tempdir', type=Path,
                        help='Optional parent directory for private temporary test files')
    args = parser.parse_args()
    probe = args.probe.resolve()
    if not probe.is_file():
        parser.error('--probe must identify a compiled executable')
    with tempfile.TemporaryDirectory(prefix='field-probe-', dir=args.tempdir) as temporary:
        result = check_probe(probe, Path(temporary))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
