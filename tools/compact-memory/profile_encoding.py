#!/usr/bin/env python3
"""Measure lossless token sharing and name front coding; not scanner RAM."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def records(path, width=1):
    with path.open('rb') as stream:
        while header := stream.read(4):
            if len(header) != 4:
                raise ValueError('truncated header')
            length, = struct.unpack('<I', header)
            data = stream.read(length * width)
            if len(data) != length * width:
                raise ValueError('truncated record')
            yield data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--names', type=Path, required=True)
    parser.add_argument('--tokens', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    names = list(records(args.names))
    assert names == sorted(set(names))
    name_results = []
    for block in (1, 8, 16, 32):
        encoded, max_chain = 0, 0
        previous = b''
        for i, name in enumerate(names):
            prefix = 0
            if i % block:
                while prefix < min(len(name), len(previous)) and name[prefix] == previous[prefix]:
                    prefix += 1
            # uint16 prefix + uint16 suffix length, then suffix (including NUL).
            assert prefix < 65536 and len(name) - prefix < 65536
            suffix = name[prefix:]
            assert previous[:prefix] + suffix == name
            encoded += 4 + len(suffix) + 1
            max_chain = max(max_chain, i % block + 1)
            previous = name
        name_results.append({'restart_every': block, 'payload_bytes': encoded,
                             'block_offsets_bytes': 4 * ((len(names) + block - 1) // block + 1),
                             'maximum_strings_decoded_per_lookup': max_chain})
    total = count = 0
    unique = set()
    for data in records(args.tokens, 2):
        total += len(data)
        count += 1
        unique.add(data)
    raw_unique = sum(map(len, unique))
    byte_specialized = sum(len(data) // 2 if not any(data[1::2]) else len(data) for data in unique)
    report = {'kind': 'encoding_feasibility_not_scanner',
              'names': len(names), 'name_raw_with_nul': sum(len(n) + 1 for n in names),
              'front_coding': name_results,
              'tokens': {'records': count, 'raw_bytes': total, 'distinct': len(unique),
                         'distinct_raw_bytes': raw_unique,
                         'distinct_byte_specialized_payload': byte_specialized,
                         'per_pattern_u32_ref_bytes': count * 4,
                         'per_distinct_u32_offset_bytes': (len(unique) + 1) * 4},
              'inputs': {str(p.name): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in (args.names, args.tokens)},
              'limitations': 'Metadata, flags, alignment, special tables, decoder workspaces, '
                             'stable decoded name storage, compilation and scan costs excluded.'}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
