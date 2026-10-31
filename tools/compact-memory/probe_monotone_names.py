#!/usr/bin/env python3
"""Exact front-coded name blocks with one-way expansion and stable allocations.

This uses ctypes buffers to retain actual stable C addresses after expansion.
Reported sizes are payload/layout accounting, not Python process RSS.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct


def names_from(path):
    with path.open('rb') as f:
        while h := f.read(4):
            if len(h) != 4:
                raise ValueError('truncated header')
            n, = struct.unpack('<I', h)
            s = f.read(n)
            if len(s) != n:
                raise ValueError('truncated string')
            yield s


def encode(block):
    result = bytearray()
    previous = b''
    for s in block:
        prefix = 0
        while prefix < min(len(previous), len(s)) and previous[prefix] == s[prefix]:
            prefix += 1
        suffix = s[prefix:]
        if max(prefix, len(suffix)) > 65535:
            raise ValueError('requires wide escape format')
        result.extend(struct.pack('<HH', prefix, len(suffix)))
        result.extend(suffix)
        previous = s
    return bytes(result)


def decode(blob, count):
    out = bytearray()
    offsets = []
    previous = b''
    pos = 0
    for _ in range(count):
        prefix, n = struct.unpack_from('<HH', blob, pos)
        pos += 4
        if prefix > len(previous) or pos + n > len(blob):
            raise ValueError('bad block')
        s = previous[:prefix] + blob[pos:pos+n]
        pos += n
        offsets.append(len(out)); out.extend(s); out.append(0)
        previous = s
    if pos != len(blob):
        raise ValueError('trailing bytes')
    return bytes(out), offsets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--names', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    names = list(names_from(args.names))
    raw_total = sum(len(s) + 1 for s in names)
    rng = random.Random(261027)
    queries = [rng.randrange(len(names)) for _ in range(10000)]
    reports = []
    for size in (16, 64, 256):
        blocks = []
        for start in range(0, len(names), size):
            members = names[start:start+size]
            blob = encode(members)
            raw = b''.join(s + b'\0' for s in members)
            decoded, offsets = decode(blob, len(members))
            assert raw == decoded
            if len(raw) >= 65536:
                raise ValueError('requires wide offset format')
            # Independent blocks make the old representation individually freeable.
            blocks.append((min(len(blob), len(raw)), len(raw), start, blob if len(blob) < len(raw) else None))
        # Conservative fixed directory: 32 bytes/block, 2 bytes/name for offsets.
        directory = 32 * len(blocks) + 2 * len(names)
        cold = directory + sum(b[0] for b in blocks)
        expanded_bound = directory + raw_total
        expanded = {}
        pointers = []
        live = cold
        peak = live
        checkpoints = []
        for number, name_id in enumerate(queries, 1):
            bid = name_id // size
            if bid not in expanded:
                compressed, raw_len, first, blob = blocks[bid]
                count = min(size, len(names) - first)
                if blob is None:
                    raw = b''.join(s + b'\0' for s in names[first:first+count])
                    offsets, p = [], 0
                    for s in names[first:first+count]: offsets.append(p); p += len(s) + 1
                else:
                    raw, offsets = decode(blob, count)
                # A production decoder can write directly to this final allocation.
                # Current+new raw allocation before retiring the compressed payload.
                peak = max(peak, live + raw_len)
                buf = ctypes.create_string_buffer(raw, raw_len)
                expanded[bid] = (buf, offsets)
                blocks[bid] = (compressed, raw_len, first, None)
                live += raw_len - compressed
            buf, offsets = expanded[bid]
            addr = ctypes.addressof(buf) + offsets[name_id % size]
            assert ctypes.string_at(addr) == names[name_id]
            pointers.append((addr, name_id))
            if number in (1, 100, 1000, 10000):
                checkpoints.append({'uniform_name_queries': number, 'expanded_blocks': len(expanded),
                                    'layout_bytes': live, 'transient_peak_layout_bytes': peak})
        for addr, name_id in pointers:
            assert ctypes.string_at(addr) == names[name_id]
        assert live <= expanded_bound and peak <= expanded_bound + max(b[0] for b in blocks)
        reports.append({'names_per_block': size, 'blocks': len(blocks), 'raw_names_bytes': raw_total,
                        'cold_layout_bytes': cold, 'directory_bytes': directory,
                        'fully_expanded_layout_bytes': expanded_bound,
                        'max_extra_compressed_block_during_expansion': max(b[0] for b in blocks),
                        'every_name_roundtrip_verified': True, 'retained_pointer_checks': len(pointers),
                        'uniform_queries_are_a_model_not_a_workload': checkpoints})
    args.output.write_text(json.dumps({'kind':'monotone_name_expansion_model',
        'source_sha256':hashlib.sha256(args.names.read_bytes()).hexdigest(), 'results':reports,
        'limitations':['Not integrated into ClamAV; no end-to-end timing or allocator RSS measurement.',
                       'Source exports, Python objects and reference strings are retained as an oracle.',
                       'Production needs bounded direct decode, safe concurrent publication, OOM handling and wide fallbacks.',
                       'The fixed directory is included; allocator rounding, locks and compiler scratch are not.',
                       'A first query expands a whole block; exposure of all blocks reaches the raw-size bound.']},indent=2)+'\n')
    print(args.output)


if __name__ == '__main__':
    main()
