#!/usr/bin/env python3
"""Intern exact eligible target templates and expression bytes; retain escapes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def entries(path):
    data = path.read_bytes(); pos = 0
    while pos < len(data):
        n, = struct.unpack_from('<I', data, pos); pos += 4
        if n > len(data)-pos: raise ValueError('Truncated entry')
        yield data[pos:pos+n]; pos += n


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('directory', type=Path)
    a = p.parse_args(); d = a.directory
    rows = bytearray((d/'logical.bin').read_bytes())
    if len(rows)%28: raise ValueError('Truncated logical header')
    result = {'logical_records':len(rows)//28, 'all_nonempty_entries_verified':True}
    for filename, column in [('templates',6),('programs',5)]:
        table = {}; distinct = []; payload = bytearray(); offsets = []; count = 0; before = 0; empty = 0
        for i, value in enumerate(entries(d/(filename+'.bin'))):
            count += 1; before += len(value)
            old, = struct.unpack_from('<I', rows, i*28+column*4)
            if not value:
                empty += 1
                if not old >> 31: raise ValueError('Missing escape')
                continue
            if old != i: raise ValueError('Unexpected header ID')
            new = table.get(value)
            if new is None:
                new = len(distinct); table[value] = new; distinct.append(value)
                offsets.append(len(payload)); payload.extend(value)
            struct.pack_into('<I', rows, i*28+column*4, new)
        if count != len(rows)//28: raise ValueError('Count mismatch')
        offsets.append(len(payload))
        if len(payload) >= 1 << 31: raise ValueError('Wide format needed')
        for i, value in enumerate(distinct):
            if payload[offsets[i]:offsets[i+1]] != value: raise AssertionError('Round trip mismatch')
        (d/(filename+'-data.bin')).write_bytes(payload)
        (d/(filename+'-index.bin')).write_bytes(struct.pack('<'+'I'*len(offsets),*offsets))
        result[filename] = {'original_eligible_payload_bytes':before,'unique_entries':len(distinct),
                            'payload_bytes':len(payload),'index_bytes':len(offsets)*4,'escapes':empty,
                            'source_sha256':hashlib.sha256((d/(filename+'.bin')).read_bytes()).hexdigest()}
    (d/'logical-interned.bin').write_bytes(rows)
    result['limitations'] = ['Templates cover the explicitly checked scalar/range subset; all other target descriptors retain original representations.',
                            'No Boolean rewrite of expressions and no reordering of logical signatures.',
                            'Scanner integration and compiler peak remain unqualified.']
    (d/'logical-preparation.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result))


if __name__ == '__main__': main()
