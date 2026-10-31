#!/usr/bin/env python3
"""Exact token interning/byte specialization; keep pattern identity and order.

Trusted diagnostic exports only. Raw signatures are never part of the deliverable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    a = p.parse_args(); d = a.directory
    originals = (d/'tokens.bin').read_bytes()
    patterns = bytearray((d/'patterns.bin').read_bytes())
    unique = {}; strings = []; offsets = []; payload = bytearray(); ids = []
    pos = 0; raw_bytes = 0; wide_count = 0
    while pos < len(originals):
        count, = struct.unpack_from('<I', originals, pos); pos += 4
        token = originals[pos:pos+count*2]; pos += count*2
        if len(token) != count*2: raise ValueError('Truncated tokens')
        raw_bytes += len(token)
        identity = unique.get(token)
        if identity is None:
            identity = len(strings); unique[token] = identity; strings.append(token)
            wide = any(token[1::2])
            encoded = token if wide else token[::2]
            if len(payload)+len(encoded) >= 1 << 31: raise ValueError('Wide offset fallback needed')
            offsets.append(len(payload) | (int(wide) << 31)); payload.extend(encoded)
            wide_count += wide
        ids.append(identity)
    if pos != len(originals) or len(patterns) != len(ids)*74: raise ValueError('Export count mismatch')
    offsets.append(len(payload))
    for i, token in enumerate(strings):
        start, end = offsets[i]&0x7fffffff, offsets[i+1]&0x7fffffff
        encoded = payload[start:end]
        decoded = encoded if offsets[i] >> 31 else b''.join(bytes((x,0)) for x in encoded)
        if decoded != token: raise AssertionError('Token mismatch')
    for i, identity in enumerate(ids):
        old, = struct.unpack_from('<I', patterns, i*74)
        if old != i: raise ValueError('Unexpected original token identity')
        struct.pack_into('<I', patterns, i*74, identity)
    (d/'patterns-interned.bin').write_bytes(patterns)
    (d/'token-data.bin').write_bytes(payload)
    (d/'token-index.bin').write_bytes(struct.pack('<'+'I'*len(offsets), *offsets))
    result = {'patterns':len(ids), 'unique_tokens':len(strings), 'wide_tokens':wide_count,
              'original_token_bytes':raw_bytes, 'encoded_token_bytes':len(payload),
              'index_bytes':len(offsets)*4, 'every_token_verified':True,
              'token_reference_location':'The existing 4-byte token field in each normalized pattern; do not add a second pattern directory.',
              'source_sha256':hashlib.sha256(originals).hexdigest(),
              'limitations':['Offline compiler experiment; dictionary and source are both retained while building.',
                             'Verifier integration must retain prefix boundaries, special tables and all rule metadata.']}
    (d/'token-preparation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
