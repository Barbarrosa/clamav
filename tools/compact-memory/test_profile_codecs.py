#!/usr/bin/env python3
"""Reproducible boundary/error tests for the standalone exact-layout codecs.

Pass sanitizer-built binaries to exercise the same cases under ASan/UBSan.
This does not qualify a ClamAV scanner integration or an untrusted file format.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scalar', type=Path, required=True)
    parser.add_argument('--blocks', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    scalar, blocks = str(args.scalar.resolve()), str(args.blocks.resolve())
    scalar_result = subprocess.run([scalar, '--selftest'], check=True,
                                   text=True, capture_output=True)
    if scalar_result.stderr:
        raise RuntimeError(scalar_result.stderr)
    rng = random.Random(261027)
    lengths = [0, 1, 2, 63, 64, 4095, 4096, 4097, 65535, 131070, 262140]
    payload = bytearray()
    offsets = []
    for i, length in enumerate(lengths):
        offsets.append(len(payload))
        payload.extend(bytes([i])*length if i % 2 == 0 else rng.randbytes(length))
    offsets.append(len(payload))
    index = struct.pack('<'+'I'*len(offsets), *offsets)
    with tempfile.TemporaryDirectory(prefix='clamav-exact-codecs-') as temporary:
        folder = Path(temporary)
        data_path, index_path = folder/'data.bin', folder/'index.bin'
        data_path.write_bytes(payload)
        index_path.write_bytes(index)
        command = [blocks, str(data_path), str(index_path), '4096', '8192', '3']
        success = subprocess.run(command, check=True, text=True, capture_output=True)
        if success.stderr:
            raise RuntimeError(success.stderr)
        layout = json.loads(success.stdout.splitlines()[0])
        if not layout['every_token_bytes_verified'] or not layout['corruption_and_truncation_rejected']:
            raise AssertionError('Missing exactness or error-path checks')
        # Reject malformed indexes before any compression or token retrieval.
        bad_indexes = []
        for position, value in [(0, 1), (len(offsets)-1, len(payload)+1),
                                (3, 0), (1, 0x80000000)]:
            bad = list(offsets)
            bad[position] = value
            bad_indexes.append(struct.pack('<'+'I'*len(bad), *bad))
        # A single oversized token exceeds the maximum two uint16-length arrays.
        bad_indexes.append(struct.pack('<II', 0, len(payload)))
        bad_indexes.append(index[:-1])
        for bad in bad_indexes:
            index_path.write_bytes(bad)
            result = subprocess.run(command, text=True, capture_output=True)
            if result.returncode != 2 or result.stderr:
                raise AssertionError((result.returncode, result.stderr))
    result = {
        'scalar': json.loads(scalar_result.stdout),
        'token_boundary_lengths': lengths,
        'tokens_roundtrip_verified': True,
        'checksum_truncation_decoded_length_and_range_failures_rejected': True,
        'malformed_indexes_rejected': len(bad_indexes),
        'synthetic_data_sha256': hashlib.sha256(payload).hexdigest(),
        'synthetic_index_sha256': hashlib.sha256(index).hexdigest(),
        'scope': 'Standalone codecs; not a scanner differential test or general malformed-file fuzzer.'
    }
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
