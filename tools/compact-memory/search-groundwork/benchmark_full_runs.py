#!/usr/bin/env python3
"""Traverse the complete compressed canonical-input view, not the counter.

Run with explicit operating-system CPU/address-space and wall-time limits.
The checksum covers (Boolean, run length) records, not expanded input bytes.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

import canonical_input
import lazy_canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cnf', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--checkpoint-runs', type=int, default=1000000)
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args()
    if args.checkpoint_runs < 1:
        parser.error('checkpoint-runs must be positive')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    raw = args.cnf.read_bytes()
    formula = canonical_input.parse_dimacs(raw.decode('ascii'))
    parsed = time.perf_counter()
    view = lazy_canonical.LazyCanonicalInput(formula)
    indexed = time.perf_counter()
    # Independent grammar sums, not results taken from the view's run iterator.
    expected_runs = (2 if formula.num_variables else 1) + sum(4 * len(c) + 2 for c in formula.clauses)
    expected_ones = formula.num_variables + sum(2 + sum(4 * code + 6 for code in c) for c in formula.clauses)
    base = {
        'schema_version': 1,
        'scope': 'complete RLE traversal of compact canonical-input view; not counting, formal frontend execution or proof of accelerated algorithm equivalence',
        'source_sha256': hashlib.sha256(raw).hexdigest(), 'source_bytes': len(raw),
        'adapter_source_sha256': hashlib.sha256(Path(lazy_canonical.__file__).read_bytes()).hexdigest(),
        'codec_source_sha256': hashlib.sha256(Path(canonical_input.__file__).read_bytes()).hexdigest(),
        'probe_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'probe_source_path': 'tools/compact-memory/search-groundwork/benchmark_full_runs.py',
        'variables': formula.num_variables, 'canonical_clauses': len(formula.clauses),
        'canonical_logical_bits': view.logical_bits,
        'packed_bytes_if_materialized': (view.logical_bits + 7) // 8,
        'index_storage_bytes': view.index_storage_bytes,
        'parse_seconds': parsed - start, 'index_build_seconds': indexed - parsed,
        'expected_runs_from_independent_grammar_sum': expected_runs,
        'expected_one_bits_from_independent_grammar_sum': expected_ones,
        'full_input_materialized': False, 'linked_counting_algorithm_executed': False,
    }
    if sys.platform.startswith('linux'):
        import resource
        base['observed_resource_limits'] = {
            name: {'soft': None if soft == resource.RLIM_INFINITY else soft,
                   'hard': None if hard == resource.RLIM_INFINITY else hard}
            for name, (soft, hard) in (
                ('address_space_bytes', resource.getrlimit(resource.RLIMIT_AS)),
                ('cpu_seconds', resource.getrlimit(resource.RLIMIT_CPU)))}
    digest = hashlib.sha256()
    runs = logical = ones = 0
    last = None

    def save(status):
        record = {**base, 'status': status, 'runs_visited': runs,
                  'logical_bits_covered': logical, 'one_bits_covered': ones,
                  'rle_stream_sha256': digest.hexdigest(),
                  'rle_hash_encoding': 'concatenated little-endian <?Q records (Boolean, uint64 run length)',
                  'traversal_seconds': time.perf_counter() - indexed,
                  'total_seconds': time.perf_counter() - start}
        if sys.platform.startswith('linux'):
            usage = resource.getrusage(resource.RUSAGE_SELF)
            record.update(process_highwater_rss_bytes=usage.ru_maxrss * 1024,
                          process_user_cpu_seconds=usage.ru_utime,
                          process_system_cpu_seconds=usage.ru_stime)
        if status == 'complete':
            record['independent_grammar_totals_match'] = (
                runs == expected_runs and ones == expected_ones and logical == view.logical_bits)
            record['exit_status'] = 'normal_completion'
        next_path = args.report.with_suffix(args.report.suffix + '.next')
        next_path.write_text(json.dumps(record, indent=2) + '\n')
        next_path.replace(args.report)

    save('running')
    for bit, length in view.iter_runs():
        if last is not None and bit == last:
            raise AssertionError('uncoalesced adjacent equal runs')
        last = bit
        if length >= 1 << 64:
            raise ValueError('benchmark checksum transport requires uint64 run lengths')
        digest.update(struct.pack('<?Q', bit, length))
        runs += 1
        logical += length
        if bit:
            ones += length
        if runs % args.checkpoint_runs == 0:
            save('running')
            if not args.quiet:
                print(json.dumps({'runs': runs, 'logical_bits': logical}), flush=True)
    if logical != view.logical_bits or runs != expected_runs or ones != expected_ones:
        raise AssertionError('complete traversal differs from independent grammar totals')
    save('complete')
    print(json.dumps({'status': 'complete', 'runs': runs, 'logical_bits': logical,
                      'rle_stream_sha256': digest.hexdigest()}), flush=True)


if __name__ == '__main__':
    main()
