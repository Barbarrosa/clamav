#!/usr/bin/env python3
"""Summarize standalone encoding/routing experiments, never whole-scanner RAM."""
import argparse
import json
import math
from pathlib import Path
import random
import statistics


def jsonlines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--census', type=Path, required=True)
    parser.add_argument('--encoding', type=Path, required=True)
    parser.add_argument('--routing', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    census = jsonlines(args.census)
    encoding = json.loads(args.encoding.read_text())
    routing = jsonlines(args.routing)
    sizes = [r for r in routing if r['kind'] == 'routing_size']
    ac = [r for r in census if r['kind'] == 'ac']
    expected = {r['target'] for r in ac if r['nodes']}
    if {r['target'] for r in sizes} != expected or len(sizes) != len(expected):
        raise ValueError('incomplete or duplicated routing experiment')
    if not all(r['all_24bit_keys_verified'] for r in sizes):
        raise ValueError('unverified routing output')
    trials = [r for r in routing if r['kind'] == 'routing_trial']
    rng = random.Random(261027)
    timing = {}
    for case in range(3):
        rows = [r for r in trials if r['input'] == case]
        if len(rows) != 30 or {r['trial'] for r in rows} != set(range(30)):
            raise ValueError('incomplete or duplicated paired trials')
        logs = [math.log(r['directory_seconds'] / r['dense_seconds']) for r in rows]
        boot = sorted(math.exp(statistics.mean(rng.choices(logs, k=len(logs))))
                      for _ in range(5000))
        timing[str(case)] = {
            'case': ('random', 'zeros', 'repeated_0_to_255')[case],
            'dense_median_seconds': statistics.median(r['dense_seconds'] for r in rows),
            'directory_median_seconds': statistics.median(r['directory_seconds'] for r in rows),
            'paired_geomean_directory_over_dense': math.exp(statistics.mean(logs)),
            'paired_bootstrap_95pct': [boot[125], boot[4874]],
        }
    original = sum(r['transition_bytes'] for r in ac)
    # Roots without nodes are left unchanged. The selection itself is not
    # implemented in the production engine; this sums its measured components.
    saved = sum(max(0, r['rows_bytes'] - r['directory_bytes']) for r in sizes)
    tokens = encoding['tokens']
    encoded_tokens = (tokens['distinct_byte_specialized_payload'] +
                      tokens['per_pattern_u32_ref_bytes'] +
                      tokens['per_distinct_u32_offset_bytes'])
    hashes = sum(r['payload_bytes'] - r['items'] * 8 for r in census if r['kind'] == 'hash')
    boundary = encoding['name_raw_with_nul'] + encoded_tokens + hashes
    report = {
        'kind': 'component_experiments_not_integrated_scanner',
        'routing': {'active_targets': len(sizes), 'keys_checked_per_target': 1 << 24,
                    'original_transition_bytes': original,
                    'hybrid_transition_bytes': original - saved,
                    'transition_bytes_saved': saved,
                    'selected_directory_targets': [r['target'] for r in sizes
                                                   if r['directory_bytes'] < r['rows_bytes']],
                    'pe_lookup_timings': timing},
        'tokens': {'original_bytes': tokens['raw_bytes'],
                   'encoded_bytes_including_two_indexes': encoded_tokens,
                   'saved_before_flags_alignment_and_metadata': tokens['raw_bytes'] - encoded_tokens},
        'chosen_representation_floor': {'raw_stable_names_bytes': encoding['name_raw_with_nul'],
                                        'exact_digest_keys_bytes': hashes,
                                        'encoded_token_bytes': encoded_tokens,
                                        'subtotal_bytes': boundary,
                                        'subtotal_mib': boundary / 1048576},
        'limitations': [
            'Routing oracle and outputs remain resident in the probe; these are table bytes, not RSS.',
            'Long-stream state comparisons and timing cover three 8 MiB PE streams, not all inputs.',
            'Routing timing excludes filters, candidates, verification, parsing and output work.',
            'Encoded tokens omit flags, alignment, auxiliary tables, compiler and verifier costs.',
            'Stable decoded name memory is excluded from compressed-name sizes.',
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
