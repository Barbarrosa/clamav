#!/usr/bin/env python3
"""Reproduce research layout calculations from the saved ClamAV evidence.

Usage: python3 remaining_memory_calculations.py --source PATH/TO/source --output result.json
These are payload calculations, not implementations or RSS measurements.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path


def elias_fano(n, universe, old_bytes, flag_bits=0):
    low = math.floor(math.log2(universe / n))
    exact_bits = n * low + n + (universe >> low) + 1
    bound_bits = n * (math.ceil(math.log2(universe / n)) + 2)
    return {
        'entries': n, 'universe_upper': universe, 'low_bits': low,
        'old_bytes': old_bytes,
        'proposed_base_bytes': math.ceil(bound_bits / 8) + math.ceil(flag_bits / 8),
        'tighter_base_bytes': math.ceil(exact_bits / 8) + math.ceil(flag_bits / 8),
        'flag_bits': flag_bits,
        'excludes': 'select support, alignment and decoder metadata',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    docs = args.source / 'docs'
    census_path = docs / 'frontier-results/encoding-census.jsonl'
    profile_path = docs / 'profile-prototype-results/profile-summary.json'
    correlation_path = docs / 'correlation-results/correlation-summary.json'
    token_path = docs / 'profile-prototype-results/token-preparation.json'
    rows = [json.loads(line) for line in census_path.read_text().splitlines()]
    hashes = [row for row in rows if row['kind'] == 'hash']
    ac = [row for row in rows if row['kind'] == 'ac']
    profile = json.loads(profile_path.read_text())
    tokens = json.loads(token_path.read_text())
    names = next(row for row in rows if row['kind'] == 'resident_floor_components')
    name_count, name_bytes = names['unique_names'], names['unique_name_bytes']
    token_count, token_bytes = tokens['unique_tokens'], tokens['encoded_token_bytes']
    name_id_bits = name_count.bit_length()
    name_model = next(row for row in json.loads(correlation_path.read_text())['monotone_names']['results']
                      if row['names_per_block'] == 64)
    n = sum(row['items'] for row in hashes)
    buckets = sum(row['size_buckets'] for row in hashes)
    groups = sum(row['size_buckets'] > 0 for row in hashes)
    metadata = sum(row['metadata_capacity_bytes'] for row in hashes)
    items = {
        'hash_bucket_metadata': {
            'old_bytes': metadata, 'proposed_base_bytes': 8 * buckets + 4 * groups,
            'buckets': buckets, 'groups': groups,
            'method': 'uint32 size keys and bucket starts; per-group sentinel included',
            'excludes': 'optional search index and group/wildcard descriptors',
        },
        'hash_name_ids': {
            'old_bytes': n * 4, 'proposed_base_bytes': math.ceil(n * name_id_bits / 8),
            'records': n, 'method': f'{name_id_bits}-bit exact name IDs; reserved code remains available',
        },
        'name_offsets': elias_fano(name_count, name_bytes, name_count * 2),
        'token_offsets': elias_fano(token_count + 1, token_bytes + 1, tokens['index_bytes'], token_count),
    }
    for item in items.values():
        item['gross_bytes_saved'] = item['old_bytes'] - item['proposed_base_bytes']
    gross = sum(item['gross_bytes_saved'] for item in items.values())
    unchanged_extra = {key: sum(row[key] for row in ac)
                       for key in ('extension_bytes', 'filter_bytes')}
    subtotals = {
        mode: {
            'prior_partial_bytes': value,
            'with_previously_omitted_hash_metadata_bytes': value + metadata,
            'proposed_partial_base_bytes': value + metadata - gross,
            'with_known_extensions_and_filters_bytes': value + metadata - gross + sum(unchanged_extra.values()),
        }
        for mode, value in profile['combined_component_subtotal_bytes'].items()
    }
    token_ceiling = profile['smallest_token_layout']['total_layout_bytes']
    dictionary_models = []
    for dictionary_bytes in (1048576, 1310720):
        dictionary_models.append({
            'dictionary_data_and_offsets_budget_bytes': dictionary_bytes,
            'code_bytes': 2, 'worker_scratch_bytes': 8000,
            'max_average_codes_existing_index': (token_ceiling - dictionary_bytes - tokens['index_bytes'] - 8000) / (2 * token_count),
            'max_average_codes_succinct_index': (token_ceiling - dictionary_bytes - items['token_offsets']['proposed_base_bytes'] - 8000) / (2 * token_count),
            'scope': 'Algebraic break-even; codec headers, padding and actual select index must also fit.',
        })
    md5 = sum(row['items'] for row in hashes if row['type'] == 0)
    ideal_savings = math.lgamma(md5 + 1) / math.log(2) / 8
    result = {
        'source_revision': '2c464040eddf2c04951a21e6277f16823f5e5bf8',
        'classification': 'Research calculations from existing evidence; no new codec or engine measurements',
        'items': items, 'gross_savings_bytes': gross, 'partial_subtotals': subtotals,
        'additional_unchanged_payloads': unchanged_extra,
        'token_codec': {'unique_sequences': token_count, 'mean_raw_sequence_bytes': token_bytes / token_count,
                        'break_even_models': dictionary_models},
        'ideal_md5_set_model': {
            'records': md5, 'raw_key_bytes': md5 * 16, 'approximate_saved_bytes': ideal_savings,
            'approximate_encoded_bytes': md5 * 16 - ideal_savings,
            'assumptions': 'One set of distinct uniform 128-bit keys; excludes bucket membership, duplicates, values, indexes and construction; not a universal corpus lower bound.',
        },
        'mapped_names_model': {
            'raw_name_bytes': name_bytes,
            'fixed_index_and_id_base_bytes': items['name_offsets']['proposed_base_bytes'] + items['hash_name_ids']['proposed_base_bytes'],
            'removed_block_descriptor_bytes': name_model['directory_bytes'] - name_count * 2,
            'formula': 'fixed base + actual charged name pages W + select support, page tables and other overhead',
            'cold_caveat': 'Creation and verification can charge all file pages; no zero-residency assumption.',
        },
        'inputs_sha256': {str(path.relative_to(docs)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (census_path, profile_path, correlation_path, token_path)},
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
