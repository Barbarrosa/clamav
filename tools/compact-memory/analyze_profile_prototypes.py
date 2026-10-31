#!/usr/bin/env python3
"""Compare exact component profiles without turning layout sums into engine RSS."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import statistics


def lines(path): return [json.loads(s) for s in path.read_text().splitlines() if s.strip()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', type=Path, required=True)
    p.add_argument('--results', type=Path, required=True)
    p.add_argument('--previous', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); done=json.loads((a.results/'completed.json').read_text())
    observations=[]
    for name in done['completed']:
        path = a.results/(name+'.jsonl')
        if hashlib.sha256(path.read_bytes()).hexdigest() != done['observations_sha256'][path.name]:
            raise ValueError('Observation checksum mismatch: '+path.name)
        observations.extend(lines(path))
    exporter=lines(a.data/'export.jsonl')
    core=next(x for x in exporter if 'patterns' in x)
    logical=next(x for x in exporter if x.get('kind')=='logical_export')
    aux=next(x for x in exporter if x.get('kind')=='logical_auxiliary')
    prep=json.loads((a.data/'logical-preparation.json').read_text())
    best={}
    for schema in ('patterns','links','nodes','logical'):
        candidates=[x for x in observations if x.get('kind')=='scalar_layout' and x['schema']==schema]
        assert len(candidates)==3 and all(x['all_fields_verified'] for x in candidates)
        best[schema]=min(candidates,key=lambda x:x['total_bytes'])
    tokens=[x for x in observations if x.get('kind')=='token_blocks']
    assert len(tokens)==6 and all(x['every_token_bytes_verified'] and x['corruption_and_truncation_rejected'] for x in tokens)
    chosen_token=min(tokens,key=lambda x:x['total_layout_bytes'])
    logical_total=best['logical']['total_bytes']+sum(prep[k]['payload_bytes']+prep[k]['index_bytes'] for k in ('templates','programs'))+logical['conservative_escape_record_bytes']+logical['code_pointer_directory_bytes']+aux['retained_escape_value_bytes']
    components={
        'pattern_records':{'old_bytes':core['original_pattern_and_directory_bytes'],'new_bytes':best['patterns']['total_bytes']+core['extension_pointer_directory_bytes']},
        'candidate_links':{'old_bytes':core['original_link_and_directory_bytes'],'new_bytes':best['links']['total_bytes']},
        'logical_records_and_known_auxiliary':{'old_bytes':logical['original_record_and_directory_bytes']+aux['original_known_auxiliary_bytes'],'new_bytes':logical_total},
        'tokens':{'old_bytes':core['token_bytes'],'new_bytes':chosen_token['total_layout_bytes']},
    }
    rng=random.Random(261027);timings=[]
    groups={}
    for row in observations:
        if row['kind']=='scalar_timing': key=('scalar',row['schema'],row['group'],row['input'])
        elif row['kind']=='token_timing': key=('tokens',row['block_bytes'],row['cache_budget'],row['input'])
        else: continue
        groups.setdefault(key,[]).append(row)
    for key, rows in groups.items():
        logs=[math.log(r['packed_seconds']/r['raw_seconds']) for r in rows]
        boot=sorted(math.exp(statistics.mean(rng.choices(logs,k=len(logs)))) for _ in range(2000))
        timings.append({'configuration':key,'paired_geomean_packed_over_raw':math.exp(statistics.mean(logs)),
                        'bootstrap_95pct':[boot[50],boot[1949]],'pairs':len(rows),
                        'raw_median_ns_per_query':statistics.median(r['raw_seconds']/r['queries']*1e9 for r in rows),
                        'packed_median_ns_per_query':statistics.median(r['packed_seconds']/r['queries']*1e9 for r in rows)})
    previous=json.loads(a.previous.read_text())
    if hashlib.sha256((a.data/'names.bin').read_bytes()).hexdigest() != previous['monotone_names']['source_sha256']:
        raise ValueError('The previous name model uses a different database export')
    names=next(r for r in previous['monotone_names']['results'] if r['names_per_block']==64)
    if names['raw_names_bytes'] != core['raw_name_bytes']:
        raise ValueError('Name census mismatch')
    route_bytes=previous['routing']['cyclic_rank']['total_bytes_with_dense_root_fallback']
    # Exact hash-key bytes are from the pinned snapshot's earlier census; they
    # remain stored. This is NOT a membership approximation or a new hash layout.
    digest_bytes=51419900
    fixed=sum(v['new_bytes'] for v in components.values())+best['nodes']['total_bytes']+digest_bytes+route_bytes
    subtotal={mode:fixed+names[f'joint_name_plus_hash_name_links_{mode}_bytes'] for mode in ('cold','expanded')}
    result={'kind':'composable_component_prototypes_not_integrated_scanner', 'best_scalar_layouts':best,
            'token_layouts':tokens,'smallest_token_layout':chosen_token,'components':components,
            'reused_component_bytes':{'exact_digest_keys':digest_bytes,'cyclic_routes':route_bytes,
                'names_and_hash_name_links_cold':names['joint_name_plus_hash_name_links_cold_bytes'],
                'names_and_hash_name_links_expanded':names['joint_name_plus_hash_name_links_expanded_bytes']},
            'combined_component_subtotal_bytes':subtotal, 'timings':timings,
            'limitations':['Component minima are compatible proposed layouts, but have not been integrated together.',
                           'Subtotal reuses the prior cyclic route and modeled name ownership; it is not RSS.',
                           'The token-reference field is included in packed pattern records and is not counted twice.',
                           'Raw names/decoder lifetime, all other matchers, parser state, allocator costs and reload overlap still require whole-engine accounting.',
                           'Microbenchmarks compare normalized record access or token retrieval, not complete scans.',
                           'The original engine remains as an oracle; compiler peak is not reduced by these post-build probes.',
                           'External extension data, special tables, exceptional descriptor payloads and many auxiliary indexes are outside the subtotal.']}
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(a.output)


if __name__ == '__main__': main()
