#!/usr/bin/env python3
"""Aggregate the correlation probes without treating component bytes as RSS."""
import argparse
import json
import math
from pathlib import Path
import random
import statistics


def lines(path): return [json.loads(s) for s in path.read_text().splitlines() if s.strip()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--research', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); root = a.research
    data = lines(root / 'transition-factoring.jsonl')
    assert data[-1]['kind'] == 'complete'
    census = lines(root / 'encoding-census.jsonl')
    active = [r for r in census if r['kind'] == 'ac' and r['nodes']]
    inactive_bytes = sum(r['transition_bytes'] for r in census if r['kind'] == 'ac' and not r['nodes'])
    results = {}
    for kind, field in [('cyclic_rank','bytes'), ('microblocks','bytes_including_state_row_map')]:
        best = []
        for row in active:
            candidates = [r for r in data if r['kind'] == kind and r['target'] == row['target']]
            assert len(candidates) == (6 if kind == 'cyclic_rank' else 4)
            chosen = min(candidates, key=lambda r:r[field])
            best.append({'target':row['target'], 'old_bytes':row['transition_bytes'],
                         'chosen':chosen, 'selected_bytes':min(chosen[field],row['transition_bytes'])})
        results[kind] = {'per_target':best, 'total_bytes_with_dense_root_fallback':inactive_bytes + sum(r['selected_bytes'] for r in best)}
    rng = random.Random(261027); timings = []
    for case in range(3):
        rows = [r for r in data if r['kind'] == 'cyclic_timing' and r['input'] == case]
        assert len(rows) == 10
        logs = [math.log(r['cyclic_seconds']/r['dense_seconds']) for r in rows]
        boot = sorted(math.exp(statistics.mean(rng.choices(logs,k=len(logs)))) for _ in range(5000))
        timings.append({'input':case, 'dense_median_seconds':statistics.median(r['dense_seconds'] for r in rows),
                        'cyclic_median_seconds':statistics.median(r['cyclic_seconds'] for r in rows),
                        'paired_cyclic_over_dense':math.exp(statistics.mean(logs)), 'bootstrap_95pct':[boot[125],boot[4874]]})
    zero = lines(root / 'zero-default.jsonl'); zero_summary = []
    for percent in (0,1,10,100):
        z={'page_write_percent':percent}
        for mode in (0,1):
            sample=[r for r in zero if r['page_write_percent']==percent and r['encoded']==mode]
            assert len(sample)==3 and all(r['every_slot_verified'] for r in sample)
            z['encoded' if mode else 'original']={'median_rss_growth_kib':statistics.median(r['after_writes_rss_kib']-r['start_rss_kib'] for r in sample)}
        zero_summary.append(z)
    names = json.loads((root / 'monotone-names.json').read_text())
    hash_count = sum(r['items'] for r in census if r['kind']=='hash')
    for r in names['results']:
        r['joint_name_plus_hash_name_links_original_bytes'] = r['raw_names_bytes'] + hash_count * 8
        r['joint_name_plus_hash_name_links_cold_bytes'] = r['cold_layout_bytes'] + hash_count * 4
        r['joint_name_plus_hash_name_links_expanded_bytes'] = r['fully_expanded_layout_bytes'] + hash_count * 4
    result={'kind':'cross_domain_component_research', 'routing':results, 'cyclic_timings':timings,
            'zero_default':zero_summary, 'monotone_names':names, 'evidence_runs':json.loads((root/'evidence-runs.json').read_text()),
            'limitations':['None of these representations is integrated into the scanner.',
                           'Cyclic lookup regresses on repetitive input; it fails the no-performance-compromise gate.',
                           'Timing is an isolated ten-pair experiment on a shared host.',
                           'Payload/layout sizes exclude allocator rounding; zero-default RSS is for fresh anonymous mappings only.',
                           'Name plus hash-link figures are a joint layout calculation, not a measured engine.']}
    a.output.write_text(json.dumps(result,indent=2)+'\n'); print(a.output)


if __name__ == '__main__': main()
