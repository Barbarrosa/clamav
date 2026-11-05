#!/usr/bin/env python3
"""Test joint token choices across candidate pools and exact lookup-work bounds.

Public literal fixtures and synthetic tagged bytes only; no compiled database.
SPDX-License-Identifier: GPL-2.0-only
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

from common import BooleanModel
from joint_token_dictionary import Problem, candidate_fragments, decode_image

ROOT = Path(__file__).resolve().parents[3]


def fixture_rows():
    rows, references, provenance = [], [], []
    for path in sorted((ROOT / 'unit_tests/input/pe_allmatch/alert-sigs').glob('*.ndb')):
        provenance.append({'path': str(path.relative_to(ROOT)),
                           'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        for line in path.read_text().splitlines():
            parts = line.split(':')
            if len(parts) < 4 or not re.fullmatch(r'(?:[a-fA-F0-9]{2})+', parts[3]):
                continue
            row = bytes.fromhex(parts[3])
            if row not in rows:
                rows.append(row)
            references.append((parts[0], parts[1], rows.index(row), row))
    return rows, references, provenance


def diverse_candidates(rows, limit=64, maximum=32):
    """Reserve equal candidate slots for short and long fragments.

    This filter is heuristic; the optimizer is exact only inside its output.
    """
    counts = Counter()
    for row in rows:
        for start in range(len(row)):
            for length in range(3, min(maximum, len(row) - start) + 1):
                counts[row[start:start + length]] += 1
    ranking = sorted((f for f in counts if counts[f] >= 2),
                     key=lambda f: (-(counts[f] * (len(f) - 2) - len(f) - 4), -len(f), f))
    selected = []
    for low, high in [(3, 4), (5, 8), (9, 16), (17, 32)]:
        selected.extend([f for f in ranking if low <= len(f) <= high][:limit // 4])
    for fragment in ranking:
        if len(selected) >= limit:
            break
        if fragment not in selected:
            selected.append(fragment)
    return selected[:limit]


def run(output, probe=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    public, references, provenance = fixture_rows()
    generic_ids = sorted({r[2] for r in references if r[1] == '0'})
    tagged = [struct.pack('<7H', 0x0102, 0x8000, 0xFFFF, 0x0041, 0x1000, 0x0102, i)
              for i in range(8)]
    inputs = [('public_unique_literals', public, [False] * len(public)),
              ('public_generic_literal_subset', [public[i] for i in generic_ids], [False] * len(generic_ids)),
              ('synthetic_tagged_tokens', tagged, [True] * len(tagged))]
    cases = []
    for label, rows, widths in inputs:
        for pool_name, pool in [('frequency', candidate_fragments(rows, 64, 32)),
                                ('length_diverse', diverse_candidates(rows))]:
            bound_values = [max(map(len, rows), default=0),
                            max(map(len, rows), default=0) + 8, None]
            for bound in bound_values:
                start = time.perf_counter()
                problem = Problem(rows, widths=widths, candidates=pool,
                                  max_decode_steps=bound)
                encoding_seconds = time.perf_counter() - start
                start = time.perf_counter()
                optimal = problem.solve()
                solve_seconds = time.perf_counter() - start
                raw, greedy = problem.fixed_dictionary([]), problem.greedy()
                recovered, flags = decode_image(optimal.to_bytes(), bound)
                assert recovered == rows and flags == widths
                if label == 'public_unique_literals':
                    assert all(recovered[ref] == source for _, _, ref, source in references)
                candidate_work = max((r.decoded_length + (0 if r.raw else len(r.payload) // 2)
                                      for r in optimal.rows), default=0)
                if bound is not None:
                    assert candidate_work <= bound
                result = {'input': label, 'candidate_pool': pool_name,
                          'candidate_count': len(pool), 'rows': len(rows),
                          'source_bytes': sum(map(len, rows)), 'max_work_budget': bound,
                          'observed_max_modeled_work': candidate_work,
                          'raw_image_bytes': raw.total_bytes, 'greedy_image_bytes': greedy.total_bytes,
                          'optimal_image_bytes': optimal.total_bytes,
                          'selected_dictionary_entries': len(optimal.dictionary),
                          'scratch_bytes': optimal.scratch_bytes,
                          'cold_image_bytes': optimal.total_bytes,
                          'hydrated_image_bytes': optimal.total_bytes,
                          'two_generation_image_and_scratch_bytes': 2 * (optimal.total_bytes + optimal.scratch_bytes),
                          'encoding_seconds': encoding_seconds, 'solve_seconds': solve_seconds,
                          'variables': problem.nv, 'hard_clauses': len(problem.hard),
                          'all_bytes_widths_and_original_references_verified': True}
                if probe and label == 'public_unique_literals' and bound is None:
                    native = {}
                    for mode, layout in [('raw', raw), ('optimal', optimal)]:
                        image = output / f'tokens-{pool_name}-{mode}.bin'
                        image.write_bytes(layout.to_bytes())
                        command = [str(Path(probe).resolve()), str(image.resolve()), '20000']
                        native[mode] = json.loads(subprocess.check_output(command, text=True))
                    assert native['raw']['decoded_checksum'] == native['optimal']['decoded_checksum']
                    result['native'] = native
                cases.append(result)
    # Small same-formulation witness: full CNF audit would otherwise dominate the
    # experiment. Both budgets reconstruct exactly or prove infeasibility.
    witness = Problem([b'abcdefgh'] * 4, candidates=[b'abcdefgh'])
    witness_layout = witness.solve()
    model = BooleanModel()
    model.hard, model.costs, model.nv = witness.hard, witness.costs, witness.nv
    audit = model.verify_budget(witness_layout.objective_bytes,
                                output / 'tokens-feasibility')
    result = {'experiment': 'joint token dictionaries', 'cases': cases,
              'feasibility_audit': audit,
              'feasibility_audit_scope': 'four 8-byte rows and one candidate; same encoding as primary experiments',
              'original_public_rule_references_preserved': len(references),
              'public_sources': provenance,
              'scope': 'public literal and synthetic byte rows; not full or PDF/JPEG/PNG with PE exclusions compiled exports',
              'solver': 'conventional RC2 and Minisat22; linked counting construction not executed'}
    (output / 'tokens.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--probe', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.probe)))
