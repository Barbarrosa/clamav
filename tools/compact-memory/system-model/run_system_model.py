#!/usr/bin/env python3
"""Synthesize GET programs for a real compiled engine's typed object graph.

Raw snapshots and images remain private. Public output contains counts, hashes,
sanitized program descriptions, and explicitly partial payload accounting.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from collections import Counter
from dataclasses import asdict
import gc
import hashlib
import json
import math
from pathlib import Path
import platform
import struct
import subprocess
import sys
import time

import numpy as np
import pysat
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

from capture import load_capture
from field_synthesis import (DESC, HEADER, FieldStore, Synthesis, build_image,
                             synthesize)

ROOT = Path(__file__).resolve().parents[3]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        while block := source.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError('raw captures and generated images require private directories')
    return path


def write_locator(addresses, path):
    """Explicit source-identity -> row resolver; never a free diagnostic oracle.

    Stored source keys and row IDs are needed by an address-based GET provider.
    We keep original engine directories separately, and charge this additional
    directory in full. Binary search adds work outside field-program depth.
    """
    addresses = np.asarray(addresses, dtype=np.uint64)
    if np.any(addresses == 0) or len(addresses) >= 1 << 32:
        raise ValueError('invalid identity locator')
    order = np.argsort(addresses, kind='stable')
    keys = addresses[order]
    if len(keys) > 1 and np.any(keys[1:] == keys[:-1]):
        raise ValueError('nonunique source identity')
    with Path(path).open('wb') as out:
        out.write(struct.pack('<8sII', b'OBJMAP1\0', len(keys), 0))
        out.write(keys.astype('<u8').tobytes())
        out.write(order.astype('<u4').tobytes())
    # Independently query every key and verify its original row coordinate.
    found = np.searchsorted(keys, addresses)
    if not np.array_equal(order[found], np.arange(len(addresses))):
        raise AssertionError('identity resolver does not reproduce original rows')
    return {'bytes': 16 + 12 * len(keys), 'objects': len(keys),
            'identity_queries_verified': len(keys),
            'maximum_binary_search_key_and_index_reads': 2 * math.ceil(math.log2(len(keys) + 1)) + 1,
            'sha256': digest(path)}


def system_selection(families, results, retained_bytes, private, budget=None):
    """Solve one combined model containing EVERY field-program variable.

    Native-provider alternatives gate each family's complete encoding. The
    resulting model chooses field dependencies and physical payloads, rather
    than selecting only previously solved per-family images.
    """
    formula = WCNF()
    top, positions = 0, []
    for family, result in zip(families, results):
        native, encoded = top + 1, top + 2
        offset = top + 2
        top = offset + result.problem.nv
        positions.append((native, encoded, offset))
        formula.append([native, encoded])
        formula.append([-native, -encoded])
        for clause in result.problem.hard:
            translated = [(v + offset if v > 0 else v - offset) for v in clause]
            formula.append([-encoded] + translated)
        for var, weight in result.problem.costs:
            formula.append([-(var + offset), encoded])
            if weight:
                formula.append([-(var + offset)], weight=weight)
        fixed = HEADER.size + DESC.size * len(result.problem.names) + family['identity_locator_bytes']
        for literal, cost in [(native, family['native_record_bytes']), (encoded, fixed)]:
            if cost:
                formula.append([-literal], weight=cost)
    started = time.perf_counter()
    with RC2(formula) as solver:
        model = solver.compute()
        if model is None:
            raise AssertionError('native providers must remain feasible')
        chosen = {v for v in model if v > 0}
        variable_bytes = solver.cost
    solve_seconds = time.perf_counter() - started
    formula_path = private / 'system.wcnf'
    formula.to_file(str(formula_path))
    witness_path = private / 'system.model.json'
    witness_path.write_text(json.dumps(model) + '\n')
    # Private mapping completes the path from a solver assignment to executable
    # GET descriptors. It contains original pointer constants and stays private.
    mapping = []
    for family, result, (native, encoded, offset) in zip(families, results, positions):
        mapping.append({'family': family['family'], 'native_variable': native,
                        'synthesized_variable': encoded,
                        'fields': [{'name': name, 'options': [dict(variable=v + offset, program=asdict(c))
                                    for c, v in zip(options, variables)]}
                                   for name, options, variables in zip(result.problem.names,
                                           result.problem.candidates, result.problem.selection)]})
    map_path = private / 'system.candidates.json'
    map_path.write_text(json.dumps(mapping) + '\n')
    expected = sum(min(f['native_record_bytes'], f['synthesized_provider_bytes']) for f in families)
    if variable_bytes != expected:
        raise AssertionError('combined model disagrees with independent family lower bounds')
    selected, added = {}, 0
    for family, result, (native, encoded, offset) in zip(families, results, positions):
        label = family['family']
        selected[label] = 'native' if native in chosen else 'synthesized'
        if encoded in chosen:
            programs = [next(c for c, v in zip(options, variables) if v + offset in chosen)
                        for options, variables in zip(result.problem.candidates, result.problem.selection)]
            image = build_image(result.problem, programs)
            reconstructed = Synthesis(result.problem, programs, image,
                                      FieldStore(image, result.problem.names, result.problem.max_depth),
                                      sum(p.payload_bytes for p in programs), {})
            if len(image) != result.total_bytes:
                raise AssertionError('combined witness has a different family optimum')
            # Revalidate the actual globally selected witness, including ties.
            for name, original in zip(result.problem.names, result.problem.columns):
                if not np.array_equal(reconstructed.reconstruct(name), original):
                    raise AssertionError('combined witness changes a source field')
            (private / (label + '.global.fields')).write_bytes(image)
            family['globally_selected_programs'] = reconstructed.public_programs
            family['global_image_sha256'] = hashlib.sha256(image).hexdigest()
            added += len(image) + family['identity_locator_bytes']
    total = retained_bytes + variable_bytes
    return {'providers': selected, 'variable_provider_bytes': variable_bytes,
            'new_allocated_provider_bytes': added, 'combined_variables': top,
            'combined_hard_clauses': len(formula.hard), 'solve_seconds': solve_seconds,
            'wcnf_sha256': digest(formula_path), 'wcnf_bytes': formula_path.stat().st_size,
            'solver_witness_sha256': digest(witness_path),
            'private_candidate_map_sha256': digest(map_path),
            'all_global_witness_fields_reconstructed': True,
            'known_modeled_payload_bytes': total,
            'requested_known_payload_budget': budget,
            'within_requested_budget': total <= budget if budget is not None else None,
            'budget_interpretation': 'modeled payload only; additional opaque/allocator/process memory is unknown'}


def lifecycle(retained, native, chosen, added, scan_tracking=0):
    """Explicit simultaneous liveness, not a measured memory peak."""
    return {'captured_native_known_payload_bytes': retained + native,
            'new_provider_cold_known_payload_bytes': retained + chosen,
            'new_provider_fully_accessed_known_payload_bytes': retained + chosen,
            'in_place_conversion_known_payload_peak_bytes': retained + native + added,
            'two_ready_generations_known_payload_bytes': 2 * (retained + chosen),
            'old_converted_plus_replacement_conversion_known_peak_bytes': 2 * retained + chosen + native + added,
            'scan_tracking_bytes_for_requested_concurrency': scan_tracking,
            'fully_accessed_with_scan_tracking_known_bytes': retained + chosen + scan_tracking,
            'reload_conversion_with_scan_tracking_known_bytes': 2 * retained + chosen + native + added + scan_tracking,
            'reload_assumption': 'two generations with this captured generation\'s dimensions; not an all-changed update bound',
            'solver_compiler_and_allocator_peak_included': False,
            'shared_source_name_and_opaque_payloads_retained_during_conversion': True,
            'physical_pages_reclaimed_proved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--private-output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--depths', default='1,2,3,16')
    parser.add_argument('--known-payload-budget-mib', type=float)
    parser.add_argument('--workers', type=int, default=1)
    args = parser.parse_args()
    if args.workers < 0:
        parser.error('--workers must be nonnegative')
    private_directory(args.capture)
    private = private_directory(args.private_output)
    args.report.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    capture = load_capture(args.capture)
    load_seconds = time.perf_counter() - started
    print(json.dumps({'capture_loaded': capture.manifest, 'graph': capture.graph_validation}), flush=True)
    # These original engine allocations remain live in both representations.
    original_directories = sum(int(target.get(key, 0)) for target in capture.layout['targets']
        for key in ['native_pattern_directory_bytes', 'native_candidate_directory_bytes',
                    'native_logical_directory_bytes', 'retained_transition_cleanup_capacity_bytes',
                    'logical_slot_directory_bytes'])
    null_node_slots = sum(int(t['native_node_arena_bytes']) for t in capture.layout['targets']) - next(
        family.native_bytes for family in capture.families if family.name == 'nodes')
    ledger_path = args.capture / 'resident-ledger.jsonl'
    ledger = [json.loads(line) for line in ledger_path.read_text().splitlines()] if ledger_path.exists() else []
    opaque_hash_bytes = sum(int(item.get('payload_bytes', 0)) + int(item.get('metadata_capacity_bytes', 0))
                            for item in ledger if item.get('kind') == 'hash')
    filter_bytes = sum(int(item.get('filter_bytes', 0)) for item in ledger if item.get('kind') == 'ac')
    retained = (capture.retained_known_payload_bytes + original_directories + null_node_slots
                + opaque_hash_bytes + filter_bytes)
    scan_tracking = args.workers * 3 * 4 * sum(int(t.get('logical_slots', 0)) for t in capture.layout['targets'])
    locator_metadata = {}
    for family in capture.families:
        addresses = family.addresses
        if family.name == 'transition_values':
            addresses = np.fromfile(args.capture / 'transition_addresses.bin', dtype='<u8')
        if addresses is not None:
            locator_metadata[family.name] = write_locator(addresses, private / (family.name + '.locator'))
    depth_results = []
    for depth in [int(x) for x in args.depths.split(',')]:
        families, results = [], []
        profile = private_directory(private / ('work-' + str(depth)))
        for family in capture.families:
            begun = time.perf_counter()
            result = synthesize(family.columns, family.source_bits, max_depth=depth, allow_sparse=True)
            replay = family.verify(result)
            path = profile / (family.name + '.fields')
            path.write_bytes(result.image)
            locator = locator_metadata.get(family.name, {'bytes': 0, 'maximum_binary_search_key_and_index_reads': 0})
            programs = result.public_programs
            field_work = max((p['work'] for p in programs), default=0)
            record = {'family': family.name, 'rows': family.rows,
                      'native_fields': len(family.columns), 'native_record_bytes': family.native_bytes,
                      'field_image_bytes': result.total_bytes,
                      'identity_locator_bytes': locator['bytes'],
                      'synthesized_provider_bytes': result.total_bytes + locator['bytes'],
                      'field_program_work_limit': depth, 'maximum_field_program_work': field_work,
                      'maximum_identity_resolution_reads': locator['maximum_binary_search_key_and_index_reads'],
                      'program_kinds': dict(Counter(p['operation'] for p in programs)),
                      'programs': programs, 'solver': result.metrics,
                      'native_replay': replay, 'image_sha256': digest(path),
                      'wall_seconds': time.perf_counter() - begun}
            families.append(record)
            results.append(result)
            print(json.dumps({k: record[k] for k in ['family', 'rows', 'native_record_bytes',
                                                    'field_image_bytes', 'synthesized_provider_bytes',
                                                    'field_program_work_limit', 'wall_seconds']}), flush=True)
        budget = int(args.known_payload_budget_mib * (1 << 20)) if args.known_payload_budget_mib else None
        selection = system_selection(families, results, retained, profile, budget)
        baseline = sum(f['native_record_bytes'] for f in families)
        phases = lifecycle(retained, baseline, selection['variable_provider_bytes'],
                           selection['new_allocated_provider_bytes'], scan_tracking)
        depth_results.append({'field_program_work_limit': depth, 'families': families,
                              'system_selection': selection, 'liveness': phases})
        del results, result
        gc.collect()
    input_hashes = {p.name: {'bytes': p.stat().st_size, 'sha256': digest(p)}
                    for p in sorted(args.capture.iterdir()) if p.is_file()}
    sources = {str(p.relative_to(ROOT)): digest(p) for p in sorted(Path(__file__).parent.glob('*.py'))}
    report = {'model': 'captured native GET/graph identity and lifecycle model',
              'source_base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'python': platform.python_version(), 'python_sat': pysat.__version__,
              'solver_executed': 'PySAT RC2, not the linked noncomputable Lean construction',
              'capture': capture.manifest, 'graph_validation': capture.graph_validation,
              'capture_validation_seconds': load_seconds,
              'retained_known_payload': {'readable_span_union_bytes': capture.retained_known_payload_bytes,
                                          'original_directories_bytes': original_directories,
                                          'null_node_slots_bytes': null_node_slots,
                                          'opaque_hash_payload_and_capacity_bytes': opaque_hash_bytes,
                                          'filter_bytes': filter_bytes,
                                          'total_bytes': retained},
              'scan_contexts': {'workers': args.workers, 'known_logical_tracking_bytes': scan_tracking,
                                'scope': 'three mutable uint32 logical-slot arrays only; other scan/parser state unknown'},
              'identity_locators': locator_metadata, 'profiles': depth_results,
              'input_hashes': input_hashes, 'source_sha256': sources,
              'wall_seconds': time.perf_counter() - started,
              'limitations': ['The bounded language synthesizes field programs and dependency graphs; it is not universal arbitrary-program synthesis.',
                              'Only named fields and captured graph queries are proved exact, not the entire scanner implementation.',
                              'Native pointer words remain source-identity tokens; accessor/provider adaptation is required for a replacement engine.',
                              'Explicit locator bytes and lookup reads are charged; diagnostic identity maps are not free runtime support.',
                              'Names, token/special/custom/bytecode/hash/parser payloads remain live. Unknown extents and uncaptured engine allocations are not treated as zero.',
                              'Byte totals concern known modeled extents, not RSS, allocator capacity, page reclamation or a whole-engine memory cap.',
                              'Sparse candidate filtering can discard beneficial programs; every accepted relation is checked over all captured rows.',
                              'Raw snapshots, pointer constants and generated field images remain private and are not portable production snapshots.']}
    (args.report / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'completed_profiles': len(depth_results), 'report': str(args.report / 'summary.json')}), flush=True)


if __name__ == '__main__':
    main()
