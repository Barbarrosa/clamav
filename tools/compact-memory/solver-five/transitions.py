#!/usr/bin/env python3
"""Exact shared microblocks on a public-fixture byte Aho--Corasick table.

Offline model only: this is not the compiled ClamAV automaton or its verifier.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from collections import deque
import hashlib
import itertools
import json
from pathlib import Path
import random
import re
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from joint_budget_cnf import budget_cnf
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF
from pysat.solvers import Solver

ROOT = Path(__file__).resolve().parents[3]
MAGIC = b'TRMICR1\0'
HEADER = struct.Struct('<8sIII')


def read_public_patterns(root=None):
    root = Path(root) if root else ROOT
    paths = sorted((root / 'unit_tests/input/pe_allmatch/alert-sigs').glob('*.ndb'))
    patterns, provenance = [], []
    for path in paths:
        for line in path.read_text().splitlines():
            fields = line.split(':')
            if len(fields) >= 4 and re.fullmatch(r'(?:[0-9a-fA-F]{2})+', fields[3]):
                patterns.append(bytes.fromhex(fields[3]))
        provenance.append({'path': str(path.relative_to(root)),
                           'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return patterns, provenance


def byte_ac(patterns):
    """Build exact literal-byte AC; insertion IDs include duplicate patterns.

    Ordered outputs are own terminal IDs followed by the failure state's outputs.
    This is a stated model order, not a reconstruction of ClamAV pointer ties.
    """
    edges, outputs, failure = [{}], [[]], [0]
    for identity, pattern in enumerate(patterns):
        if not pattern:
            raise ValueError('empty literal pattern')
        state = 0
        for byte in pattern:
            if byte not in edges[state]:
                edges[state][byte] = len(edges)
                edges.append({})
                outputs.append([])
                failure.append(0)
            state = edges[state][byte]
        outputs[state].append(identity)
    table = [[0] * 256 for _ in edges]
    for byte, child in edges[0].items():
        table[0][byte] = child
    queue = deque(edges[0].values())
    while queue:
        state = queue.popleft()
        table[state] = table[failure[state]].copy()
        for byte, child in edges[state].items():
            table[state][byte] = child
            failure[child] = table[failure[state]][byte]
            outputs[child].extend(outputs[failure[child]])
            queue.append(child)
    return table, outputs


def blocks_for_rows(rows):
    if len(rows) > 4096 or any(len(row) != 256 for row in rows):
        raise ValueError('table must have at most 4096 rows of 256 entries')
    if any(type(v) is not int or not 0 <= v < (1 << 32) for row in rows for v in row):
        raise ValueError('destinations must be unsigned 32-bit integers')
    blocks, ids, lookup = [], [], {}
    for row in rows:
        row_ids = []
        for at in range(0, 256, 16):
            block = tuple(row[at:at + 16])
            if block not in lookup:
                lookup[block] = len(blocks)
                blocks.append(block)
            row_ids.append(lookup[block])
        ids.append(row_ids)
    if len(blocks) > 65536:
        raise ValueError('microblock IDs exceed u16')
    return blocks, ids


def serialized_cost(rows, shared):
    blocks, ids = blocks_for_rows(rows)
    active = {block for i in shared for block in ids[i]}
    return HEADER.size + 4 * (len(rows) + 1) + len(rows) + 64 * len(active) + sum(
        32 if i in shared else 1024 for i in range(len(rows)))


def optimize(rows, forbid_shared=()):
    """Each row picks dense or shared; shared rows imply all global blocks.

    Returns selected rows, serialized cost and the weighted Boolean model.
    No heuristic candidate pruning occurs in this bounded table family.
    """
    blocks, ids = blocks_for_rows(rows)
    n = len(rows)
    shared_vars = list(range(1, n + 1))
    dense_vars = list(range(n + 1, 2 * n + 1))
    block_vars = list(range(2 * n + 1, 2 * n + len(blocks) + 1))
    hard = []
    costs = []
    for i, (shared, dense) in enumerate(zip(shared_vars, dense_vars)):
        hard.extend([[shared, dense], [-shared, -dense]])
        hard.extend([[-shared, block_vars[b]] for b in set(ids[i])])
        if i in forbid_shared:
            hard.append([-shared])
        costs.extend([(shared, 32), (dense, 1024)])
    costs.extend((v, 64) for v in block_vars)
    formula = WCNF()
    formula.extend(hard)
    for variable, weight in costs:
        formula.append([-variable], weight=weight)
    start = time.perf_counter()
    with RC2(formula) as solver:
        model = solver.compute()
        if model is None:
            raise ValueError('infeasible table')
        positives = set(v for v in model if v > 0)
        shared_rows = {i for i, v in enumerate(shared_vars) if v in positives}
        cost = solver.cost
    elapsed = time.perf_counter() - start
    fixed = HEADER.size + 4 * (n + 1) + n
    if fixed + cost != serialized_cost(rows, shared_rows):
        raise AssertionError('SAT and actual format costs disagree')
    return shared_rows, cost + fixed, {
        'hard': hard, 'costs': costs, 'fixed': fixed,
        'variables': 2 * n + len(blocks), 'hard_clauses': len(hard),
        'maxsat_seconds': elapsed, 'variable_optimum': cost}


def encode(rows, shared, destination_states=None):
    blocks, ids = blocks_for_rows(rows)
    if not set(shared) <= set(range(len(rows))):
        raise ValueError('invalid selected row')
    if destination_states is None:
        destination_states = max((v for r in rows for v in r), default=0) + 1
    if type(destination_states) is not int or not 1 <= destination_states < (1 << 32) or any(v >= destination_states for r in rows for v in r):
        raise ValueError('invalid destination-state bound')
    selected = sorted({block for i in shared for block in ids[i]})
    remap = {old: new for new, old in enumerate(selected)}
    payload = bytearray()
    offsets = [0]
    for i, row in enumerate(rows):
        if i in shared:
            payload.extend(struct.pack('<16H', *(remap[b] for b in ids[i])))
        else:
            payload.extend(struct.pack('<256I', *row))
        offsets.append(len(payload))
    image = bytearray(HEADER.pack(MAGIC, len(rows), len(selected), destination_states))
    for old in selected:
        image.extend(struct.pack('<16I', *blocks[old]))
    image.extend(struct.pack('<' + 'I' * len(offsets), *offsets))
    image.extend(bytes(int(i in shared) for i in range(len(rows))))
    image.extend(payload)
    if len(image) != serialized_cost(rows, shared):
        raise AssertionError('image cost mismatch')
    return bytes(image)


class View:
    """Independent directory/code validator and direct scalar lookup decoder."""
    def __init__(self, image):
        self.image = memoryview(image)
        if len(image) < HEADER.size:
            raise ValueError('truncated header')
        magic, self.rows, blocks, self.states = HEADER.unpack_from(image)
        if magic != MAGIC or self.rows > 4096 or blocks > 65536 or not self.states:
            raise ValueError('invalid image header')
        self.dictionary = HEADER.size
        self.index = self.dictionary + blocks * 64
        flags = self.index + 4 * (self.rows + 1)
        self.payload = flags + self.rows
        if self.payload > len(image):
            raise ValueError('truncated directory')
        self.offsets = struct.unpack_from('<' + 'I' * (self.rows + 1), image, self.index)
        self.flags = self.image[flags:self.payload]
        if self.offsets[0] or self.offsets[-1] != len(image) - self.payload:
            raise ValueError('invalid image endpoints')
        if any(a > b for a, b in zip(self.offsets, self.offsets[1:])):
            raise ValueError('nonmonotone row offsets')
        for i, flag in enumerate(self.flags):
            if flag not in (0, 1) or self.offsets[i + 1] - self.offsets[i] != (32 if flag else 1024):
                raise ValueError('invalid row length or mode')
            if flag:
                codes = struct.unpack_from('<16H', image, self.payload + self.offsets[i])
                if any(code >= blocks for code in codes):
                    raise ValueError('invalid microblock reference')
        # Validate all stored destinations, including blocks with unused entries.
        for at in range(self.dictionary, self.index, 4):
            if struct.unpack_from('<I', image, at)[0] >= self.states:
                raise ValueError('invalid dictionary destination')
        for i, flag in enumerate(self.flags):
            if not flag:
                for at in range(self.payload + self.offsets[i], self.payload + self.offsets[i + 1], 4):
                    if struct.unpack_from('<I', image, at)[0] >= self.states:
                        raise ValueError('invalid dense destination')

    def lookup(self, row, byte):
        if not 0 <= row < self.rows or not 0 <= byte < 256:
            raise ValueError('lookup outside table')
        start = self.payload + self.offsets[row]
        if self.flags[row]:
            block, = struct.unpack_from('<H', self.image, start + 2 * (byte // 16))
            return struct.unpack_from('<I', self.image, self.dictionary + block * 64 + 4 * (byte % 16))[0]
        return struct.unpack_from('<I', self.image, start + 4 * byte)[0]

    def decode(self):
        return [[self.lookup(i, c) for c in range(256)] for i in range(self.rows)]


def audit_budget(model):
    results = []
    for delta in (-1, 0):
        budget = model['variable_optimum'] + delta
        begin = time.perf_counter()
        clauses = budget_cnf(model['hard'], model['costs'], budget)
        encoding = time.perf_counter() - begin
        begin = time.perf_counter()
        with Solver(name='m22', bootstrap_with=clauses) as solver:
            feasible = solver.solve()
        if feasible != (delta == 0):
            raise AssertionError('feasibility disagrees with optimum')
        results.append({'variable_budget': budget, 'feasible': feasible,
                        'variables': max((abs(v) for c in clauses for v in c), default=0),
                        'clauses': len(clauses), 'maximum_width': max(map(len, clauses), default=0),
                        'encoding_seconds': encoding, 'sat_seconds': time.perf_counter() - begin})
    return results


def timing(view, repeats=10000):
    if not view.rows:
        return []
    rng = random.Random(378)
    queries = [(i % view.rows, i % 256) for i in range(repeats)]
    random_queries = [(rng.randrange(view.rows), rng.randrange(256)) for _ in range(repeats)]
    result = []
    for label, sequence in [('sequential', queries), ('random', random_queries)]:
        begin, cpu = time.perf_counter(), time.process_time()
        checksum = sum(view.lookup(row, byte) for row, byte in sequence)
        result.append({'trace': label, 'queries': len(sequence), 'checksum': checksum,
                       'wall_seconds': time.perf_counter() - begin,
                       'cpu_seconds': time.process_time() - cpu,
                       'scope': 'Python scalar decoder only; not native scanner CPU'})
    return result


def run_case(label, rows, destination_states=None):
    shared, optimum, model = optimize(rows)
    raw_image = encode(rows, set(), destination_states)
    shared_image = encode(rows, set(range(len(rows))), destination_states)
    optimized_image = encode(rows, shared, destination_states)
    measured = {}
    for name, image in [('raw', raw_image), ('all_shared', shared_image), ('optimized', optimized_image)]:
        view = View(image)
        if view.decode() != rows:
            raise AssertionError('transition mismatch')
        measured[name] = {'image_bytes': len(image), 'sha256': hashlib.sha256(image).hexdigest(),
                          'cold_component_bytes': len(image), 'hydrated_component_bytes': len(image),
                          'reload_two_image_bytes': 2 * len(image), 'decoded_cache_bytes': 0,
                          'scratch_bytes': 0, 'timings': timing(view)}
    for trace in range(2):
        if len({m['timings'][trace]['checksum'] for m in measured.values()}) != 1:
            raise AssertionError('lookup trace mismatch')
    return {'case': label, 'rows': len(rows), 'transitions_verified_per_variant': len(rows) * 256,
            'shared_rows': len(shared), 'dense_rows': len(rows) - len(shared),
            'maxsat_variables': model['variables'], 'hard_clauses': model['hard_clauses'],
            'maxsat_seconds': model['maxsat_seconds'], 'actual_serialized_optimum': optimum,
            'per_lookup_payload_reads_excluding_common_row_directory_and_mode': {'dense': 1, 'shared': 2},
            'measurements': measured}, model


def run(output):
    patterns, provenance = read_public_patterns()
    rows, outputs = byte_ac(patterns)
    real, _ = run_case('public_fixture_literal_byte_ac', rows, len(rows))
    # This table is a real slice of the same built byte automaton. Destinations
    # remain global state IDs; selecting rows does not remap the automaton.
    audit_rows = rows[:8]
    audit, model = run_case('public_fixture_8_row_budget_audit', audit_rows, len(rows))
    audit['fixed_width_feasibility'] = audit_budget(model)
    rng = random.Random(379)
    adversarial = [[rng.randrange(4096) for _ in range(256)] for _ in range(8)]
    distinct, _ = run_case('distinct_microblocks_raw_fallback', adversarial, 4096)
    hybrid_rows = [list(range(256)), list(range(256)), list(range(256, 512))]
    hybrid, _ = run_case('global_setup_hybrid_control', hybrid_rows, 512)
    result = {'scope': 'offline literal-byte AC and synthetic transition model; not a compiled ClamAV automaton',
              'source_patterns': len(patterns), 'source_unique_patterns': len(set(patterns)),
              'source_files': provenance, 'cases': [real, audit, distinct, hybrid],
              'cost_model': '20-byte header + u32 row offsets/terminal + byte modes + 64 bytes per shared block + 32 per shared row or 1024 per dense row',
              'exact_all_transitions_verified': True,
              'limitations': ['No ClamAV extended verifier/output semantics or runtime representation was changed.',
                              'Component image bytes are not process RSS or full-engine memory savings.',
                              'Shared lookups add a dependent table read; Python timings are not deployment CPU forecasts.',
                              'Only the bounded eight-row slice was translated to byte-budget <=3-CNF.',
                              'Conventional RC2/Minisat tested the reductions; the linked counting algorithm was not executed.']}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'cases': [{k: c[k] for k in ('case', 'rows', 'shared_rows', 'dense_rows', 'actual_serialized_optimum')} for c in result['cases']]}))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'docs/solver-five-results/transitions.json')
    args = parser.parse_args()
    run(args.output)
