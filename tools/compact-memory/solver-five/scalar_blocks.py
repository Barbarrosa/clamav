#!/usr/bin/env python3
"""Bounded exact scalar blocks: jointly select boundaries and representations.

Standalone uint32 representation experiment; not compiled ClamAV metadata.
SPDX-License-Identifier: GPL-2.0-only
"""
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import re
import struct
import time

from common import BooleanModel

MAGIC = b'SCALAR1\0'
HEADER = struct.Struct('<8sII')
BLOCK = struct.Struct('<HBB')
RAW, CONSTANT, AFFINE, FRAME, SPARSE = range(5)
MODE_NAMES = ['raw', 'constant', 'affine', 'frame', 'sparse']
U32 = (1 << 32) - 1
ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Choice:
    start: int
    stop: int
    mode: int
    work: int
    encoded: bytes

    @property
    def cost(self):
        return 8 + len(self.encoded)  # actual start/offset directory entry


def validate_values(values):
    values = tuple(values)
    if len(values) > 256 or any(type(v) is not int or not 0 <= v <= U32 for v in values):
        raise ValueError('expected at most 256 unsigned 32-bit integers')
    return values


def block_choices(values, start=0, max_work=4):
    """Work is abstract scalar access work, excluding bounded directory search."""
    values = validate_values(values)
    n = len(values)
    if not n:
        return []
    choices = []

    def add(mode, bits, payload, work):
        if work <= max_work:
            choices.append(Choice(start, start + n, mode, work,
                                  BLOCK.pack(n, mode, bits) + payload))

    add(RAW, 0, struct.pack('<' + 'I' * n, *values), 1)
    if len(set(values)) == 1:
        add(CONSTANT, 0, struct.pack('<I', values[0]), 1)
    if n >= 2:
        step = values[1] - values[0]
        if all(values[0] + i * step == v for i, v in enumerate(values)):
            add(AFFINE, 0, struct.pack('<Iq', values[0], step), 2)
    base = min(values)
    bits = (max(values) - base).bit_length()
    if bits:
        packed = sum((v - base) << (i * bits) for i, v in enumerate(values))
        add(FRAME, bits, struct.pack('<I', base) +
            packed.to_bytes((n * bits + 7) // 8, 'little'), 2)
    counts = Counter(values)
    common = min(counts, key=lambda v: (-counts[v], v))
    exceptions = [(i, v) for i, v in enumerate(values) if v != common]
    if exceptions:
        add(SPARSE, 0, struct.pack('<IH', common, len(exceptions)) +
            b''.join(struct.pack('<HI', i, v) for i, v in exceptions), len(exceptions) + 1)
    return choices


def all_choices(values, max_span=16, max_work=4):
    values = validate_values(values)
    if not 1 <= max_span <= 64 or not 1 <= max_work <= 65:
        raise ValueError('invalid span/work bounds')
    choices = [choice for start in range(len(values))
               for stop in range(start + 1, min(len(values), start + max_span) + 1)
               for choice in block_choices(values[start:stop], start, max_work)]
    # Global direct formats are important baselines. Their access work does not
    # depend on the number of rows; do not force extra directory headers merely
    # to satisfy an arbitrary regular-block-size limit.
    if len(values) > max_span:
        choices.extend(block_choices(values, 0, max_work))
    return choices


def make_problem(values, max_span=16, max_work=4):
    values = validate_values(values)
    choices = all_choices(values, max_span, max_work)
    model = BooleanModel()
    incoming = [[] for _ in range(len(values) + 1)]
    outgoing = [[] for _ in range(len(values) + 1)]
    edges = []
    for choice in choices:
        variable = model.new()
        model.costs.append((variable, choice.cost))
        outgoing[choice.start].append(variable)
        incoming[choice.stop].append(variable)
        edges.append((variable, choice))
    if values:
        model.exactly_one(outgoing[0])
        model.exactly_one(incoming[-1])
    for at in range(1, len(values)):
        model.at_most(incoming[at], 1)
        model.at_most(outgoing[at], 1)
        for v in incoming[at]:
            model.hard.append([-v] + outgoing[at])
        for v in outgoing[at]:
            model.hard.append([-v] + incoming[at])
    return model, edges


def solve_layout(values, max_span=16, max_work=4):
    values = validate_values(values)
    model, edges = make_problem(values, max_span, max_work)
    positive, cost, metrics = model.solve()
    selected = sorted((c for v, c in edges if v in positive), key=lambda c: c.start)
    image = serialize(len(values), selected)
    if len(image) != 20 + cost or decode_image(image, max_work) != list(values):
        raise AssertionError('solver/serialized cost or exact reconstruction disagrees')
    return image, selected, metrics, model


def dp_layout(values, max_span=16, max_work=4):
    """Independent selection baseline using shortest-path dynamic programming."""
    values = validate_values(values)
    choices = all_choices(values, max_span, max_work)
    costs, paths = [None] * (len(values) + 1), [None] * (len(values) + 1)
    costs[0], paths[0] = 0, []
    for start in range(len(values)):
        for choice in choices:
            if choice.start == start and costs[start] is not None:
                cost = costs[start] + choice.cost
                if costs[choice.stop] is None or cost < costs[choice.stop]:
                    costs[choice.stop] = cost
                    paths[choice.stop] = paths[start] + [choice]
    return serialize(len(values), paths[-1] or []), paths[-1] or []


def fixed_layout(values, span=8, max_work=4, raw_only=False):
    values = validate_values(values)
    selected = []
    for start in range(0, len(values), span):
        options = block_choices(values[start:start + span], start, max_work)
        if raw_only:
            options = [c for c in options if c.mode == RAW]
        selected.append(min(options, key=lambda c: (c.cost, c.mode)))
    return serialize(len(values), selected), selected


def serialize(rows, selected):
    if not 0 <= rows <= 256:
        raise ValueError('invalid row count')
    end, offset, entries, payload = 0, 0, [], []
    for choice in selected:
        if choice.start != end or choice.stop <= choice.start:
            raise ValueError('noncontiguous selected blocks')
        entries.append(struct.pack('<II', choice.start, offset))
        payload.append(choice.encoded)
        offset += len(choice.encoded)
        end = choice.stop
    if end != rows:
        raise ValueError('incomplete block coverage')
    return HEADER.pack(MAGIC, rows, len(selected)) + b''.join(entries) + struct.pack('<I', offset) + b''.join(payload)


def _parse(image):
    image = bytes(image)
    if len(image) < 20:
        raise ValueError('truncated scalar image')
    magic, rows, blocks = HEADER.unpack_from(image)
    if magic != MAGIC or rows > 256 or blocks > rows or (rows == 0) != (blocks == 0):
        raise ValueError('invalid scalar header')
    payload_start = 20 + blocks * 8
    if len(image) < payload_start:
        raise ValueError('truncated scalar directory')
    entries = [struct.unpack_from('<II', image, 16 + i * 8) for i in range(blocks)]
    terminal, = struct.unpack_from('<I', image, 16 + blocks * 8)
    if terminal != len(image) - payload_start:
        raise ValueError('trailing or truncated scalar payload')
    if entries and entries[0] != (0, 0):
        raise ValueError('invalid scalar directory origin')
    if any(a[0] >= b[0] or a[1] >= b[1] for a, b in zip(entries, entries[1:])):
        raise ValueError('nonmonotone scalar directory')
    ends = entries[1:] + [(rows, terminal)]
    result = []
    for (start, offset), (stop, end) in zip(entries, ends):
        if stop > rows or end > terminal or start >= stop or offset >= end:
            raise ValueError('scalar block bounds')
        block = image[payload_start + offset:payload_start + end]
        if len(block) < 4:
            raise ValueError('truncated scalar block')
        count, mode, bits = BLOCK.unpack_from(block)
        if count != stop - start or mode not in range(5) or (mode != FRAME and bits):
            raise ValueError('invalid scalar mode/count')
        result.append((start, _decode_block(block)))
    return rows, result


def _decode_block(block):
    count, mode, bits = BLOCK.unpack_from(block)
    data = block[4:]
    if mode == RAW:
        if len(data) != count * 4:
            raise ValueError('raw scalar length')
        values = list(struct.unpack('<' + 'I' * count, data)); work = 1
    elif mode == CONSTANT:
        if len(data) != 4:
            raise ValueError('constant scalar length')
        base, = struct.unpack('<I', data)
        values = [base] * count; work = 1
    elif mode == AFFINE:
        if len(data) != 12:
            raise ValueError('affine scalar length')
        base, step = struct.unpack('<Iq', data)
        values = [base + step * i for i in range(count)]; work = 2
        if any(not 0 <= value <= U32 for value in values):
            raise ValueError('affine scalar overflow')
    elif mode == FRAME:
        if not 1 <= bits <= 32 or len(data) != 4 + (count * bits + 7) // 8:
            raise ValueError('frame scalar width/length')
        base, = struct.unpack_from('<I', data)
        packed = int.from_bytes(data[4:], 'little')
        values = [base + ((packed >> (bits * i)) & ((1 << bits) - 1)) for i in range(count)]; work = 2
        if any(v > U32 for v in values):
            raise ValueError('frame scalar overflow')
    elif mode == SPARSE:
        if len(data) < 6:
            raise ValueError('sparse scalar header')
        base, exceptions = struct.unpack_from('<IH', data)
        if exceptions > count or len(data) != 6 + exceptions * 6:
            raise ValueError('sparse scalar size')
        values = [base] * count; last = -1
        for i in range(exceptions):
            pos, value = struct.unpack_from('<HI', data, 6 + i * 6)
            if pos >= count or pos <= last:
                raise ValueError('sparse scalar position')
            last = pos; values[pos] = value
        work = exceptions + 1
    else:
        raise ValueError('unknown scalar mode')
    return values, work


def decode_image(image, max_work=65):
    _, blocks = _parse(image)
    if any(work > max_work for _, (_, work) in blocks):
        raise ValueError('scalar work bound exceeded')
    return [value for _, (values, _) in blocks for value in values]


def lookup_image(image, index, max_work=65):
    """Diagnostic random lookup; parsing/validation is intentionally included."""
    rows, blocks = _parse(image)
    if not 0 <= index < rows:
        raise ValueError('scalar lookup out of bounds')
    at = bisect_right([start for start, _ in blocks], index) - 1
    start, (values, work) = blocks[at]
    if work > max_work:
        raise ValueError('scalar work bound exceeded')
    return values[index - start]


def fixture_columns():
    targets, lengths, offsets, sources = [], [], [], []
    paths = sorted((ROOT / 'unit_tests/input/pe_allmatch/alert-sigs').glob('*.ndb'))
    paths.append(ROOT / 'unit_tests/input/other_sigs/Clamav-Unit-Test-Signature.ndb')
    for path in paths:
        for line in path.read_text().splitlines():
            f = line.split(':')
            if len(f) >= 4 and f[1].isdigit() and re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', f[3]):
                targets.append(int(f[1])); lengths.append(len(f[3]) // 2)
                if f[2].isdigit():
                    offsets.append(int(f[2]))
        sources.append({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return {'fixture_targets': targets, 'fixture_literal_lengths': lengths,
            'fixture_numeric_offsets': offsets}, sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    columns, sources = fixture_columns()
    rng = random.Random(378)
    columns.update({'constant': [U32] * 32,
                    'changing_runs': [7] * 5 + [U32] * 7 + [19] * 4 + [20, 21, 22, 23, 24, 25] + [0] * 10,
                    'sparse_outlier': [100] * 15 + [U32] + [100] * 16,
                    'distinct_random': [rng.getrandbits(32) for _ in range(32)],
                    'descending_boundary': [U32 - i for i in range(24)]})
    results = []
    for name, values in columns.items():
        if not values:
            continue
        image, selected, metrics, _ = solve_layout(values)
        oracle, _ = dp_layout(values)
        if len(image) != len(oracle):
            raise AssertionError('MaxSAT differs from dynamic-program optimum')
        alternatives = {'raw_single_block': fixed_layout(values, span=len(values), raw_only=True)[0],
                        'single_block_best': fixed_layout(values, span=len(values))[0],
                        'fixed_8': fixed_layout(values, span=8)[0],
                        'fixed_16': fixed_layout(values, span=16)[0], 'joint': image}
        for candidate in alternatives.values():
            if decode_image(candidate) != values:
                raise AssertionError('scalar roundtrip')
            if [lookup_image(candidate, i) for i in range(len(values))] != values:
                raise AssertionError('scalar random lookups')
        query = [rng.randrange(len(values)) for _ in range(256)]
        cpu_start = time.process_time(); start = time.perf_counter()
        checksum = sum(lookup_image(image, i, 4) for i in query)
        wall, cpu = time.perf_counter() - start, time.process_time() - cpu_start
        work = max((c.work for c in selected), default=0)
        results.append({'case': name, 'rows': len(values), 'image_bytes': {k: len(v) for k, v in alternatives.items()},
                        'mode_counts': dict(Counter(MODE_NAMES[c.mode] for c in selected)),
                        'selected_blocks': len(selected), 'max_regular_block_rows': 16, 'max_mode_work': 4,
                        'whole_column_direct_format_fallback_enabled': True,
                        'directory_search_comparisons_upper_bound': math.ceil(math.log2(len(values) + 1)),
                        'modeled_lookup_work_upper_bound': math.ceil(math.log2(len(values) + 1)) + work,
                        'empty_cache_image_bytes': len(image), 'hydrated_image_bytes': len(image),
                        'two_generation_image_bytes': 2 * len(image),
                        'maximum_block_decoded_uint32_payload_bytes': max((c.stop - c.start for c in selected), default=0) * 4,
                        'diagnostic_decoder_all_values_uint32_payload_bytes': len(values) * 4,
                        'all_values_and_random_lookups_verified': True,
                        'independent_shortest_path_cost_agrees': True, 'solver': metrics,
                        'python_validation_and_lookup': {'queries': len(query), 'wall_seconds': wall,
                                                         'cpu_seconds': cpu, 'checksum': checksum},
                        'source_uint32_sha256': hashlib.sha256(struct.pack('<' + 'I' * len(values), *values)).hexdigest(),
                        'image_sha256': hashlib.sha256(image).hexdigest()})
    tiny = [7, 7, 7, 65535, 1, 2, 3, 4]
    image, selected, _, model = solve_layout(tiny, max_span=4, max_work=3)
    audit = model.verify_budget(sum(c.cost for c in selected))
    result = {'experiment': 'adaptive scalar block boundaries and formats',
              'scope': 'bounded fixture-derived/synthetic uint32 columns, not ClamAV compiled metadata',
              'format_modes': MODE_NAMES, 'source_fixture_files': sources, 'cases': results,
              'fixed_width_feasibility_audit': {'rows': len(tiny), 'global_fixed_bytes': 20, **audit},
              'limitations': ['Uses conventional RC2 and Minisat, not execution of the linked counting program.',
                             'A shortest-path dynamic program solves this bounded family without SAT; no solver advantage is claimed.',
                             'Image counts exclude process/allocator overhead, engine state and compiler/solver peak.',
                             'The decoder materializes blocks in Python; timings include validation and are not native ClamAV CPU measurements.',
                             'Decoded uint32 payload counts exclude Python objects/list overhead and are not measured RAM or a native scratch guarantee.',
                             'Work bound is an abstract representation-access bound; decoder implementation and CPU cost differ.',
                             'No decoded cache exists; no C pointer lifetime or scanner output-order qualification is claimed.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'cases': len(results), 'results': [{k: row[k] for k in ('case', 'rows', 'image_bytes')} for row in results]}))


if __name__ == '__main__':
    main()
