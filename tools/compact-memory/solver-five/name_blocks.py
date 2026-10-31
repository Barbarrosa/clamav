#!/usr/bin/env python3
"""Adaptive immutable name blocks; standalone bounded SAT layout experiment.

SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import struct
import time

from common import BooleanModel

ROOT = Path(__file__).resolve().parents[3]
HEADER = struct.Struct('<8sII')
DESCRIPTOR = struct.Struct('<IHHIII')
MAGIC = b'NMDBLK1\0'


def prefix_length(left, right):
    count = 0
    while count < min(len(left), len(right)) and left[count] == right[count]:
        count += 1
    return count


@dataclass(frozen=True)
class Block:
    start: int
    stop: int
    front: bool
    payload: bytes
    decoded: int

    @property
    def cost(self):
        return DESCRIPTOR.size + len(self.payload)

    @property
    def work(self):
        # Abstract copied/scanned bytes plus one header dispatch per coded name.
        return self.decoded + (self.stop - self.start if self.front else 0)


def encode_block(names, start, stop, front):
    payload = bytearray()
    previous = b''
    for name in names[start:stop]:
        if front:
            prefix = prefix_length(previous, name)
            suffix = name[prefix:]
            payload.extend(struct.pack('<HH', prefix, len(suffix)))
            payload.extend(suffix)
        else:
            payload.extend(name + b'\0')
        previous = name
    return Block(start, stop, front, bytes(payload), sum(len(n) + 1 for n in names[start:stop]))


@dataclass(frozen=True)
class Layout:
    names: tuple[bytes, ...]
    blocks: tuple[Block, ...]

    @property
    def variable_bytes(self):
        return sum(block.cost for block in self.blocks)

    @property
    def common_bytes(self):
        return HEADER.size + 4 * len(self.names)

    @property
    def total_bytes(self):
        return self.common_bytes + self.variable_bytes

    def image(self):
        refs = [0] * len(self.names)
        descriptors = bytearray()
        payload = bytearray()
        expected = 0
        for index, block in enumerate(self.blocks):
            if block.start != expected or block.stop <= block.start:
                raise ValueError('blocks must partition original name order')
            expected = block.stop
            for row in range(block.start, block.stop):
                refs[row] = index
            descriptors.extend(DESCRIPTOR.pack(block.start, block.stop - block.start,
                                               int(block.front), len(payload),
                                               len(block.payload), block.decoded))
            payload.extend(block.payload)
        if expected != len(self.names):
            raise ValueError('incomplete block partition')
        image = HEADER.pack(MAGIC, len(self.names), len(self.blocks))
        image += struct.pack('<' + 'I' * len(refs), *refs) + descriptors + payload
        if len(image) != self.total_bytes:
            raise AssertionError('serialized and modeled cost disagree')
        return image


def parse_image(image):
    image = memoryview(image)
    if len(image) < HEADER.size:
        raise ValueError('truncated header')
    magic, names, count = HEADER.unpack_from(image)
    if magic != MAGIC or names > 256 or count > names:
        raise ValueError('invalid header')
    head_size = HEADER.size + 4 * names + count * DESCRIPTOR.size
    if head_size > len(image):
        raise ValueError('truncated directory')
    refs = struct.unpack_from('<' + 'I' * names, image, HEADER.size)
    directory = HEADER.size + 4 * names
    descriptors = []
    expected_row, expected_offset = 0, 0
    for index in range(count):
        start, span, front, offset, size, decoded = DESCRIPTOR.unpack_from(image, directory + index * DESCRIPTOR.size)
        if (start != expected_row or not span or span > 64 or front > 1 or
                offset != expected_offset or decoded > 65536 or start + span > names):
            raise ValueError('invalid block descriptor')
        if any(refs[row] != index for row in range(start, start + span)):
            raise ValueError('name reference does not match block')
        if size > len(image) - head_size - offset:
            raise ValueError('truncated block payload')
        descriptors.append((start, span, bool(front), head_size + offset, size, decoded))
        expected_row += span
        expected_offset += size
    if expected_row != names or head_size + expected_offset != len(image):
        raise ValueError('incomplete directory or trailing payload')
    return image, refs, descriptors


def decode_block(image, descriptor, max_work=None):
    start, span, front, offset, size, expected = descriptor
    if max_work is not None and expected + (span if front else 0) > max_work:
        raise ValueError('decode-work bound exceeded')
    payload = image[offset:offset + size]
    if not front and size != expected:
        raise ValueError('raw block length mismatch')
    previous = b''
    output = []
    pos = 0
    expanded = 0
    for _ in range(span):
        if front:
            if size - pos < 4:
                raise ValueError('truncated front-code header')
            prefix, suffix = struct.unpack_from('<HH', payload, pos)
            pos += 4
            if prefix > len(previous) or suffix > size - pos:
                raise ValueError('invalid front-code length')
            # Reject before copying a suffix or previous prefix. Declared work
            # must bound every intermediate allocation, not just the final sum.
            if prefix + suffix + 1 > expected - expanded:
                raise ValueError('name exceeds remaining decoded budget')
            name = previous[:prefix] + bytes(payload[pos:pos + suffix])
            pos += suffix
            if b'\0' in name:
                raise ValueError('embedded NUL in name')
        else:
            stop = pos
            limit = min(size, pos + expected - expanded)
            while stop < limit and payload[stop] != 0:
                stop += 1
            if stop == limit:
                raise ValueError('unterminated raw name')
            name = bytes(payload[pos:stop])
            pos = stop + 1
        output.append(name)
        previous = name
        expanded += len(name) + 1
    if pos != size or expanded != expected:
        raise ValueError('block length mismatch')
    return output


def decode_image(image, max_work=None):
    image, refs, descriptors = parse_image(image)
    output = []
    for descriptor in descriptors:
        output.extend(decode_block(image, descriptor, max_work))
    return output


class StableNames:
    """Prototype retained immutable backing, not a C pointer/ABI integration."""
    def __init__(self, image, max_work=None):
        self.image, self.refs, self.descriptors = parse_image(bytes(image))
        self.max_work = max_work
        self.arenas = {}
        self.raw_offsets = {}

    def get(self, row):
        if not 0 <= row < len(self.refs):
            raise IndexError(row)
        index = self.refs[row]
        descriptor = self.descriptors[index]
        if not descriptor[2]:
            start, span, front, offset, size, expected = descriptor
            if size != expected:
                raise ValueError('raw block length mismatch')
            if self.max_work is not None and expected > self.max_work:
                raise ValueError('decode-work bound exceeded')
            if index not in self.raw_offsets:
                offsets, pos = [], 0
                for _ in range(span):
                    end = pos
                    while end < size and self.image[offset + end]:
                        end += 1
                    if end == size:
                        raise ValueError('unterminated raw name')
                    offsets.append((offset + pos, offset + end))
                    pos = end + 1
                if pos != size or pos != expected:
                    raise ValueError('raw block length mismatch')
                self.raw_offsets[index] = offsets
            left, right = self.raw_offsets[index][row - start]
            return self.image[left:right]
        if index not in self.arenas:
            names = decode_block(self.image, descriptor, self.max_work)
            # All views retain the immutable arena; never replace or evict it.
            arena = b''.join(name + b'\0' for name in names)
            offsets, pos = [], 0
            for name in names:
                offsets.append((pos, pos + len(name)))
                pos += len(name) + 1
            self.arenas[index] = (arena, offsets)
        arena, offsets = self.arenas[index]
        left, right = offsets[row - descriptor[0]]
        return memoryview(arena)[left:right]

    @property
    def stable_payload_bytes(self):
        return len(self.image) + sum(len(arena) for arena, _ in self.arenas.values())


class NameProblem:
    def __init__(self, names, max_span=8, max_work=512):
        self.names = tuple(bytes(name) for name in names)
        if (len(self.names) > 256 or any(b'\0' in n or len(n) > 4096 for n in self.names)
                or not 1 <= max_span <= 64 or not 1 <= max_work <= 65536):
            raise ValueError('experimental input limit exceeded')
        self.max_span, self.max_work = max_span, max_work
        self.model = BooleanModel()
        self.choices = []
        incoming = [[] for _ in range(len(names) + 1)]
        outgoing = [[] for _ in range(len(names) + 1)]
        for start in range(len(names)):
            for stop in range(start + 1, min(len(names), start + max_span) + 1):
                for front in [False, True]:
                    block = encode_block(self.names, start, stop, front)
                    if block.work > max_work:
                        continue
                    variable = self.model.new()
                    self.choices.append((variable, block))
                    self.model.costs.append((variable, block.cost))
                    incoming[stop].append(variable)
                    outgoing[start].append(variable)
        if names:
            self.model.hard.extend([outgoing[0], incoming[-1]])
            for row in range(1, len(names)):
                for variable in incoming[row]:
                    self.model.hard.append([-variable] + outgoing[row])
                for variable in outgoing[row]:
                    self.model.hard.append([-variable] + incoming[row])
            for group in incoming + outgoing:
                self.model.at_most(group, 1)

    def solve(self):
        selected, cost, metrics = self.model.solve()
        blocks = tuple(sorted((b for v, b in self.choices if v in selected), key=lambda b: b.start))
        layout = Layout(self.names, blocks)
        if layout.variable_bytes != cost or decode_image(layout.image(), self.max_work) != list(self.names):
            raise AssertionError('optimized image mismatch')
        return layout, metrics

    def fixed(self, span, raw_only=False):
        if not 1 <= span <= self.max_span:
            raise ValueError('fixed segmentation exceeds span bound')
        blocks = []
        for start in range(0, len(self.names), span):
            stop = min(len(self.names), start + span)
            choices = [encode_block(self.names, start, stop, front) for front in [False, True]]
            choices = [b for b in choices if b.work <= self.max_work and (not raw_only or not b.front)]
            if not choices:
                raise ValueError('fixed segmentation exceeds work bound')
            blocks.append(min(choices, key=lambda b: (b.cost, b.front)))
        return Layout(self.names, tuple(blocks))


def independent_optimum(names, max_span, max_work):
    """Independent DP cost arithmetic, never calling encoder/model edge builder."""
    best = [0] + [None] * len(names)
    for start in range(len(names)):
        if best[start] is None:
            continue
        for stop in range(start + 1, min(len(names), start + max_span) + 1):
            sequence = names[start:stop]
            decoded = sum(len(n) + 1 for n in sequence)
            payload = 0
            previous = b''
            for name in sequence:
                shared = 0
                for a, b in zip(name, previous):
                    if a != b:
                        break
                    shared += 1
                payload += 4 + len(name) - shared
                previous = name
            costs = []
            if decoded <= max_work:
                costs.append(decoded + DESCRIPTOR.size)
            if decoded + stop - start <= max_work:
                costs.append(payload + DESCRIPTOR.size)
            if costs:
                value = best[start] + min(costs)
                if best[stop] is None or value < best[stop]:
                    best[stop] = value
    return best[-1]


def public_names():
    paths = sorted((ROOT / 'unit_tests/input/pe_allmatch/alert-sigs').glob('*.ndb'))
    names, sources = [], []
    for path in paths:
        for line in path.read_bytes().splitlines():
            if line and not line.startswith(b'#'):
                names.append(line.split(b':', 1)[0])
        sources.append({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return names, sources


def run_case(name, names, sources, max_span=8, max_work=512, budget_check=False):
    start = time.perf_counter()
    problem = NameProblem(names, max_span, max_work)
    encoding_seconds = time.perf_counter() - start
    layout, metrics = problem.solve()
    optimum = independent_optimum(names, max_span, max_work)
    if layout.variable_bytes != optimum:
        raise AssertionError('independent DP optimum differs')
    baselines = {}
    decode_timings = {}
    for mode, span, raw_only in [('raw', max_span, True), ('fixed_1', 1, False), ('fixed_4', 4, False), ('fixed_8', 8, False)]:
        try:
            value = problem.fixed(span, raw_only)
            baselines[mode] = value.total_bytes
            baseline_image = value.image()
            begin = time.process_time()
            for _ in range(100):
                if decode_image(baseline_image, max_work) != list(names):
                    raise AssertionError('baseline decode timing mismatch')
            decode_timings[mode] = time.process_time() - begin
        except ValueError:
            baselines[mode] = None
    image = layout.image()
    holder = StableNames(image, max_work)
    borrowed = [holder.get(0)] if names else []
    for row in range(len(names)):
        if bytes(holder.get(row)) != names[row]:
            raise AssertionError('materialized name mismatch')
    if names and bytes(borrowed[0]) != names[0]:
        raise AssertionError('retained prototype name view changed')
    start = time.process_time()
    for _ in range(100):
        if decode_image(image, max_work) != list(names):
            raise AssertionError('decode timing mismatch')
    cpu_seconds = time.process_time() - start
    result = {'case': name, 'names': len(names), 'source_name_bytes_with_nul': sum(len(n) + 1 for n in names),
              'maximum_names_per_block': max_span, 'maximum_decode_work': max_work,
              'optimized_image_bytes': len(image), 'optimized_variable_bytes': layout.variable_bytes,
              'common_bytes': layout.common_bytes, 'blocks': len(layout.blocks),
              'front_coded_blocks': sum(b.front for b in layout.blocks), 'baseline_image_bytes': baselines,
              'cold_image_bytes': len(image), 'all_hydrated_image_and_stable_name_bytes': holder.stable_payload_bytes,
              'reload_two_cold_images_bytes': 2 * len(image),
              'reload_two_hydrated_payload_bytes': 2 * holder.stable_payload_bytes,
              'maximum_block_decoded_payload_bytes': max((b.decoded for b in layout.blocks), default=0),
              'transient_python_peak_measured': False,
              'cpu_seconds_for_100_complete_python_decodes': cpu_seconds,
              'baseline_cpu_seconds_for_100_complete_python_decodes': decode_timings,
              'worst_block_modeled_decode_work': max((b.work for b in layout.blocks), default=0),
              'every_name_and_original_order_verified': True, 'prototype_retained_views_verified': True,
              'independent_dp_optimum_verified': True, 'image_sha256': hashlib.sha256(image).hexdigest(),
              'encoding_seconds': encoding_seconds, 'solver': metrics, 'sources': sources}
    if budget_check:
        result['fixed_width_budget_checks'] = problem.model.verify_budget(layout.variable_bytes)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    public, sources = public_names()
    rng = random.Random(378)
    distinct = [rng.randbytes(24).hex().encode() for _ in range(12)]
    groups = [b'A' * 24, b'B' * 24, b'C' * 24]
    clustered = [groups[g] + ('%03d' % i).encode() for g, size in enumerate([3, 4, 6]) for i in range(size)]
    cases = [run_case('public-original-order-names', public, sources),
             run_case('clustered-name-boundaries', clustered, []),
             run_case('distinct-name-control', distinct, [], max_span=4),
             run_case('tiny-budget-witness', [b'alpha-one', b'alpha-two', b'beta'], [], max_span=3, max_work=64, budget_check=True)]
    report = {'experiment': 'adaptive_name_blocks',
              'scope': 'bounded offline name representation; no scanner or C name-pointer integration',
              'algorithm_executed': 'conventional RC2 MaxSAT and MiniSat budget feasibility, not linked counting construction',
              'cases': cases,
              'limitations': ['Public names are test fixture labels, not official-database name distributions.',
                             'Hydrated accounting retains the entire encoded image plus immutable decoded name blocks; no eviction or compressed retirement.',
                             'Payload counts exclude Python objects, allocator rounding, and actual process RSS.',
                             'Maximum block decoded payload is not Python temporary scratch: decoded names and joined immutable arenas coexist; transient allocation peak is unmeasured.',
                             'Python memoryview lifetimes are prototype evidence, not proof of the C ABI borrowed-pointer contract.',
                             'Decode work is abstract expanded bytes plus one dispatch per front-coded name; CPU data is Python-only.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({case['case']: {'raw': case['baseline_image_bytes']['raw'], 'optimized': case['optimized_image_bytes'],
                                   'hydrated': case['all_hydrated_image_and_stable_name_bytes']} for case in cases}))


if __name__ == '__main__':
    main()
