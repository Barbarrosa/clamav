#!/usr/bin/env python3
"""Exact ordered candidate-tail sharing, offline bounded byte-AC model only.

Every record retains pattern identity, occurrence identity, attributes and the
next_same occurrence identity. No ClamAV matcher or alert ordering is changed.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from dataclasses import dataclass
import hashlib
import itertools
import json
from pathlib import Path
import struct
import time

from common import BooleanModel

NIL = 0xffffffff
HEADER = struct.Struct('<8sIIII')
DESCRIPTOR = struct.Struct('<IIII')
RECORD = struct.Struct('<IIII')
NODE = struct.Struct('<IIIII')
MAGIC = b'CTAIL1\0\0'


def validate_records(records):
    seen = {}
    for position, record in enumerate(records):
        if len(record) != 4 or any(type(v) is not int or not 0 <= v <= NIL for v in record):
            raise ValueError('candidate fields must be four uint32 values')
        if record[1] in seen:
            raise ValueError('duplicate occurrence identity inside a list')
        seen[record[1]] = position
    for position, record in enumerate(records):
        if record[3] != NIL:
            target = seen.get(record[3], -1)
            if target <= position or records[target][0] != record[0]:
                raise ValueError('next_same must reference a later equal-pattern occurrence')


def make_records(patterns, output_ids):
    pattern_ids = {p: i for i, p in enumerate(dict.fromkeys(patterns))}
    result = []
    for position, occurrence in enumerate(output_ids):
        next_same = next((other for other in output_ids[position + 1:]
                          if patterns[other] == patterns[occurrence]), NIL)
        result.append((pattern_ids[patterns[occurrence]], occurrence,
                       occurrence % 4, next_same))
    validate_records(result)
    return tuple(result)


@dataclass(frozen=True)
class Image:
    lists: tuple
    lengths: tuple
    max_hops: int

    def to_bytes(self):
        if len(self.lists) != len(self.lengths) or not 0 <= self.max_hops <= 4096:
            raise ValueError('invalid image dimensions')
        tails = set()
        for records, length in zip(self.lists, self.lengths):
            validate_records(records)
            if not 0 <= length <= min(len(records), self.max_hops):
                raise ValueError('invalid shared suffix length')
            tails.update(records[-j:] for j in range(1, length + 1))
        ordered = sorted(tails, key=lambda t: (len(t), t))
        positions = {tail: i for i, tail in enumerate(ordered)}
        inline, descriptors = [], []
        for records, length in zip(self.lists, self.lengths):
            count = len(records) - length
            head = positions[records[-length:]] if length else NIL
            descriptors.append((len(inline), count, head, len(records)))
            inline.extend(records[:count])
        output = bytearray(HEADER.pack(MAGIC, len(self.lists), len(ordered), len(inline), self.max_hops))
        for descriptor in descriptors:
            output.extend(DESCRIPTOR.pack(*descriptor))
        for record in inline:
            output.extend(RECORD.pack(*record))
        for tail in ordered:
            nxt = positions[tail[1:]] if len(tail) > 1 else NIL
            output.extend(NODE.pack(*tail[0], nxt))
        return bytes(output)

    @property
    def common_bytes(self):
        return HEADER.size + len(self.lists) * DESCRIPTOR.size

    @property
    def variable_bytes(self):
        return len(self.to_bytes()) - self.common_bytes


def decode_image(data, max_hops=None):
    data = memoryview(data)
    if len(data) < HEADER.size:
        raise ValueError('truncated header')
    magic, count, nodes, inline, bound = HEADER.unpack_from(data)
    if magic != MAGIC or count > 256 or nodes > 4096 or inline > 4096 or bound > 4096:
        raise ValueError('invalid image header')
    expected = HEADER.size + count * DESCRIPTOR.size + inline * RECORD.size + nodes * NODE.size
    if len(data) != expected:
        raise ValueError('truncated or trailing image')
    if max_hops is not None:
        if type(max_hops) is not int or max_hops < 0:
            raise ValueError('invalid hop bound')
        bound = min(bound, max_hops)
    inline_start = HEADER.size + count * DESCRIPTOR.size
    node_start = inline_start + inline * RECORD.size
    node_values = [NODE.unpack_from(data, node_start + i * NODE.size) for i in range(nodes)]
    # Canonical images store shorter tails first. This validates even unreachable
    # nodes and excludes cycles before any pointer traversal.
    for index, node in enumerate(node_values):
        if node[4] != NIL and node[4] >= index:
            raise ValueError('cyclic or noncanonical shared-tail graph')
    result = []
    for i in range(count):
        start, size, head, total = DESCRIPTOR.unpack_from(data, HEADER.size + i * DESCRIPTOR.size)
        if start > inline or size > inline - start or total > 4096 or size > total:
            raise ValueError('invalid list descriptor')
        records = [RECORD.unpack_from(data, inline_start + (start + j) * RECORD.size) for j in range(size)]
        hops = 0
        while head != NIL:
            if head >= nodes or hops >= bound or len(records) >= total:
                raise ValueError('invalid shared tail or hop bound')
            records.append(node_values[head][:4])
            head = node_values[head][4]
            hops += 1
        if len(records) != total:
            raise ValueError('candidate length mismatch')
        validate_records(records)
        result.append(tuple(records))
    return tuple(result)


class Problem:
    def __init__(self, lists, max_hops=16):
        self.lists = tuple(tuple(tuple(r) for r in records) for records in lists)
        if (type(max_hops) is not int or not 0 <= max_hops <= 4096 or
                len(self.lists) > 256 or sum(map(len, self.lists)) > 4096):
            raise ValueError('bounded experiment dimensions exceeded')
        self.max_hops = max_hops
        tails = set()
        for records in self.lists:
            validate_records(records)
            tails.update(records[-j:] for j in range(1, min(len(records), max_hops) + 1))
        self.tails = sorted(tails, key=lambda t: (len(t), t))
        self.model = BooleanModel()
        self.nodes = {tail: self.model.new() for tail in self.tails}
        for tail, variable in self.nodes.items():
            self.model.costs.append((variable, NODE.size))
            if len(tail) > 1:
                self.model.hard.append([-variable, self.nodes[tail[1:]]])
        self.choices = []
        for records in self.lists:
            choices = []
            for length in range(min(len(records), max_hops) + 1):
                variable = self.model.new()
                choices.append((length, variable))
                self.model.costs.append((variable, (len(records) - length) * RECORD.size))
                if length:
                    self.model.hard.append([-variable, self.nodes[records[-length:]]])
            self.model.exactly_one(v for _, v in choices)
            self.choices.append(choices)

    def solve(self):
        chosen, cost, metrics = self.model.solve()
        lengths = tuple(next(length for length, variable in choices if variable in chosen)
                        for choices in self.choices)
        image = Image(self.lists, lengths, self.max_hops)
        if image.variable_bytes != cost:
            raise AssertionError('serialized and solver byte costs differ')
        if decode_image(image.to_bytes()) != self.lists:
            raise AssertionError('exact candidate reconstruction failed')
        return image, metrics

    def raw(self):
        return Image(self.lists, (0,) * len(self.lists), self.max_hops)

    def always_share(self):
        return Image(self.lists, tuple(min(len(records), self.max_hops) for records in self.lists), self.max_hops)

    def greedy(self):
        selected = set()

        def materialize(nodes):
            lengths = tuple(max((j for j in range(1, min(len(records), self.max_hops) + 1)
                                 if records[-j:] in nodes), default=0)
                            for records in self.lists)
            return Image(self.lists, lengths, self.max_hops)

        current = materialize(selected)
        while True:
            possibilities = []
            for tail in self.tails:
                if tail not in selected:
                    addition = {tail[j:] for j in range(len(tail))}
                    nodes = selected | addition
                    image = materialize(nodes)
                    possibilities.append((image.variable_bytes, tail, nodes, image))
            if not possibilities:
                return current
            cost, _, nodes, image = min(possibilities, key=lambda x: (x[0], x[1]))
            if cost >= current.variable_bytes:
                return current
            selected, current = nodes, image


def exhaustive_minimum(lists, max_hops):
    """Independent list-choice enumeration; does not use Image or model costs."""
    best = None
    for lengths in itertools.product(*(range(min(len(r), max_hops) + 1) for r in lists)):
        tails, inlined = set(), 0
        for records, length in zip(lists, lengths):
            records = tuple(records)
            inlined += len(records) - length
            for j in range(1, length + 1):
                tails.add(records[-j:])
        cost = 16 * inlined + 20 * len(tails)
        best = cost if best is None else min(best, cost)
    return best


def fixture_lists():
    from transitions import byte_ac, read_public_patterns
    patterns, provenance = read_public_patterns()
    _, outputs = byte_ac(patterns)
    lists = [make_records(patterns, ids) for ids in outputs if ids]
    return lists, provenance


def run_case(name, lists, max_hops=16, provenance=None):
    problem = Problem(lists, max_hops)
    optimum, metrics = problem.solve()
    variants = {'raw': problem.raw(), 'always_share': problem.always_share(),
                'greedy': problem.greedy(), 'joint': optimum}
    measurements = {}
    for label, image in variants.items():
        blob = image.to_bytes()
        if decode_image(blob) != problem.lists:
            raise AssertionError('exact reconstruction failed')
        begin = time.process_time()
        for _ in range(200):
            decode_image(blob)
        cpu = time.process_time() - begin
        scratch = max(map(len, lists), default=0) * RECORD.size
        measurements[label] = {'image_bytes': len(blob), 'variable_bytes': image.variable_bytes,
                               'cold_image_bytes': len(blob), 'fully_hydrated_image_bytes': len(blob),
                               'maximum_list_record_payload_bytes': scratch,
                               'aggregate_decoded_record_payload_bytes': sum(map(len, lists)) * RECORD.size,
                               'reload_two_images_plus_two_modeled_list_payloads_bytes': 2 * (len(blob) + scratch),
                               'python_decode_cpu_seconds_200_full_passes': cpu,
                               'sha256': hashlib.sha256(blob).hexdigest()}
    return {'case': name, 'lists': len(lists), 'record_occurrences': sum(map(len, lists)),
            'unique_candidate_tail_nodes': len(problem.tails), 'maximum_shared_hops': max_hops,
            'common_descriptor_bytes': optimum.common_bytes,
            'solver': metrics, 'measurements': measurements,
            'every_full_record_and_order_verified': True, 'sources': provenance or []}


def main():
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=root / 'docs/solver-five-results/candidates.json')
    args = parser.parse_args()
    public, provenance = fixture_lists()
    tail = tuple((100 + i, 1000 + i, i % 4, NIL) for i in range(5))
    shared = [((i, i, i % 4, NIL),) + tail for i in range(8)]
    distinct = [tuple((100 * i + j, 100 * i + j, j % 4, NIL) for j in range(6)) for i in range(5)]
    # Equal pattern values with different occurrence IDs and attributes must not
    # accidentally merge; each tuple and its next_same coordinate survives.
    duplicates = [((7, i * 10, 1, i * 10 + 1), (7, i * 10 + 1, 3, NIL)) for i in range(4)]
    cases = [run_case('public-literal-byte-ac-output-lists', public, provenance=provenance),
             run_case('synthetic-common-tail', shared),
             run_case('synthetic-all-distinct', distinct),
             run_case('synthetic-duplicate-pattern-different-identities', duplicates),
             run_case('synthetic-hop-bound-two', shared, max_hops=2)]
    witness = Problem([tail[-2:]] * 3, 2)
    image, _ = witness.solve()
    assert image.variable_bytes == exhaustive_minimum(witness.lists, 2)
    result = {'experiment': 'ordered candidate suffix sharing',
              'scope': 'offline byte-AC lists and synthetic tuple records; not ClamAV allocation or callback-order qualification',
              'record_format': 'four uint32: pattern identity, occurrence identity, attributes, next_same occurrence; shared node adds uint32 next',
              'cases': cases,
              'fixed_width_feasibility_audit': witness.model.verify_budget(image.variable_bytes),
              'small_exhaustive_oracle_agrees': True,
              'limitations': ['The byte-only AC builder supplies model order; it does not reproduce ClamAV address-based ordering.',
                              'Public-list attributes are deterministic test attributes, not engine severity metadata.',
                              'No names are dropped and every record/order/multiplicity/next_same coordinate reconstructs exactly.',
                              'The images have no decoded cache; physical RSS and whole-engine/reload peaks were not measured.',
                              'The Python decoder materializes all lists; payload counts exclude Python objects and are not an actual temporary-peak or native scratch measurement.',
                              'Two-image plus two list-payload accounting is a prospective one-list-at-a-time decoder estimate, not measured Python reload RAM.',
                              'This restricted suffix family is also a weighted closure problem; it does not establish a need for an expensive counting solver.']}
    path = args.output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'path': str(path), 'cases': [{k: c[k] for k in ('case', 'lists', 'record_occurrences')}
                                                  | {'image_bytes': {n: m['image_bytes'] for n, m in c['measurements'].items()}}
                                                 for c in cases]}))


if __name__ == '__main__':
    main()
