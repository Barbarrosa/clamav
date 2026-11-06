#!/usr/bin/env python3
"""Analyze fixed-record pool size classes, not resident memory or live traces.

The normal LP64 mpool header is two bytes. Fresh allocations use the actual
alignment padding; free-list lookup uses its conservative maximum. This tool
inspects the production size table and validates the relevant source patterns.
Its independent test executes the production allocator over all start residues.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from bisect import bisect_left
import hashlib
import json
from pathlib import Path
import re


HEADER_BYTES = 2


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inspect_source(path):
    text = Path(path).read_text()
    match = re.search(r'#if SIZEOF_VOID_P == 8\s+static const unsigned int fragsz\[\] = \{(.*?)\};', text, re.S)
    if not match:
        raise ValueError('LP64 production size table not found')
    body = re.sub(r'/\*.*?\*/', '', match.group(1), flags=re.S)
    if re.sub(r'[\d,\s]', '', body):
        raise ValueError('unexpected expression in size table')
    classes = [int(v) for v in re.findall(r'\d+', body)]
    if not classes or classes != sorted(set(classes)):
        raise ValueError('size classes must be strictly increasing')
    if not re.search(r'struct alloced\s*\{\s*uint8_t padding;\s*uint8_t sbits;\s*uint8_t fake;\s*\};', text):
        raise ValueError('normal two-byte allocation header layout changed')
    guards = ('uint8_t padding;', 'uint8_t sbits;', 'uint8_t fake;',
              '#define FRAG_OVERHEAD (offsetof(struct FRAG, u.a.fake))',
              '#undef CL_DEBUG /* bb#2222 */', 'switch (size % 8)',
              'unsigned realneed  = p_aligned + size - mpm->usize;',
              'size_t i, needed = align_increase(size + FRAG_OVERHEAD, align);')
    for guard in guards:
        if guard not in text:
            raise ValueError('inspected source pattern changed: ' + guard)
    return classes


def alignment(size):
    if type(size) is not int or size < 1:
        raise ValueError('requested size must be a positive integer')
    return {0: 8, 2: 2, 6: 2, 4: 4}.get(size % 8, 1)


def profile(size, classes):
    align = alignment(size)
    rows = []
    for pad in range(align):
        needed = size + HEADER_BYTES + pad
        index = bisect_left(classes, needed)
        if index == len(classes):
            raise ValueError('request exceeds inspected size classes')
        charged = classes[index]
        rows.append({'alignment_padding': pad, 'needed_bytes': needed,
                     'fragment_charge_bytes': charged, 'tail_rounding_bytes': charged - needed})
    charges = [r['fragment_charge_bytes'] for r in rows]
    tails = [r['tail_rounding_bytes'] for r in rows]
    return {'requested_bytes': size, 'header_bytes': HEADER_BYTES, 'alignment': align,
            'alignment_padding_range': [0, align - 1],
            'fresh_carve_possible_charges': sorted(set(charges)),
            'charge_above_payload_range': [min(charges) - size, max(charges) - size],
            'tail_rounding_range': [min(tails), max(tails)],
            'free_list_lookup_class': max(charges), 'by_alignment_padding': rows}


def analyze(source, capture_path):
    classes = inspect_source(source)
    if profile(1024, classes)['fresh_carve_possible_charges'] != [1176] or profile(168, classes)['fresh_carve_possible_charges'] != [196]:
        raise ValueError('illustrative proposals must be updated for the changed baseline classes')
    raw = json.loads(Path(capture_path).read_text())
    capture = raw['capture']
    sizes = capture['native_sizes']
    if sizes['pointer'] != 8:
        raise ValueError('this assessment requires the recorded LP64 capture')
    if sizes['logical'] != 168 or capture['transition_values'] != 256 * capture['transition_rows']:
        raise ValueError('the illustrative class proposals require 168-byte logical records and 256-wide rows')
    if capture['native_family_bytes']['transition_values'] != 1024 * capture['transition_rows']:
        raise ValueError('the row assessment requires four-byte transitions')
    definitions = [('patterns', 'pattern', 'patterns'),
                   ('candidates', 'candidate', 'candidate_records'),
                   ('logical_records', 'logical', 'logical_records'),
                   ('extensions', 'extension', 'extensions')]
    families = []
    for name, size_key, count_key in definitions:
        size, count = sizes[size_key], capture[count_key]
        families.append((name, size, count))
    families.append(('transition_rows', 256 * 4, capture['transition_rows']))
    rows = []
    for name, size, count in families:
        p = profile(size, classes)
        low, high = p['charge_above_payload_range']
        rows.append({'family': name, 'retained_record_count': count,
                     'payload_bytes': count * size, 'baseline': p,
                     'total_charge_above_payload_range_bytes': [count * low, count * high],
                     'padded_request_profiles': {str(d): profile(size + d, classes) for d in (8, 32)}})
    row_count = capture['transition_rows']
    logical_count = capture['logical_records']
    return {'schema_version': 1, 'scope': 'LP64 fixed-record pool fragment charges; not RSS or a live allocation trace',
            'analysis_implementation_sha256': digest(__file__),
            'mpool_source_sha256': digest(source), 'capture_summary_sha256': digest(capture_path),
            'capture_source_base_commit': raw['source_base_commit'],
            'header_bytes': HEADER_BYTES,
            'size_classes': classes, 'families': rows,
            'builder_node_record_profile': profile(sizes['node'], classes),
            'builder_node_scope': 'individual old builder nodes are freed after packing; retained flat-node arenas use libc calloc, so per-node pool charges do not apply to them',
            'hypothetical_class_examples': [
                {'new_class_bytes': 1040, 'family': 'transition_rows',
                 'reason': '1024+2+maximum alignment padding 7 fits 1040; existing class is1176',
                 'fragment_charge_reduction_per_record': 136,
                 'historical_capture_charge_reduction_bytes': 136 * row_count},
                {'new_class_bytes': 184, 'family': 'logical_records',
                 'reason': '168+2+maximum alignment padding7 fits184; existing class is196',
                 'fragment_charge_reduction_per_record': 12,
                 'historical_capture_charge_reduction_bytes': 12 * logical_count}],
            'limitations': [
                'The counts come from the cited earlier full-engine capture, not the perturbation run counters.',
                'Charge above payload includes necessary metadata and alignment, not only potentially avoidable rounding.',
                'Fresh carve padding depends on preceding allocation addresses; exact per-record charges were not traced.',
                'Free-list selection uses the worst-case class, while fresh carving may select a smaller class.',
                'Mapped page slack, free fragments, growing directories, names and variable token buffers are outside this fixed-record subtotal.',
                'Prospective size classes are arithmetic examples, not implemented allocator changes or measured RSS savings.',
                'Changing size classes can alter addresses, duplicate-order behavior, reuse, construction and reload peaks.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='libclamav/mpool.c')
    parser.add_argument('--capture-summary', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.source, args.capture_summary)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'families': len(result['families']), 'header_bytes': HEADER_BYTES,
                      'hypothetical_class_examples': result['hypothetical_class_examples']}))


if __name__ == '__main__':
    main()
