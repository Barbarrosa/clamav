#!/usr/bin/env python3
"""Reject an infeasible resident boundary from a matching engine_census run.

This is a lower-bound check, not an acceptance test: omitted subsystems can
only increase the total. A subtotal below the budget is inconclusive.
"""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('census', type=Path)
    parser.add_argument('--budget-mb', type=int, default=200, help='Decimal MB, not MiB')
    args = parser.parse_args()
    if args.budget_mb <= 0:
        parser.error('budget must be positive')
    records = [json.loads(line) for line in args.census.read_text().splitlines() if line.strip()]
    floors = [r for r in records if r.get('kind') == 'resident_floor_components']
    if len(floors) != 1:
        parser.error('expected exactly one resident_floor_components record')
    floor = floors[0]
    keys = ('ac_core_bytes', 'unique_name_bytes', 'logical_records_bytes')
    if any(type(floor.get(k)) is not int or floor[k] < 0 for k in keys):
        parser.error('invalid component byte count')
    subtotal = sum(floor[k] for k in keys)
    budget = args.budget_mb * 1_000_000
    print(json.dumps({
        'architecture': 'resident routing, stable interned names, current logical descriptors',
        'components': {k: floor[k] for k in keys},
        'subtotal_bytes': subtotal,
        'subtotal_mib': subtotal / 1048576,
        'budget_bytes': budget,
        'gate': 'blocked' if subtotal > budget else 'inconclusive',
        'concurrent_reload_subtotal_bytes': 2 * subtotal,
        'excludes': ['cache', 'scan and parser state', 'code and runtime',
                     'logical expression and target metadata payloads',
                     'other resident matchers and compatibility objects',
                     'allocator overhead', 'build scratch', 'kernel file cache'],
        'interpretation': 'A bound for the planned layouts, not an information-theoretic limit.'
    }, indent=2))
    if subtotal > budget:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
