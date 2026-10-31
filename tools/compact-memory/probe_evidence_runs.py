#!/usr/bin/env python3
"""Differential model of exact evidence-stack run compression; no scanner change."""
from collections import OrderedDict
import argparse
import copy
import json
from pathlib import Path
import random


class Reference:
    def __init__(self): self.maps = [OrderedDict() for _ in range(3)]
    def push(self, kind, name, meta, count=1):
        self.maps[kind].setdefault(name, []).extend([meta] * count)
    def pop(self, kind, name):
        rows = self.maps[kind].get(name)
        if rows:
            rows.pop()
            if not rows: del self.maps[kind][name]
    def merge(self, other, normalize):
        for kind, table in enumerate(other.maps):
            for name, metas in table.items():
                for ptr, depth, obj in metas:
                    self.push(kind, name, (ptr, depth + (not normalize), obj))
    def expanded(self): return self.maps


class Runs:
    def __init__(self): self.maps = [OrderedDict() for _ in range(3)]
    def push(self, kind, name, meta, count=1):
        rows = self.maps[kind].setdefault(name, [])
        if rows and rows[-1][0] == meta: rows[-1][1] += count
        else: rows.append([meta, count])
    def pop(self, kind, name):
        rows = self.maps[kind].get(name)
        if rows:
            rows[-1][1] -= 1
            if not rows[-1][1]: rows.pop()
            if not rows: del self.maps[kind][name]
    def merge(self, other, normalize):
        for kind, table in enumerate(other.maps):
            for name, rows in table.items():
                for (ptr, depth, obj), count in rows:
                    self.push(kind, name, (ptr, depth + (not normalize), obj), count)
    def expanded(self):
        return [OrderedDict((name, [meta for meta, count in rows for _ in range(count)])
                            for name, rows in table.items()) for table in self.maps]


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--output', type=Path, required=True); args = p.parse_args()
    rng = random.Random(261027); refs = [Reference() for _ in range(4)]; runs = [Runs() for _ in range(4)]
    operations = 20000
    for _ in range(operations):
        dst = rng.randrange(4); kind = rng.randrange(3); name = rng.randrange(12); op = rng.randrange(10)
        if sum(len(x) for t in refs[dst].maps for x in t.values()) > 1000:
            refs[dst], runs[dst] = Reference(), Runs()
        if op < 6:
            # Same text can have different original pointers: never merge these.
            meta = (name * 2 + rng.randrange(2), rng.randrange(3), rng.randrange(3))
            count = rng.randrange(1, 8)
            refs[dst].push(kind, name, meta, count); runs[dst].push(kind, name, meta, count)
        elif op < 8:
            refs[dst].pop(kind, name); runs[dst].pop(kind, name)
        else:
            src = (dst + rng.randrange(1, 4)) % 4
            if op == 8:
                refs[dst], runs[dst] = copy.deepcopy(refs[src]), copy.deepcopy(runs[src])
            else:
                normalized = bool(rng.randrange(2))
                refs[dst].merge(refs[src], normalized); runs[dst].merge(runs[src], normalized)
        assert refs[dst].expanded() == runs[dst].expanded()
    # Pop is observable: a latest-value-only replacement is incorrect.
    rollback = Reference(); rollback.push(0, 'same-name', (100, 0, 1)); rollback.push(0, 'same-name', (200, 0, 2)); rollback.pop(0, 'same-name')
    assert rollback.maps[0]['same-name'][-1] == (100, 0, 1)
    flood = Runs(); flood.push(2, 'weak', (123, 0, 7), 1000000)
    for _ in range(100): flood.pop(2, 'weak')
    assert flood.maps[2]['weak'] == [[(123, 0, 7), 999900]]
    report = {'kind':'evidence_run_compression_model', 'random_operations':operations,
              'full_ordered_stacks_equal_after_every_operation':True,
              'pop_counterexample_to_latest_only_verified':True,
              'repeated_metas':1000000, 'native_64bit_uncompressed_payload_bytes':24000000,
              'native_meta_plus_u64_count_run_bytes':32,
              'distinct_meta_worst_case_run_overhead_fraction':1/3,
              'limitations':['Only a model; not an implementation or Rust/FFI test.',
                             'JSON metadata and callbacks must still preserve every required occurrence.',
                             'Plain RLE expands all-distinct stacks; a literal/run hybrid or measured fallback is required.',
                             'Count and depth overflow, allocation behavior and API lifecycle need native tests.']}
    args.output.write_text(json.dumps(report,indent=2)+'\n'); print(args.output)


if __name__ == '__main__': main()
