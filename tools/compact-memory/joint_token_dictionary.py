#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Joint fragment activation and exact token parsing with weighted MaxSAT.

Offline, trusted-export research only. No scanner representation is changed.
Requires python-sat (RC2). Optimality is only for the enumerated flat dictionary,
fixed 16-bit codes, raw fallback and the documented byte/decode-work model.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import time

from pysat.card import CardEnc, EncType
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

MAGIC = b'JTDICT1\0'
HEADER = struct.Struct('<8sIIII')
MAX_ENTRIES = 65536 - 256
MAX_INPUT_BYTES = 4096


@dataclass(frozen=True)
class Row:
    raw: bool
    payload: bytes
    decoded_length: int
    wide: bool = False


@dataclass(frozen=True)
class Layout:
    dictionary: tuple[bytes, ...]
    rows: tuple[Row, ...]

    @property
    def objective_bytes(self):
        return sum(len(x) + 4 for x in self.dictionary) + sum(len(r.payload) for r in self.rows)

    @property
    def common_bytes(self):
        # Header, dictionary terminal, row terminal/offsets, lengths, mode/width.
        return HEADER.size + 4 + (len(self.rows) + 1) * 4 + len(self.rows) * 5

    @property
    def total_bytes(self):
        return self.common_bytes + self.objective_bytes

    @property
    def scratch_bytes(self):
        return max((r.decoded_length for r in self.rows), default=0)

    def to_bytes(self):
        if len(self.dictionary) > MAX_ENTRIES:
            raise ValueError('dictionary exceeds 16-bit code space')
        dindex = [0]
        for fragment in self.dictionary:
            if not fragment:
                raise ValueError('empty dictionary fragment')
            dindex.append(dindex[-1] + len(fragment))
        rindex = [0]
        for row in self.rows:
            rindex.append(rindex[-1] + len(row.payload))
        values = dindex + rindex + [r.decoded_length for r in self.rows]
        if any(v >= 1 << 32 or v < 0 for v in values):
            raise ValueError('32-bit image bounds exceeded')
        image = bytearray(HEADER.pack(MAGIC, len(self.rows), len(self.dictionary), self.scratch_bytes, 0))
        image.extend(struct.pack('<' + 'I' * len(dindex), *dindex))
        image.extend(b''.join(self.dictionary))
        image.extend(struct.pack('<' + 'I' * len(rindex), *rindex))
        image.extend(struct.pack('<' + 'I' * len(self.rows), *(r.decoded_length for r in self.rows)))
        image.extend(bytes(int(r.raw) | (int(r.wide) << 1) for r in self.rows))
        image.extend(b''.join(r.payload for r in self.rows))
        if len(image) != self.total_bytes:
            raise AssertionError('serialized cost mismatch')
        return bytes(image)


def decode_image(image, max_decode_steps=None):
    """Independent bounded decoder. Work = output bytes + encoded codewords.

    Raw rows cost output bytes; there is no recursive dictionary or decoded cache.
    This operation count is a model, not CPU instructions or a latency guarantee.
    """
    image = memoryview(image)
    if len(image) < HEADER.size:
        raise ValueError('truncated header')
    magic, nrows, ndict, maxdecoded, reserved = HEADER.unpack_from(image)
    # This image is bounded to the offline experiment, not a general format.
    if magic != MAGIC or reserved or ndict > MAX_ENTRIES or nrows > 256 or maxdecoded > MAX_INPUT_BYTES:
        raise ValueError('invalid header')
    pos = HEADER.size

    def u32s(count):
        nonlocal pos
        if count > (len(image) - pos) // 4:
            raise ValueError('truncated directory')
        values = struct.unpack_from('<' + 'I' * count, image, pos)
        pos += count * 4
        return values

    dindex = u32s(ndict + 1)
    if dindex[0] or any(a >= b for a, b in zip(dindex, dindex[1:])):
        raise ValueError('invalid dictionary offsets')
    if dindex[-1] > len(image) - pos:
        raise ValueError('truncated dictionary')
    dictionary_data = image[pos:pos + dindex[-1]]
    pos += dindex[-1]
    rindex = u32s(nrows + 1)
    lengths = u32s(nrows)
    if rindex[0] or any(a > b for a, b in zip(rindex, rindex[1:])):
        raise ValueError('invalid row offsets')
    if nrows > len(image) - pos:
        raise ValueError('truncated flags')
    flags = image[pos:pos + nrows]
    pos += nrows
    if rindex[-1] != len(image) - pos:
        raise ValueError('truncated or trailing row payload')
    if max(lengths, default=0) != maxdecoded:
        raise ValueError('invalid maximum decoded size')
    output, widths = [], []
    for i in range(nrows):
        flag, expected = flags[i], lengths[i]
        if flag & ~3 or (flag & 2 and expected % 2):
            raise ValueError('invalid row flags or wide-token length')
        payload = image[pos + rindex[i]:pos + rindex[i + 1]]
        if flag & 1:
            if len(payload) != expected:
                raise ValueError('raw length mismatch')
            work = expected
            if max_decode_steps is not None and work > max_decode_steps:
                raise ValueError('decode-work bound exceeded')
            decoded = bytes(payload)
        else:
            if len(payload) % 2:
                raise ValueError('odd code stream')
            work = expected + len(payload) // 2
            if max_decode_steps is not None and work > max_decode_steps:
                raise ValueError('decode-work bound exceeded')
            # Count output first, so corrupt expanded lengths cannot grow output.
            count = 0
            for (code,) in struct.iter_unpack('<H', payload):
                if code < 256:
                    count += 1
                else:
                    j = code - 256
                    if j >= ndict:
                        raise ValueError('unknown dictionary code')
                    count += dindex[j + 1] - dindex[j]
                if count > expected:
                    raise ValueError('decoded output exceeds declared length')
            if count != expected:
                raise ValueError('decoded length mismatch')
            result = bytearray()
            for (code,) in struct.iter_unpack('<H', payload):
                if code < 256:
                    result.append(code)
                else:
                    j = code - 256
                    result.extend(dictionary_data[dindex[j]:dindex[j + 1]])
            decoded = bytes(result)
        output.append(decoded)
        widths.append(bool(flag & 2))
    return output, widths


def candidate_fragments(rows, max_candidates=32, max_fragment=16):
    counts = Counter()
    for row in rows:
        for start in range(len(row)):
            for size in range(3, min(max_fragment, len(row) - start) + 1):
                counts[row[start:start + size]] += 1
    # Gross score is a candidate filter only; it can double-count overlaps.
    ranked = sorted((fragment for fragment, count in counts.items() if count >= 2),
                    key=lambda f: (-(counts[f] * (len(f) - 2) - len(f) - 4), -len(f), f))
    return ranked[:max_candidates]


class Problem:
    """Byte-exact shared dictionary and per-row path optimization.

    hard/costs/variable_map expose the same problem to budget-CNF experiments.
    Costs omit common_bytes, which is constant for a fixed row set.
    """
    def __init__(self, rows, widths=None, candidates=None, max_candidates=32,
                 max_fragment=16, max_decode_steps=None):
        self.rows = tuple(bytes(row) for row in rows)
        self.widths = tuple(bool(x) for x in widths) if widths is not None else (False,) * len(rows)
        if len(self.widths) != len(self.rows):
            raise ValueError('width count mismatch')
        if any(w and len(r) % 2 for r, w in zip(self.rows, self.widths)):
            raise ValueError('wide token length must be even')
        if not 0 <= max_candidates <= 64 or not 3 <= max_fragment <= 64:
            raise ValueError('candidate limits exceeded')
        if sum(map(len, self.rows)) > MAX_INPUT_BYTES or len(self.rows) > 256:
            raise ValueError('experiment slice exceeds 4096 bytes or 256 rows')
        if max_decode_steps is not None and (type(max_decode_steps) is not int or max_decode_steps < 0):
            raise ValueError('invalid decode-work bound')
        self.max_decode_steps = max_decode_steps
        if candidates is None:
            candidates = candidate_fragments(self.rows, max_candidates, max_fragment)
        self.candidates = tuple(sorted(set(bytes(x) for x in candidates)))
        if len(self.candidates) > 64 or any(not 3 <= len(x) <= 64 for x in self.candidates):
            raise ValueError('explicit candidate limits exceeded')
        self.hard, self.costs, self.variable_map = [], [], {}
        self.nv = 0
        self.dictionary_vars = [self._var({'kind': 'dictionary', 'candidate': i}) for i in range(len(self.candidates))]
        for v, fragment in zip(self.dictionary_vars, self.candidates):
            self.costs.append((v, len(fragment) + 4))
        self.raw_vars, self.edges = [], []
        for ri, row in enumerate(self.rows):
            raw = self._var({'kind': 'raw', 'row': ri})
            self.raw_vars.append(raw)
            if row:
                self.costs.append((raw, len(row)))
            edges, incoming, outgoing = [], [[] for _ in range(len(row) + 1)], [[] for _ in range(len(row) + 1)]
            for start in range(len(row)):
                options = [(start + 1, None, row[start])]
                options += [(start + len(f), ci, None) for ci, f in enumerate(self.candidates) if row.startswith(f, start)]
                for end, ci, literal in options:
                    v = self._var({'kind': 'edge', 'row': ri, 'start': start, 'end': end, 'candidate': ci})
                    edges.append((start, end, ci, literal, v))
                    outgoing[start].append(v)
                    incoming[end].append(v)
                    self.costs.append((v, 2))
                    self.hard.append([-v, -raw])
                    if ci is not None:
                        self.hard.append([-v, self.dictionary_vars[ci]])
            self.edges.append(edges)
            if not row:
                self.hard.append([raw])
            else:
                self.hard.extend([[raw] + outgoing[0], [raw] + incoming[-1]])
                for position in range(1, len(row)):
                    for v in incoming[position]:
                        self.hard.append([-v] + outgoing[position])
                    for v in outgoing[position]:
                        self.hard.append([-v] + incoming[position])
                for group in incoming + outgoing:
                    self._atmost(group, 1)
            if max_decode_steps is not None:
                if len(row) > max_decode_steps:
                    self.hard.append([])
                else:
                    # A forward path already has at most len(row) edges.
                    if max_decode_steps - len(row) < len(row):
                        self._atmost([e[-1] for e in edges], max_decode_steps - len(row))
        self._atmost(self.dictionary_vars, MAX_ENTRIES)

    @property
    def common_bytes(self):
        return HEADER.size + 4 + (len(self.rows) + 1) * 4 + len(self.rows) * 5

    def _var(self, meaning):
        self.nv += 1
        self.variable_map[self.nv] = meaning
        return self.nv

    def _atmost(self, literals, bound):
        if bound >= len(literals):
            return
        # Fail before constructing an unexpectedly large offline CNF. The bound
        # is deliberately small and explicit; this is not a full-DB compiler.
        if len(literals) * max(1, bound) > 2_000_000:
            raise ValueError('cardinality encoding exceeds experiment budget')
        encoded = CardEnc.atmost(lits=literals, bound=bound, top_id=self.nv, encoding=EncType.seqcounter)
        self.hard.extend(encoded.clauses)
        self.nv = max(self.nv, encoded.nv)
        if self.nv > 2_000_000 or len(self.hard) > 4_000_000:
            raise ValueError('CNF exceeds experiment budget')

    def wcnf(self):
        formula = WCNF()
        formula.extend(self.hard)
        for var, weight in self.costs:
            formula.append([-var], weight=weight)
        return formula

    def layout_from_model(self, model):
        chosen = set(v for v in model if v > 0)
        selected = [i for i, v in enumerate(self.dictionary_vars) if v in chosen]
        remap = {ci: index + 256 for index, ci in enumerate(selected)}
        result = []
        for i, row in enumerate(self.rows):
            if self.raw_vars[i] in chosen:
                result.append(Row(True, row, len(row), self.widths[i]))
                continue
            edges = {start: (end, ci, literal) for start, end, ci, literal, v in self.edges[i] if v in chosen}
            pos, codes = 0, []
            while pos < len(row):
                if pos not in edges:
                    raise ValueError('model has incomplete path')
                end, ci, literal = edges.pop(pos)
                codes.append(literal if ci is None else remap[ci])
                pos = end
            if edges:
                raise ValueError('model has disconnected path')
            result.append(Row(False, struct.pack('<' + 'H' * len(codes), *codes), len(row), self.widths[i]))
        layout = Layout(tuple(self.candidates[i] for i in selected), tuple(result))
        decoded, widths = decode_image(layout.to_bytes(), self.max_decode_steps)
        if decoded != list(self.rows) or widths != list(self.widths):
            raise AssertionError('independent reconstruction failed')
        return layout

    def solve(self):
        with RC2(self.wcnf()) as solver:
            model = solver.compute()
            if model is None:
                raise ValueError('infeasible decode bound')
            layout = self.layout_from_model(model)
            if layout.objective_bytes != solver.cost:
                raise AssertionError('model and serialized objective disagree')
            self.last_model = model
            return layout

    def fixed_dictionary(self, indices):
        """Independent shortest-path DP for a fixed dictionary (raw fallback).

        Deliberately charges every requested fragment, including unused ones.
        """
        selected = sorted(set(indices))
        if any(type(i) is not int or i < 0 or i >= len(self.candidates) for i in selected):
            raise ValueError('invalid candidate index')
        dictionary = tuple(self.candidates[i] for i in selected)
        result = []
        for row, wide in zip(self.rows, self.widths):
            if self.max_decode_steps is not None and len(row) > self.max_decode_steps:
                raise ValueError('infeasible decode bound')
            best = [None] * (len(row) + 1)
            best[0] = ()
            for pos in range(len(row)):
                if best[pos] is None:
                    continue
                choices = [(pos + 1, row[pos])]
                choices += [(pos + len(f), j + 256) for j, f in enumerate(dictionary) if row.startswith(f, pos)]
                for end, code in choices:
                    candidate = best[pos] + (code,)
                    if best[end] is None or len(candidate) < len(best[end]):
                        best[end] = candidate
            codes = best[-1]
            within_bound = self.max_decode_steps is None or len(row) + len(codes) <= self.max_decode_steps
            if within_bound and len(codes) * 2 < len(row):
                result.append(Row(False, struct.pack('<' + 'H' * len(codes), *codes), len(row), wide))
            else:
                result.append(Row(True, row, len(row), wide))
        return Layout(dictionary, tuple(result))

    def greedy(self):
        selected, layout = [], self.fixed_dictionary([])
        while True:
            candidates = [(self.fixed_dictionary(selected + [i]), i) for i in range(len(self.candidates)) if i not in selected]
            if not candidates:
                return layout
            better, i = min(candidates, key=lambda x: (x[0].objective_bytes, x[1]))
            if better.objective_bytes >= layout.objective_bytes:
                return layout
            selected.append(i)
            layout = better


def read_token_store(data_path, index_path):
    """Read prepare_token_store.py's byte-specialized, flagged-offset export."""
    data, index = Path(data_path).read_bytes(), Path(index_path).read_bytes()
    if len(index) < 4 or len(index) % 4:
        raise ValueError('invalid token index size')
    values = struct.unpack('<' + 'I' * (len(index) // 4), index)
    offsets = [v & 0x7fffffff for v in values]
    if offsets[0] or offsets[-1] != len(data) or values[-1] >> 31:
        raise ValueError('invalid token index endpoints')
    if any(a > b for a, b in zip(offsets, offsets[1:])):
        raise ValueError('nonmonotone token offsets')
    rows = [data[a:b] for a, b in zip(offsets, offsets[1:])]
    widths = [bool(v >> 31) for v in values[:-1]]
    if any(w and len(r) % 2 for r, w in zip(rows, widths)):
        raise ValueError('wide token length must be even')
    return rows, widths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--index', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--row-limit', type=int, default=32)
    parser.add_argument('--max-candidates', type=int, default=16)
    parser.add_argument('--max-fragment', type=int, default=16)
    parser.add_argument('--max-decode-steps', type=int)
    args = parser.parse_args()
    if args.row_limit < 1:
        parser.error('--row-limit must be positive')
    rows, widths = read_token_store(args.data, args.index)
    total_rows = len(rows)
    rows, widths = rows[:args.row_limit], widths[:args.row_limit]
    start = time.perf_counter()
    problem = Problem(rows, widths, max_candidates=args.max_candidates,
                      max_fragment=args.max_fragment, max_decode_steps=args.max_decode_steps)
    encoding_seconds = time.perf_counter() - start
    start = time.perf_counter()
    optimal = problem.solve()
    solve_seconds = time.perf_counter() - start
    baselines = {'raw': problem.fixed_dictionary([]), 'all_candidates': problem.fixed_dictionary(range(len(problem.candidates))), 'greedy': problem.greedy()}
    args.output.mkdir(parents=True, exist_ok=False)
    problem.wcnf().to_file(str(args.output / 'problem.wcnf'))
    (args.output / 'variable-map.json').write_text(json.dumps(problem.variable_map, indent=2) + '\n')
    (args.output / 'model.json').write_text(json.dumps(problem.last_model) + '\n')
    (args.output / 'layout.bin').write_bytes(optimal.to_bytes())
    result = {
        'scope': 'offline bounded slice, enumerated flat-fragment family; no scanner integration',
        'source_data_sha256': hashlib.sha256(args.data.read_bytes()).hexdigest(),
        'source_index_sha256': hashlib.sha256(args.index.read_bytes()).hexdigest(),
        'input_rows': total_rows, 'sample_rows': len(rows), 'sample': 'prefix',
        'source_payload_bytes': sum(map(len, rows)), 'candidate_count': len(problem.candidates),
        'max_decode_steps': args.max_decode_steps, 'decode_work': 'output bytes + encoded codewords (raw: output bytes)',
        'variables': problem.nv, 'hard_clauses': len(problem.hard), 'encoding_seconds': encoding_seconds,
        'solve_seconds': solve_seconds, 'optimal_total_bytes': optimal.total_bytes,
        'optimal_variable_bytes': optimal.objective_bytes, 'common_bytes': optimal.common_bytes,
        'scratch_bytes_per_decoder': optimal.scratch_bytes,
        'empty_and_hydrated_cache_layout_bytes': optimal.total_bytes,
        'old_new_reload_layout_bytes_for_equal_images': 2 * optimal.total_bytes,
        'baseline_total_bytes': {k: v.total_bytes for k, v in baselines.items()},
        'exact_bytes_and_widths_verified': True,
        'limitations': ['Serialized bytes exclude Python/solver allocator and construction peak.',
                        'Layout has no decoded cache; physical page residency and whole-engine RSS are not measured.',
                        'Reload figure is image bytes only, excludes builders, old/new decoder scratch and engine state.',
                        'No scanner order, severity, prefix-boundary metadata or end-to-end performance qualification.']}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
