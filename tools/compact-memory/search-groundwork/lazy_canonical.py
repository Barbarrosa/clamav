#!/usr/bin/env python3
"""A compact random-access view of the linked theorem's canonical input.

The view represents exactly canonical_input.canonical_bits without expanding
unary literal codes. Its prefix index has one entry per canonical clause.
This is an input adapter, not the linked counter, nor a faithful simulation of
the counter's formal steps. Skipping runs accelerates access to an encoding;
it does not justify skipping the published machine's work on those bits.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
from array import array
from bisect import bisect_right
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys
import time

from canonical_input import CanonicalCNF, canonical_bit_length, parse_dimacs

DEFAULT_MAX_READ_BITS = 1024 * 1024
UINT64_MAX = (1 << 64) - 1


def _natural(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be a nonnegative integer')
    return value


class LazyCanonicalInput:
    """Read-only Boolean tape view using O(m) extra prefix-index storage.

    Input CanonicalCNF already occupies O(m + literal occurrences). A bit lookup
    costs O(log m + k), where k is the maximum canonical clause width (three in
    our queries), independent of the expanded unary literal length. run_at()
    identifies the end of the current constant-bit run without visiting its bits.
    """

    def __init__(self, formula, *, max_read_bits=DEFAULT_MAX_READ_BITS):
        if not isinstance(formula, CanonicalCNF):
            raise ValueError('formula must be an already canonical CanonicalCNF')
        _natural(max_read_bits, 'max_read_bits')
        self.formula = formula
        self.max_read_bits = max_read_bits
        self.logical_bits = canonical_bit_length(formula)
        self._header_end = formula.num_variables + 1
        # Use packed machine integers for ordinary inputs. The arbitrary-size
        # fallback still has only m entries, including for huge symbolic n.
        self._ends = array('Q') if self.logical_bits <= UINT64_MAX else []
        total = 0
        for clause in formula.clauses:
            total += 4 + sum(8 + 4 * code for code in clause)
            self._ends.append(total)
        self._clause_bits = total
        if self.logical_bits != self._header_end + total + 1:
            raise AssertionError('prefix index differs from exact canonical length')

    @property
    def index_storage_bytes(self):
        """Index container and integer storage; excludes the shared formula."""
        if isinstance(self._ends, array):
            return sys.getsizeof(self._ends)
        return sys.getsizeof(self._ends) + sum(map(sys.getsizeof, self._ends))

    @property
    def index_format(self):
        return 'packed uint64 clause ends' if isinstance(self._ends, array) else 'arbitrary-size integer clause ends'

    def _position(self, position, *, allow_end=False):
        _natural(position, 'position')
        if position > self.logical_bits or position == self.logical_bits and not allow_end:
            raise ValueError('position is outside the canonical Boolean input')

    def _span_at(self, position):
        """Return a constant grammar piece containing position: (bit, end)."""
        n = self.formula.num_variables
        if position < n:
            return True, n
        if position == n:
            return False, self._header_end
        relative = position - self._header_end
        if relative == self._clause_bits:
            return False, self.logical_bits
        index = bisect_right(self._ends, relative)
        start = self._header_end + (self._ends[index - 1] if index else 0)
        offset = position - start
        if offset == 0:
            return True, start + 1
        at = start + 1
        # After both frames a literal c is 1^(4c+5),0,1,0.
        for code in self.formula.clauses[index]:
            ones_end = at + 4 * code + 5
            if position < ones_end:
                return True, ones_end
            if position == ones_end:
                return False, ones_end + 1
            if position == ones_end + 1:
                return True, ones_end + 2
            if position == ones_end + 2:
                return False, ones_end + 3
            at = ones_end + 3
        # The inner list terminator, its outer frame terminator: 1,0,0.
        if position == at:
            return True, at + 1
        if position < at + 3:
            return False, at + 3
        raise AssertionError('clause prefix index failed to locate a grammar piece')

    def bit_at(self, position):
        self._position(position)
        return self._span_at(position)[0]

    def run_at(self, position):
        """Return (bit, exclusive_end) for the run starting at this position.

        The position can be in the middle of a run. Adjacent equal grammar
        pieces are coalesced, so iter_runs emits maximal runs except at its
        requested start/stop boundaries.
        """
        self._position(position)
        bit, end = self._span_at(position)
        while end < self.logical_bits:
            next_bit, next_end = self._span_at(end)
            if next_bit != bit:
                break
            end = next_end
        return bit, end

    def skip_run(self, position):
        return self.run_at(position)[1]

    def iter_runs(self, start=0, stop=None):
        """Yield (Boolean value, run length), without per-bit expansion."""
        stop = self.logical_bits if stop is None else stop
        self._position(start, allow_end=True)
        self._position(stop, allow_end=True)
        if stop < start:
            raise ValueError('stop precedes start')
        position = start
        while position < stop:
            bit, end = self.run_at(position)
            end = min(end, stop)
            yield bit, end - position
            position = end

    def iter_bits(self, start=0, stop=None):
        stop = self.logical_bits if stop is None else stop
        self._position(start, allow_end=True)
        self._position(stop, allow_end=True)
        if stop < start:
            raise ValueError('stop precedes start')
        if stop - start > self.max_read_bits:
            raise ValueError('expanded read exceeds max_read_bits')
        for bit, length in self.iter_runs(start, stop):
            yield from itertools.repeat(bit, length)

    def window(self, start, count):
        _natural(count, 'count')
        return tuple(self.iter_bits(start, start + count))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cnf', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--random-reads', type=int, default=10000)
    parser.add_argument('--run-limit', type=int, default=10000)
    parser.add_argument('--window-bits', type=int, default=64)
    parser.add_argument('--seed', type=int, default=378)
    args = parser.parse_args()
    if (not 0 <= args.random_reads <= 1000000 or not 0 <= args.run_limit <= 1000000
            or not 0 <= args.window_bits <= DEFAULT_MAX_READ_BITS):
        parser.error('benchmark reads/runs must be in 0..1000000 and window must respect expansion cap')
    start = time.perf_counter()
    raw = args.cnf.read_bytes()
    formula = parse_dimacs(raw.decode('ascii'))
    parsed = time.perf_counter()
    view = LazyCanonicalInput(formula)
    indexed = time.perf_counter()
    rng, checksum = random.Random(args.seed), hashlib.sha256()
    for _ in range(args.random_reads):
        position = rng.randrange(view.logical_bits)
        checksum.update(str(position).encode('ascii') + b':' + bytes((view.bit_at(position),)))
    random_done = time.perf_counter()
    runs, logical_covered = 0, 0
    for bit, length in itertools.islice(view.iter_runs(), args.run_limit):
        checksum.update(bytes((bit,)) + str(length).encode('ascii') + b';')
        logical_covered += length
        runs += 1
    runs_done = time.perf_counter()
    window = view.window(0, min(args.window_bits, view.logical_bits))
    checksum.update(bytes(window))
    report = {'schema_version': 1, 'source_sha256': hashlib.sha256(raw).hexdigest(),
              'adapter_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'canonical_codec_source_sha256': hashlib.sha256(
                  Path(__file__).with_name('canonical_input.py').read_bytes()).hexdigest(),
              'source_bytes': len(raw), 'variables': formula.num_variables,
              'canonical_clauses': len(formula.clauses),
              'canonical_logical_bits': view.logical_bits,
              'packed_transport_bytes_if_materialized': (view.logical_bits + 7) // 8,
              'index_format': view.index_format, 'index_storage_bytes': view.index_storage_bytes,
              'dimacs_parse_seconds': parsed - start, 'index_build_seconds': indexed - parsed,
              'random_bit_reads': args.random_reads, 'random_read_seconds': random_done - indexed,
              'runs_visited': runs, 'logical_bits_covered_by_run_access': logical_covered,
              'run_access_seconds': runs_done - random_done,
              'checksum': checksum.hexdigest(), 'full_input_materialized': False,
              'linked_counting_algorithm_executed': False,
              'scope': 'compact canonical-input access only; not counting, frontend simulation or a formal-step shortcut',
              'complexity': {'extra_index_space': 'O(canonical clauses)',
                             'bit_access': 'O(log canonical clauses + clause width)',
                             'run_access': 'O(log canonical clauses + clause width) per run',
                             'expanded_window_limit_bits': view.max_read_bits},
              'limitations': ['The caller still holds the compact canonical formula.',
                             'Lazy access avoids an expanded resident input but does not eliminate the counter working state.',
                             'The literal published frontend copies/parses/clears canonical words bit by bit; skipping them needs an additional justified implementation.',
                             'This benchmark does not run the linked counting method or establish its time/space requirements.']}
    if sys.platform.startswith('linux'):
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        def limit(kind):
            soft, hard = resource.getrlimit(kind)
            return {'soft': None if soft == resource.RLIM_INFINITY else soft,
                    'hard': None if hard == resource.RLIM_INFINITY else hard}
        report['observed_resource_limits'] = {
            'address_space_bytes': limit(resource.RLIMIT_AS),
            'cpu_seconds': limit(resource.RLIMIT_CPU),
            'scope': 'per-process observed limits; address space differs from resident RAM'}
        report['process_highwater_rss_bytes'] = usage.ru_maxrss * 1024
        report['process_user_cpu_seconds'] = usage.ru_utime
        report['process_system_cpu_seconds'] = usage.ru_stime
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('canonical_logical_bits', 'index_storage_bytes',
                       'dimacs_parse_seconds', 'index_build_seconds', 'random_read_seconds',
                       'run_access_seconds', 'linked_counting_algorithm_executed')}))


if __name__ == '__main__':
    main()
