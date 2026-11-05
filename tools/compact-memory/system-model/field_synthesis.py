#!/usr/bin/env python3
"""Synthesize a dependency-bounded field store from complete captured columns.

The query interface is GET(field_id, row_id). Field and row identities do not
change. Candidate access programs are validated against EVERY captured value;
MaxSAT chooses their global dependency graph and physical payload ownership.
This executes conventional RC2, not the linked Lean counting construction.
The access-work score excludes common descriptor dispatch/schema lookup. It
charges payload words, dependent GET steps and the declared integer primitives;
it is not a count of Python operations or processor instructions.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import struct
import sys
import time

import numpy as np
from pysat.card import CardEnc, EncType
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from joint_budget_cnf import budget_cnf

HEADER = struct.Struct('<8sII')
DESC = struct.Struct('<BBBBIQQQ')
MAGIC = b'FIELDS1\0'
STORE_XOR, CONST, ROW_AFFINE, ALIAS_XOR, ALIAS_ADD, STORE_BASE_NULL, SPARSE = range(7)
OP_NAMES = ['store_xor', 'constant', 'row_affine', 'alias_xor', 'alias_add', 'store_base_null', 'sparse_override']
NIL = (1 << 32) - 1
RANK_BLOCK = 512
CHUNK = 65536


def align8(size):
    return (size + 7) // 8 * 8


def packed_size(count, width):
    return align8((count * width + 7) // 8) + 8 if width else 0


def bitmap_size(count):
    return align8((count + 7) // 8) + 8


def rank_size(count):
    return align8(((count + RANK_BLOCK - 1) // RANK_BLOCK + 1) * 4)


def pack_values(values, width):
    values = np.asarray(values, dtype=np.uint64)
    if not 0 <= width <= 64:
        raise ValueError('invalid packed width')
    if width == 0:
        if np.any(values):
            raise ValueError('zero-width payload has nonzero values')
        return b''
    if width < 64 and np.any(values >> np.uint64(width)):
        raise ValueError('value exceeds packed width')
    output = bytearray(packed_size(len(values), width))
    for start in range(0, len(values), CHUNK):
        part = np.ascontiguousarray(values[start:start + CHUNK], dtype='<u8')
        bits = np.unpackbits(part.view(np.uint8).reshape(-1, 8), axis=1, bitorder='little')[:, :width]
        encoded = np.packbits(bits.reshape(-1), bitorder='little').tobytes()
        offset = start * width // 8
        output[offset:offset + len(encoded)] = encoded
    return bytes(output)


def unpack_values(data, width, count):
    """Vector decoder independent of scalar GET's aligned-word extraction."""
    if not 0 <= width <= 64 or len(data) < packed_size(count, width):
        raise ValueError('truncated packed payload')
    if not width:
        return np.zeros(count, dtype=np.uint64)
    output = np.empty(count, dtype=np.uint64)
    weights = np.left_shift(np.uint64(1), np.arange(width, dtype=np.uint64))
    for start in range(0, count, CHUNK):
        n = min(CHUNK, count - start)
        at = start * width // 8
        needed = (n * width + 7) // 8
        bits = np.unpackbits(np.frombuffer(data[at:at + needed], dtype=np.uint8), bitorder='little')[:n * width]
        output[start:start + n] = bits.reshape(n, width).astype(np.uint64) @ weights
    return output


def packed_get(data, offset, width, index):
    if width == 0:
        return 0
    bit = index * width
    at = offset + (bit // 64) * 8
    shift = bit % 64
    low, = struct.unpack_from('<Q', data, at)
    value = low >> shift
    if shift + width > 64:
        high, = struct.unpack_from('<Q', data, at + 8)
        value |= high << (64 - shift)
    return value & ((1 << width) - 1)


def word_reads(count, width):
    if width == 0 or count == 0:
        return 0
    # Query starts repeat with period 64/gcd(width,64). Check the actual period
    # rather than declaring every non-power-of-two width a straddling format.
    period = min(count, 64 // math.gcd(width, 64))
    return max(1 + int((i * width) % 64 + width > 64) for i in range(period))


@dataclass(frozen=True)
class Candidate:
    op: int
    width: int
    bits: int
    parent: int = NIL
    arg: int = 0
    count: int = 0
    increment: int = 0
    payload_bytes: int = 0


class FieldProblem:
    def __init__(self, columns, source_bits, max_depth=3, allow_sparse=True,
                 sparse_sample_agreement=0.75):
        started = time.perf_counter()
        if not 1 <= max_depth <= 64:
            raise ValueError('depth must be in 1..64')
        self.names = list(columns)
        if len(self.names) > 512:
            raise ValueError('at most 512 fields per captured family')
        self.columns = []
        self.source_bits = []
        self.max_depth = max_depth
        self.nrows = None
        for name in self.names:
            original = np.asarray(columns[name])
            bits = source_bits[name] if isinstance(source_bits, dict) else source_bits
            if original.ndim != 1 or original.dtype.kind not in 'ui' or not 1 <= bits <= 64:
                raise ValueError('columns must be one-dimensional unsigned integer values')
            if original.dtype.kind == 'i' and np.any(original < 0):
                raise ValueError('negative source field')
            values = np.array(original, dtype=np.uint64, copy=True)
            if bits < 64 and np.any(values >> np.uint64(bits)):
                raise ValueError('source value exceeds declared native field width')
            values.flags.writeable = False
            self.columns.append(values)
            self.source_bits.append(bits)
            if self.nrows is None:
                self.nrows = len(values)
            if len(values) != self.nrows:
                raise ValueError('all fields in a family must have equal row counts')
        self.nrows = self.nrows or 0
        if self.nrows >= 1 << 32:
            raise ValueError('row directory exceeds u32')
        self.hard, self.costs, self.nv = [], [], 0
        self.candidates = []
        self.sample_rejected_sparse_pairs = 0
        self.full_validated_relations = 0
        self.constant_fields = [not self.nrows or bool(np.all(values == values[0]))
                                for values in self.columns]
        sample = np.linspace(0, max(0, self.nrows - 1), min(64, self.nrows), dtype=np.int64)
        for field, (values, bits) in enumerate(zip(self.columns, self.source_bits)):
            mask = (1 << bits) - 1
            options = []
            if self.constant_fields[field]:
                options.append(Candidate(CONST, 0, bits, arg=int(values[0]) if self.nrows else 0))
            else:
                # Every legal physical width is considered. XOR baselines use
                # both zero and the first value; NULL bases preserve zero exactly.
                for base in sorted({0, int(values[0])}):
                    encoded = values ^ np.uint64(base)
                    minimum = int(np.bitwise_or.reduce(encoded)).bit_length()
                    for width in range(max(1, minimum), bits + 1):
                        work = word_reads(self.nrows, width) + int(base != 0)
                        if work <= max_depth:
                            options.append(Candidate(STORE_XOR, width, bits, arg=base,
                                                     increment=work, payload_bytes=packed_size(self.nrows, width)))
                nonzero = values[values != 0]
                if len(nonzero):
                    base = int(nonzero.min())
                    encoded = np.zeros_like(values)
                    nz = values != 0
                    encoded[nz] = values[nz] - np.uint64(base) + np.uint64(1)
                    minimum = int(np.bitwise_or.reduce(encoded)).bit_length()
                    for width in range(max(1, minimum), bits + 1):
                        work = word_reads(self.nrows, width) + 2
                        if work <= max_depth:
                            options.append(Candidate(STORE_BASE_NULL, width, bits, arg=base,
                                                     increment=work, payload_bytes=packed_size(self.nrows, width)))
                # Row-derived fields are captured, not presumed from exporter IDs.
                # Caller must label diagnostic-only columns outside native costs.
                a = ((int(values[1]) - int(values[0])) & mask) if self.nrows > 1 else 0
                b = int(values[0])
                row = np.arange(self.nrows, dtype=np.uint64)
                affine = row * np.uint64(a) + np.uint64(b)
                if bits < 64:
                    affine &= np.uint64(mask)
                if np.array_equal(affine, values):
                    work = 1 + int(a not in (0, 1)) + int(b != 0)
                    if work <= max_depth:
                        options.append(Candidate(ROW_AFFINE, 0, bits, arg=b, count=a, increment=work))
                seen_constant_parents = set()
                for parent, other in enumerate(self.columns):
                    if parent == field or not self.nrows:
                        continue
                    constant_parent = self.constant_fields[parent]
                    if constant_parent:
                        # Exact aliases cannot derive a varying column from a
                        # constant, but sparse overrides often can. Equal
                        # constant parents have identical value/depth/cost.
                        if not allow_sparse or max_depth < 13:
                            continue
                        constant_value = int(other[0])
                        if constant_value in seen_constant_parents:
                            continue
                        seen_constant_parents.add(constant_value)
                    xor = (int(values[0]) ^ int(other[0])) & mask
                    add = (int(values[0]) - int(other[0])) & mask
                    aliases = [] if constant_parent else [(ALIAS_XOR, xor), (ALIAS_ADD, add)]
                    for op, constant in aliases:
                        if op == ALIAS_XOR:
                            sample_result = (other[sample] ^ np.uint64(constant)) & np.uint64(mask)
                        else:
                            sample_result = (other[sample] + np.uint64(constant)) & np.uint64(mask)
                        if not np.array_equal(sample_result, values[sample]):
                            continue
                        predicted = (other ^ np.uint64(constant)) if op == ALIAS_XOR else (other + np.uint64(constant))
                        if bits < 64:
                            predicted &= np.uint64(mask)
                        if np.array_equal(predicted, values):
                            self.full_validated_relations += 1
                            options.append(Candidate(op, 0, bits, parent=parent, arg=constant,
                                                     increment=1 + int(constant != 0)))
                    if allow_sparse and max_depth >= 13:
                        # Candidate pruning can reject a relation, never accept it.
                        # Every accepted sparse relation is rebuilt and checked in
                        # full. Optimality is only within this declared pool.
                        if np.mean(other[sample] == values[sample]) < sparse_sample_agreement:
                            self.sample_rejected_sparse_pairs += 1
                            continue
                        different = values != other
                        count = int(np.count_nonzero(different))
                        if not count:
                            continue
                        exceptions = values[different]
                        base = int(exceptions[0])
                        width = int(np.bitwise_or.reduce(exceptions ^ np.uint64(base))).bit_length()
                        size = bitmap_size(self.nrows) + rank_size(self.nrows) + packed_size(count, width)
                        options.append(Candidate(SPARSE, width, bits, parent=parent, arg=base,
                                                 count=count, increment=13, payload_bytes=size))
                        self.full_validated_relations += 1
            # Identical programs add no semantic choices. Payload choices that
            # cannot fit the requested work budget are excluded by construction.
            options = list(dict.fromkeys(options))
            self.candidates.append(options)
        self._encode()
        self.model_build_seconds = time.perf_counter() - started

    def _new(self):
        self.nv += 1
        return self.nv

    def _at_most(self, variables, limit):
        if len(variables) <= limit:
            return
        result = CardEnc.atmost(lits=variables, bound=limit, top_id=self.nv, encoding=EncType.seqcounter)
        self.hard.extend(result.clauses)
        self.nv = max(self.nv, result.nv)

    def _encode(self):
        self.levels = [[None] + [self._new() for _ in range(self.max_depth)] for _ in self.names]
        for levels in self.levels:
            self.hard.extend([[-levels[i + 1], levels[i]] for i in range(1, self.max_depth)])
        self.selection = []
        for field, options in enumerate(self.candidates):
            variables = []
            for candidate in options:
                variable = self._new()
                variables.append(variable)
                self.costs.append((variable, candidate.payload_bytes))
                work = candidate.increment
                if work > self.max_depth:
                    self.hard.append([-variable])
                    continue
                if work:
                    self.hard.append([-variable, self.levels[field][work]])
                if candidate.parent != NIL:
                    for depth in range(1, self.max_depth + 1):
                        if depth + work <= self.max_depth:
                            self.hard.append([-variable, -self.levels[candidate.parent][depth],
                                              self.levels[field][depth + work]])
                        else:
                            self.hard.append([-variable, -self.levels[candidate.parent][depth]])
            self.hard.append(variables)
            self._at_most(variables, 1)
            self.selection.append(variables)

    def solve(self):
        formula = WCNF()
        formula.extend(self.hard)
        for variable, cost in self.costs:
            if cost:
                formula.append([-variable], weight=cost)
        start = time.perf_counter()
        with RC2(formula) as solver:
            model = solver.compute()
            if model is None:
                raise ValueError('no representation meets the access-work bound')
            positive = {v for v in model if v > 0}
            selected = [next(c for c, variable in zip(options, variables) if variable in positive)
                        for options, variables in zip(self.candidates, self.selection)]
            objective = solver.cost
        solver_seconds = time.perf_counter() - start
        started = time.perf_counter()
        image = build_image(self, selected)
        expected = HEADER.size + DESC.size * len(self.names) + objective
        if len(image) != expected:
            raise AssertionError('serialized size differs from solver byte cost')
        serialization_seconds = time.perf_counter() - started
        started = time.perf_counter()
        store = FieldStore(image, self.names, self.max_depth)
        for field, values in enumerate(self.columns):
            if not np.array_equal(store.reconstruct(field), values):
                raise AssertionError('complete field reconstruction failed')
            for row in np.linspace(0, max(0, self.nrows - 1), min(33, self.nrows), dtype=np.int64):
                if store.get(field, int(row)) != int(values[row]):
                    raise AssertionError('independent scalar GET failed')
        return Synthesis(self, selected, image, store, objective,
                         {'solver': 'PySAT RC2; not the linked counting construction',
                          'solve_seconds': solver_seconds,
                          'model_build_seconds': self.model_build_seconds,
                          'serialization_seconds': serialization_seconds,
                          'verification_seconds': time.perf_counter() - started,
                          'variables': self.nv, 'hard_clauses': len(self.hard),
                          'candidate_programs': sum(map(len, self.candidates)),
                          'validated_relations': self.full_validated_relations,
                          'sample_rejected_sparse_pairs': self.sample_rejected_sparse_pairs,
                          'all_rows_all_fields_verified': True})


def build_image(problem, selected):
    payload = bytearray()
    descriptors = []
    base_offset = HEADER.size + len(selected) * DESC.size
    for field, candidate in enumerate(selected):
        values = problem.columns[field]
        encoded = b''
        offset = 0
        if candidate.op == STORE_XOR:
            encoded = pack_values(values ^ np.uint64(candidate.arg), candidate.width)
        elif candidate.op == STORE_BASE_NULL:
            shifted = np.zeros_like(values)
            nz = values != 0
            shifted[nz] = values[nz] - np.uint64(candidate.arg) + np.uint64(1)
            encoded = pack_values(shifted, candidate.width)
        elif candidate.op == SPARSE:
            different = values != problem.columns[candidate.parent]
            bits = np.packbits(different, bitorder='little').tobytes()
            bitmap = bits + bytes(bitmap_size(problem.nrows) - len(bits))
            ranks = [0]
            for start in range(0, problem.nrows, RANK_BLOCK):
                ranks.append(ranks[-1] + int(np.count_nonzero(different[start:start + RANK_BLOCK])))
            rank = struct.pack('<' + 'I' * len(ranks), *ranks)
            rank += bytes(rank_size(problem.nrows) - len(rank))
            exceptions = values[different] ^ np.uint64(candidate.arg)
            encoded = bitmap + rank + pack_values(exceptions, candidate.width)
        if len(encoded) != candidate.payload_bytes:
            raise AssertionError('candidate payload cost mismatch')
        if encoded:
            offset = base_offset + len(payload)
            payload.extend(encoded)
        descriptors.append(DESC.pack(candidate.op, candidate.width, candidate.bits, 0,
                                     candidate.parent, candidate.arg, offset, candidate.count))
    return HEADER.pack(MAGIC, problem.nrows, len(selected)) + b''.join(descriptors) + payload


class FieldStore:
    def __init__(self, image, names=None, max_depth=None):
        self.image = bytes(image)
        self._view = memoryview(self.image)
        if len(self.image) < HEADER.size:
            raise ValueError('truncated field image')
        magic, self.rows, count = HEADER.unpack_from(self.image)
        if magic != MAGIC or count > 512 or HEADER.size + count * DESC.size > len(self.image):
            raise ValueError('invalid field image header')
        self.names = list(names) if names is not None else list(range(count))
        if len(self.names) != count:
            raise ValueError('schema field count mismatch')
        self.programs = []
        self.depths = {}
        position = HEADER.size + count * DESC.size
        for field in range(count):
            op, width, bits, flags, parent, arg, offset, n = DESC.unpack_from(self.image, HEADER.size + field * DESC.size)
            if op not in range(7) or flags or not 1 <= bits <= 64 or width > bits:
                raise ValueError('invalid field access program')
            if op in (ALIAS_XOR, ALIAS_ADD, SPARSE):
                if parent >= count or parent == field:
                    raise ValueError('invalid field dependency')
            elif parent != NIL:
                raise ValueError('unexpected field dependency')
            if op in (STORE_XOR, STORE_BASE_NULL):
                if not width:
                    raise ValueError('stored field requires a width')
                size = packed_size(self.rows, width)
            elif op == SPARSE:
                if n > self.rows:
                    raise ValueError('too many sparse exceptions')
                size = bitmap_size(self.rows) + rank_size(self.rows) + packed_size(n, width)
            else:
                if width or offset:
                    raise ValueError('nonstored field has payload')
                size = 0
            if size:
                if offset != position or size > len(self.image) - position:
                    raise ValueError('invalid field payload bounds')
                position += size
            candidate = Candidate(op, width, bits, parent, arg, n, 0, size)
            self.programs.append((candidate, offset))
        if position != len(self.image):
            raise ValueError('trailing field payload')
        for field in range(count):
            depth = self._depth(field, set())
            if max_depth is not None and depth > max_depth:
                raise ValueError('field dependency exceeds work bound')
        # Validate sparse directory arithmetic before any scalar GET.
        for candidate, offset in self.programs:
            if candidate.op == SPARSE:
                bitmap = self.image[offset:offset + bitmap_size(self.rows)]
                rank_at = offset + bitmap_size(self.rows)
                running = 0
                blocks = (self.rows + RANK_BLOCK - 1) // RANK_BLOCK
                for block in range(blocks):
                    if struct.unpack_from('<I', self.image, rank_at + 4 * block)[0] != running:
                        raise ValueError('invalid sparse rank directory')
                    first = block * 64
                    remaining = min(RANK_BLOCK, self.rows - block * RANK_BLOCK)
                    raw = int.from_bytes(bitmap[first:first + (remaining + 7) // 8], 'little')
                    running += (raw & ((1 << remaining) - 1)).bit_count()
                if running != candidate.count or struct.unpack_from('<I', self.image, rank_at + 4 * blocks)[0] != running:
                    raise ValueError('invalid sparse exception count')

    def _depth(self, field, visiting):
        if field in self.depths:
            return self.depths[field]
        if field in visiting:
            raise ValueError('cyclic field dependency')
        visiting.add(field)
        c, _ = self.programs[field]
        if c.op == CONST:
            work = 0
        elif c.op == ROW_AFFINE:
            work = 1 + int(c.count not in (0, 1)) + int(c.arg != 0)
        elif c.op == STORE_XOR:
            work = word_reads(self.rows, c.width) + int(c.arg != 0)
        elif c.op == STORE_BASE_NULL:
            work = word_reads(self.rows, c.width) + 2
        elif c.op in (ALIAS_XOR, ALIAS_ADD):
            work = self._depth(c.parent, visiting) + 1 + int(c.arg != 0)
        else:
            work = self._depth(c.parent, visiting) + 13
        visiting.remove(field)
        self.depths[field] = work
        return work

    def _field(self, field):
        if isinstance(field, str):
            field = self.names.index(field)
        if type(field) is not int or not 0 <= field < len(self.programs):
            raise ValueError('invalid field ID')
        return field

    def get(self, field, row):
        field = self._field(field)
        if type(row) is not int or not 0 <= row < self.rows:
            raise ValueError('invalid row ID')
        c, offset = self.programs[field]
        mask = (1 << c.bits) - 1
        if c.op == CONST:
            return c.arg & mask
        if c.op == ROW_AFFINE:
            return (row * c.count + c.arg) & mask
        if c.op == STORE_XOR:
            return (packed_get(self.image, offset, c.width, row) ^ c.arg) & mask
        if c.op == STORE_BASE_NULL:
            value = packed_get(self.image, offset, c.width, row)
            return 0 if value == 0 else (c.arg + value - 1) & mask
        if c.op in (ALIAS_XOR, ALIAS_ADD):
            parent = self.get(c.parent, row)
            return ((parent ^ c.arg) if c.op == ALIAS_XOR else (parent + c.arg)) & mask
        word = struct.unpack_from('<Q', self.image, offset + (row // 64) * 8)[0]
        if not (word >> (row % 64)) & 1:
            return self.get(c.parent, row) & mask
        block = row // RANK_BLOCK
        rank_at = offset + bitmap_size(self.rows)
        rank = struct.unpack_from('<I', self.image, rank_at + 4 * block)[0]
        for index in range(block * 8, row // 64):
            rank += struct.unpack_from('<Q', self.image, offset + index * 8)[0].bit_count()
        rank += (word & ((1 << (row % 64)) - 1)).bit_count()
        payload_at = rank_at + rank_size(self.rows)
        return (packed_get(self.image, payload_at, c.width, rank) ^ c.arg) & mask

    def reconstruct(self, field, cache=None):
        field = self._field(field)
        cache = {} if cache is None else cache
        if field in cache:
            return cache[field]
        c, offset = self.programs[field]
        mask = np.uint64((1 << c.bits) - 1)
        if c.op == CONST:
            values = np.full(self.rows, c.arg, dtype=np.uint64)
        elif c.op == ROW_AFFINE:
            values = np.arange(self.rows, dtype=np.uint64) * np.uint64(c.count) + np.uint64(c.arg)
        elif c.op == STORE_XOR:
            values = unpack_values(self._view[offset:], c.width, self.rows) ^ np.uint64(c.arg)
        elif c.op == STORE_BASE_NULL:
            encoded = unpack_values(self._view[offset:], c.width, self.rows)
            values = np.zeros(self.rows, dtype=np.uint64)
            nz = encoded != 0
            values[nz] = encoded[nz] + np.uint64(c.arg) - np.uint64(1)
        elif c.op in (ALIAS_XOR, ALIAS_ADD):
            parent = self.reconstruct(c.parent, cache)
            values = (parent ^ np.uint64(c.arg)) if c.op == ALIAS_XOR else (parent + np.uint64(c.arg))
        else:
            values = self.reconstruct(c.parent, cache).copy()
            bits = np.unpackbits(np.frombuffer(self._view[offset:offset + bitmap_size(self.rows)], dtype=np.uint8), bitorder='little')[:self.rows].astype(bool)
            at = offset + bitmap_size(self.rows) + rank_size(self.rows)
            exceptions = unpack_values(self._view[at:], c.width, c.count) ^ np.uint64(c.arg)
            values[bits] = exceptions
        values = values & mask
        cache[field] = values
        return values


@dataclass
class Synthesis:
    problem: FieldProblem
    selected: list[Candidate]
    image: bytes
    store: FieldStore
    payload_bytes: int
    metrics: dict

    @property
    def programs(self):
        return [{'field': name, 'operation': OP_NAMES[c.op], 'width': c.width,
                 'native_bits': c.bits, 'parent': self.problem.names[c.parent] if c.parent != NIL else None,
                 'argument': c.arg, 'exception_count_or_affine_factor': c.count,
                 'payload_bytes': c.payload_bytes, 'work': self.store.depths[i]}
                for i, (name, c) in enumerate(zip(self.problem.names, self.selected))]

    @property
    def public_programs(self):
        """Program structure without captured field/pointer parameter values.

        The private image and ``programs`` still retain every exact parameter for
        reconstruction. Hashes let public provenance bind them without publishing
        actual address words or captured data-derived constants.
        """
        result = []
        for program, candidate in zip(self.programs, self.selected):
            public = dict(program)
            argument = public.pop('argument')
            public['argument_sha256'] = hashlib.sha256(struct.pack('<Q', argument)).hexdigest()
            if candidate.op == ROW_AFFINE:
                factor = public.pop('exception_count_or_affine_factor')
                public['affine_factor_sha256'] = hashlib.sha256(struct.pack('<Q', factor)).hexdigest()
            result.append(public)
        return result

    @property
    def total_bytes(self):
        return len(self.image)

    @property
    def cold_bytes(self):
        return len(self.image)

    @property
    def fully_hydrated_bytes(self):
        return len(self.image)  # no persistent decoded cache in this model

    def get(self, field, row):
        return self.store.get(field, row)

    def reconstruct(self, field):
        return self.store.reconstruct(field)


def synthesize(columns, source_bits, max_depth=3, allow_sparse=True, **kwargs):
    return FieldProblem(columns, source_bits, max_depth, allow_sparse, **kwargs).solve()
