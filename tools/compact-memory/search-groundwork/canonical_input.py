#!/usr/bin/env python3
"""Prepare the linked counting theorem's canonical Boolean-list input.

This mirrors Encoding.encodeCNF in openai/math's
lean/ComparatorChallenges/SubexponentialSAT.lean: unary naturals, nested framed
lists, sorted finite-set clauses and literals. It does not implement the counter.
Packed MSB-first bytes are only a transport of that Boolean list; the logical
bit length, not transport byte count, is the theorem's input-length parameter.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import itertools
import json
from pathlib import Path
import re


REFERENCE = ('https://github.com/openai/math/blob/main/lean/'
             'ComparatorChallenges/SubexponentialSAT.lean')
DEFAULT_MAX_BITS = 8 * 1024 * 1024


def _natural(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be a nonnegative integer')
    return value


@dataclass(frozen=True)
class CanonicalCNF:
    """Clauses contain zero-based Lean literal codes, not DIMACS literals."""
    num_variables: int
    clauses: tuple[tuple[int, ...], ...]
    source_clause_count: int
    source_literal_occurrences: int
    source_maximum_clause_width: int

    def __post_init__(self):
        _natural(self.num_variables, 'num_variables')
        for name in ('source_clause_count', 'source_literal_occurrences', 'source_maximum_clause_width'):
            _natural(getattr(self, name), name)
        if not isinstance(self.clauses, tuple):
            raise ValueError('canonical clauses must be immutable tuples')
        previous, occurrences = None, 0
        for clause in self.clauses:
            if not isinstance(clause, tuple):
                raise ValueError('canonical clauses must be immutable tuples')
            if previous is not None and not previous < clause:
                raise ValueError('canonical clauses must be strictly lexicographically sorted')
            previous = clause
            prior_code = -1
            for code in clause:
                if type(code) is not int or not prior_code < code < 2 * self.num_variables:
                    raise ValueError('canonical literal codes must be sorted, distinct and in range')
                prior_code = code
            occurrences += len(clause)
        if (self.source_clause_count < len(self.clauses) or
                self.source_literal_occurrences < occurrences or
                self.source_maximum_clause_width < self.maximum_clause_width):
            raise ValueError('source dimensions cannot be smaller than their canonical finite sets')

    @property
    def maximum_clause_width(self):
        return max(map(len, self.clauses), default=0)


def canonical_formula(num_variables, clauses, *, maximum_width=3):
    """Normalize signed clauses as the Lean finite sets, preserving ambient n.

    Repeated literals and repeated clauses disappear. Tautological clauses do
    not disappear: the canonical encoding still stores both literal signs.
    Width is the finite-set width, matching SAT.WidthAtMost in the theorem.
    """
    _natural(num_variables, 'num_variables')
    _natural(maximum_width, 'maximum_width')
    unique, source_count, occurrences, raw_width = set(), 0, 0, 0
    for clause in clauses:
        codes, width = set(), 0
        for literal in clause:
            if type(literal) is not int or not 1 <= abs(literal) <= num_variables:
                raise ValueError('literal must reference a declared nonzero DIMACS variable')
            width += 1
            codes.add(2 * (abs(literal) - 1) + int(literal > 0))
        if len(codes) > maximum_width:
            raise ValueError('canonical clause exceeds the permitted width')
        unique.add(tuple(sorted(codes)))
        source_count += 1
        occurrences += width
        raw_width = max(raw_width, width)
    return CanonicalCNF(num_variables, tuple(sorted(unique)), source_count,
                        occurrences, raw_width)


def parse_dimacs(text, *, maximum_width=3):
    """Parse complete DIMACS, including multiline clauses and declared free vars."""
    if not isinstance(text, str):
        raise ValueError('DIMACS input must be text')
    header, clauses, pending = None, [], []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('c'):
            continue
        tokens = stripped.split()
        if tokens[0] == 'p':
            if header is not None or clauses or pending or len(tokens) != 4 or tokens[1] != 'cnf':
                raise ValueError('exactly one p cnf header must precede clauses')
            if not all(re.fullmatch(r'\d+', token) for token in tokens[2:]):
                raise ValueError('DIMACS header dimensions must be nonnegative integers')
            header = tuple(map(int, tokens[2:]))
            continue
        if header is None:
            raise ValueError('DIMACS clauses require a preceding header')
        for token in tokens:
            if not re.fullmatch(r'-?\d+', token):
                raise ValueError('invalid DIMACS literal token')
            literal = int(token)
            if literal:
                if abs(literal) > header[0]:
                    raise ValueError('DIMACS literal exceeds declared variable universe')
                pending.append(literal)
            else:
                clauses.append(tuple(pending))
                pending = []
                if len(clauses) > header[1]:
                    raise ValueError('more clauses than declared in DIMACS header')
    if header is None:
        raise ValueError('missing DIMACS header')
    if pending:
        raise ValueError('unterminated DIMACS clause')
    if len(clauses) != header[1]:
        raise ValueError('DIMACS clause count differs from its header')
    return canonical_formula(header[0], clauses, maximum_width=maximum_width)


def _formula(num_variables, clauses=None):
    if isinstance(num_variables, CanonicalCNF):
        if clauses is not None:
            raise ValueError('do not supply clauses with an already canonical formula')
        return num_variables
    if clauses is None:
        raise ValueError('signed clauses are required with a variable count')
    return canonical_formula(num_variables, clauses)


def canonical_bit_length(num_variables, clauses=None):
    """Exact encoded length without constructing any unary natural words.

    A literal of code c contributes 8+4c bits after both list frames. The
    equivalent DIMACS expression is n+2+4m+8*sum(abs(lit))+4*positive_count.
    """
    formula = _formula(num_variables, clauses)
    return (formula.num_variables + 2 + 4 * len(formula.clauses) +
            sum(8 + 4 * code for clause in formula.clauses for code in clause))


def _encode_nat(value):
    yield from itertools.repeat(True, value)
    yield False


def _frame(bits):
    for bit in bits:
        yield True
        yield bit
    yield False


def _encode_list(values, encoder):
    for value in values:
        yield True
        yield from _frame(encoder(value))
    yield False


def canonical_bits(num_variables, clauses=None):
    """Yield exactly the canonical Boolean list; callers must bound its size."""
    formula = _formula(num_variables, clauses)
    yield from _encode_nat(formula.num_variables)
    yield from _encode_list(formula.clauses,
                            lambda clause: _encode_list(clause, _encode_nat))


def write_packed(path, num_variables, clauses=None, *, max_bits=DEFAULT_MAX_BITS):
    """Write an explicitly bounded MSB-first packed transport of the bit list.

    Final unused low bits are zero. Refusing an oversized input does not create
    or overwrite the destination. The counter needs an adapter that expands
    exactly logical_bits bits; these bytes are not a ready-made solver protocol.
    """
    formula = _formula(num_variables, clauses)
    _natural(max_bits, 'max_bits')
    logical_bits = canonical_bit_length(formula)
    if logical_bits > max_bits:
        raise ValueError('canonical input exceeds max_bits; no transport was written')
    output = bytearray()
    word, used = 0, 0
    for bit in canonical_bits(formula):
        word = (word << 1) | int(bit)
        used += 1
        if used == 8:
            output.append(word)
            word, used = 0, 0
    if used:
        output.append(word << (8 - used))
    path = Path(path)
    path.write_bytes(output)
    return {'logical_bits': logical_bits, 'transport_bytes': len(output),
            'transport_sha256': hashlib.sha256(output).hexdigest(),
            'transport_encoding': 'MSB-first packed Boolean list; final low padding bits zero',
            'counter_protocol': 'none; an executable-specific adapter is still required'}


def input_report(formula, source_bytes):
    logical_bits = canonical_bit_length(formula)
    return {'schema_version': 1, 'reference': REFERENCE,
            'source_sha256': hashlib.sha256(source_bytes).hexdigest(),
            'source_bytes': len(source_bytes), 'variables': formula.num_variables,
            'source_clauses': formula.source_clause_count,
            'canonical_clauses': len(formula.clauses),
            'source_literal_occurrences': formula.source_literal_occurrences,
            'source_maximum_clause_width': formula.source_maximum_clause_width,
            'canonical_maximum_clause_width': formula.maximum_clause_width,
            'canonical_logical_bits': logical_bits,
            'packed_transport_bytes_if_materialized': (logical_bits + 7) // 8,
            'declared_unused_variables_preserved': True,
            'normalization': 'finite-set literal/clauses deduplication and Lean literal-code ordering; no tautology elimination',
            'linked_counter_executed': False,
            'limits': ['Logical input length is the theorem parameter, not DIMACS byte count.',
                       'Packed bytes are only a transport, not a supplied counting-machine executable.',
                       'Canonical encoding preserves the assignment universe, including declared free variables.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cnf', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='optional packed Boolean-list transport')
    parser.add_argument('--max-bits', type=int, default=DEFAULT_MAX_BITS)
    args = parser.parse_args()
    raw = args.cnf.read_bytes()
    try:
        formula = parse_dimacs(raw.decode('ascii'))
        _natural(args.max_bits, 'max_bits')
        report = input_report(formula, raw)
        report['materialization_cap_bits'] = args.max_bits
        report['within_materialization_cap'] = report['canonical_logical_bits'] <= args.max_bits
        if args.output is not None:
            report['transport'] = write_packed(args.output, formula, max_bits=args.max_bits)
        report['status'] = 'prepared' if args.output is not None else 'length_only'
    except (ValueError, UnicodeError) as error:
        parser.error(str(error))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'variables': formula.num_variables,
                      'canonical_logical_bits': report['canonical_logical_bits'],
                      'report': str(args.report)}))


if __name__ == '__main__':
    main()
