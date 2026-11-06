#!/usr/bin/env python3
"""Reproducible complexity indicators and field-provider resource bounds.

These are semantic resource bounds and lexical source indicators, not processor
instruction counts, scanner timing guarantees, or a proof of C correctness.
The field rules mirror system-model/probe_field_store.c and its validated image
format, including the fixed 512-bit sparse rank block. No private field values
or pointer constants are emitted.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import math
from pathlib import Path
import re
import tokenize


OPS = ('store_xor', 'constant', 'row_affine', 'alias_xor', 'alias_add',
       'store_base_null', 'sparse_override')
NIL = (1 << 32) - 1
RANK_BLOCK = 512
COST_KEYS = ('payload_read_operations', 'payload_bytes_read',
             'descriptor_visits', 'dependency_edges', 'dependency_depth',
             'rank_popcounts', 'rank_loop_iterations', 'data_control_tests',
             'scan_allocations', 'scan_syscalls')
ALLOCATORS = frozenset(('malloc', 'calloc', 'realloc', 'free', 'mmap', 'munmap',
                        'aligned_alloc', 'strdup', 'strndup', 'new', 'delete',
                        'list', 'dict', 'set', 'bytearray'))


def _natural(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(label + ' must be a nonnegative integer')
    return value


def packed_word_reads(rows, width):
    """Maximum aligned u64 payload loads over the actual packed row universe."""
    _natural(rows, 'rows')
    if type(width) is not int or not 0 <= width <= 64:
        raise ValueError('packed width must be in 0..64')
    if not rows or not width:
        return 0
    period = min(rows, 64 // math.gcd(width, 64))
    return max(1 + ((row * width) % 64 + width > 64) for row in range(period))


def _zero(**values):
    result = dict.fromkeys(COST_KEYS, 0)
    result.update(values)
    return result


def _add(left, right):
    return {key: left[key] + right[key] for key in COST_KEYS}


def _maximum(*costs):
    return {key: max(cost[key] for cost in costs) for key in COST_KEYS}


def _get(program, name, fallback=None):
    if isinstance(program, dict):
        return program.get(name, fallback)
    return getattr(program, name, fallback)


def local_field_bounds(program, rows):
    """Conservative additive bounds for one instruction, excluding its parent.

    A dependent instruction's local bound can be added to its parent's bound.
    Sparse instructions deliberately charge the exception path AND a potential
    parent traversal, rather than attempting to share mutually exclusive paths.
    The graph analyzer above/below can give tighter component-wise bounds.
    These units count declared resources; integer arithmetic is not a hardware
    instruction tally and must not be inferred from this additive score.
    """
    _natural(rows, 'rows')
    op = _get(program, 'op', _get(program, 'operation'))
    if type(op) is int and 0 <= op < len(OPS):
        op = OPS[op]
    if op not in OPS:
        raise ValueError('unsupported field operation')
    width = _get(program, 'width', 0)
    bits = _get(program, 'bits', _get(program, 'native_bits', 64))
    count = _get(program, 'count', _get(program, 'exception_count_or_affine_factor', 0))
    if type(bits) is not int or not 1 <= bits <= 64:
        raise ValueError('invalid native bit width')
    if type(width) is not int or not 0 <= width <= bits:
        raise ValueError('invalid field width')
    _natural(count, 'field count')
    if op in ('store_xor', 'store_base_null') and not width:
        raise ValueError('stored field requires width')
    if op in ('constant', 'row_affine', 'alias_xor', 'alias_add') and width:
        raise ValueError('nonstored field has packed width')
    if op == 'sparse_override' and count > rows:
        raise ValueError('sparse exceptions exceed rows')
    if not rows:
        return _zero()
    result = _zero(descriptor_visits=1)
    if op in ('store_xor', 'store_base_null'):
        reads = packed_word_reads(rows, width)
        result.update(payload_read_operations=reads, payload_bytes_read=reads * 8,
                      data_control_tests=1 + (op == 'store_base_null'))
    elif op in ('alias_xor', 'alias_add'):
        result.update(dependency_edges=1, dependency_depth=1)
    elif op == 'sparse_override':
        result.update(payload_read_operations=1, payload_bytes_read=8,
                      dependency_edges=1, dependency_depth=1, data_control_tests=1)
        if count:
            preceding = min(7, (rows - 1) // 64)
            packed = packed_word_reads(count, width)
            result = _add(result, _zero(
                payload_read_operations=1 + preceding + packed,
                payload_bytes_read=4 + 8 * preceding + 8 * packed,
                rank_popcounts=preceding + 1, rank_loop_iterations=preceding,
                data_control_tests=int(width != 0)))
    return result


def local_query_units(program, rows):
    """Positive additive resource score, not CPU instructions or latency.

    The one-unit floor also makes dependency validation well-founded for an
    empty row universe. It is a modeling convention, not an executed empty GET.
    """
    counts = local_field_bounds(program, rows)
    included = ('descriptor_visits', 'payload_read_operations', 'dependency_edges',
                'rank_popcounts', 'rank_loop_iterations', 'data_control_tests')
    return max(1, sum(counts[key] for key in included))


def analyze_field_programs(programs, rows, *, identity_strategy='direct_row',
                           identity_objects=None):
    """Bound each scalar GET, including descriptor dispatch and optional lookup.

    Accept existing Candidate objects or mappings with op/operation, width,
    bits/native_bits, parent, and count/exception_count_or_affine_factor. Parent
    names are resolved using mapping field names. Bounds are component-wise:
    the maximum loads and maximum dependency depth need not share one row.
    Descriptors are visited even for constants; their visits are not free work.
    This does not convert descriptor visits into speculative hardware loads.
    """
    _natural(rows, 'rows')
    if identity_strategy not in ('direct_row', 'binary_address'):
        raise ValueError('unsupported identity strategy')
    if identity_strategy == 'binary_address':
        if identity_objects is None:
            raise ValueError('binary identity lookup requires object count')
        _natural(identity_objects, 'identity_objects')
        if rows and not identity_objects:
            raise ValueError('nonempty query universe requires identity objects')
    source = list(programs)
    names = [_get(p, 'field', str(i)) for i, p in enumerate(source)]
    if len(set(names)) != len(names):
        raise ValueError('duplicate field names')
    normalized = []
    for index, program in enumerate(source):
        op = _get(program, 'op', _get(program, 'operation'))
        if type(op) is int and 0 <= op < len(OPS):
            op = OPS[op]
        if op not in OPS:
            raise ValueError('unsupported field operation')
        width = _get(program, 'width', 0)
        bits = _get(program, 'bits', _get(program, 'native_bits', 64))
        count = _get(program, 'count', _get(program, 'exception_count_or_affine_factor', 0))
        if type(bits) is not int or not 1 <= bits <= 64:
            raise ValueError('invalid native bit width')
        if type(width) is not int or not 0 <= width <= bits:
            raise ValueError('invalid field width')
        _natural(count, 'field count')
        parent = _get(program, 'parent')
        if parent == NIL:
            parent = None
        if isinstance(parent, str):
            if parent not in names:
                raise ValueError('absent parent field')
            parent = names.index(parent)
        dependent = op in ('alias_xor', 'alias_add', 'sparse_override')
        if dependent:
            if type(parent) is not int or not 0 <= parent < len(source) or parent == index:
                raise ValueError('invalid dependency')
        elif parent is not None:
            raise ValueError('unexpected dependency')
        if op in ('store_xor', 'store_base_null') and width == 0:
            raise ValueError('stored field requires width')
        if op in ('constant', 'row_affine', 'alias_xor', 'alias_add') and width:
            raise ValueError('nonstored field has packed width')
        if op == 'sparse_override' and count > rows:
            raise ValueError('sparse exceptions exceed rows')
        normalized.append(dict(operation=op, width=width, bits=bits,
                               parent=parent, count=count))

    # Validate all dependencies independently of whether this particular sparse
    # bitmap could avoid a parent. The native reader rejects all graph cycles.
    state, structural_depth = {}, {}

    def depth(field):
        if state.get(field) == 1:
            raise ValueError('cyclic field dependencies')
        if field in structural_depth:
            return structural_depth[field]
        state[field] = 1
        parent = normalized[field]['parent']
        result = 0 if parent is None else 1 + depth(parent)
        state[field] = 2
        structural_depth[field] = result
        return result

    for field in range(len(source)):
        depth(field)
    cache = {}

    def bound(field):
        if field in cache:
            return cache[field]
        p = normalized[field]
        result = _zero(descriptor_visits=1)
        op, width, parent, count = (p[k] for k in ('operation', 'width', 'parent', 'count'))
        if op in ('store_xor', 'store_base_null'):
            reads = packed_word_reads(rows, width)
            result.update(payload_read_operations=reads, payload_bytes_read=8 * reads,
                          data_control_tests=1 + (op == 'store_base_null'))
        elif op in ('alias_xor', 'alias_add'):
            result = _add(result, bound(parent))
            result['dependency_edges'] += 1
            result['dependency_depth'] += 1
        elif op == 'sparse_override':
            # One bitmap u64 determines which path is followed. The exception
            # path loads one u32 rank base and up to seven preceding u64 words;
            # the current bitmap word is reused rather than loaded a second time.
            prefix = _zero(descriptor_visits=1, payload_read_operations=1,
                           payload_bytes_read=8, data_control_tests=1)
            normal = _add(prefix, bound(parent))
            normal['dependency_edges'] += 1
            normal['dependency_depth'] += 1
            preceding = min(7, max(0, (rows - 1) // 64))
            packed = packed_word_reads(count, width)
            exception = _add(prefix, _zero(
                payload_read_operations=1 + preceding + packed,
                payload_bytes_read=4 + 8 * preceding + 8 * packed,
                rank_popcounts=preceding + 1, rank_loop_iterations=preceding,
                data_control_tests=int(width != 0)))
            if count == 0:
                result = normal
            elif count == rows:
                result = exception
            else:
                result = _maximum(normal, exception)
        if rows == 0:
            result = _zero()
        cache[field] = result
        return result

    if identity_strategy == 'binary_address' and rows:
        # Exactly ceil(log2(N+1)); floating-point logs undercount near large
        # powers of two, which would invalidate a worst-case resource bound.
        levels = identity_objects.bit_length()
        # Same conservative key/index allowance charged by the existing model.
        identity_reads = 2 * levels + 1
        identity_growth = 'O(log N) in identity object count'
    else:
        levels, identity_reads = 0, 0
        identity_growth = 'O(1)'
    fields = []
    for index, p in enumerate(normalized):
        costs = bound(index)
        fields.append({'field': names[index], 'operation': p['operation'],
                       'bounds': costs, 'structural_dependency_depth': structural_depth[index],
                       'identity_lookup_reads_upper': identity_reads,
                       'data_and_identity_reads_upper': costs['payload_read_operations'] + identity_reads,
                       'native_baseline': {'payload_read_operations': int(rows > 0),
                                           'payload_bytes_read': (p['bits'] + 7) // 8 if rows else 0,
                                           'descriptor_visits': 0,
                                           'identity_lookup_reads_upper': 0}})
    worst = _maximum(*(entry['bounds'] for entry in fields)) if fields else _zero()
    return {'scope': 'component-wise scalar-GET semantic bounds, not CPU timing or whole-scanner complexity',
            'rows': rows, 'fields': fields, 'worst_bounds': worst,
            'identity_strategy': identity_strategy, 'identity_lookup_reads_upper': identity_reads,
            'identity_search_levels_upper': levels, 'identity_growth': identity_growth,
            'field_query_growth': 'O(D + 8), where D is the validated field dependency bound',
            'field_query_constant_for_fixed_dependency_bound': True,
            'rank_block_bits': RANK_BLOCK, 'rank_popcounts_per_sparse_step_upper': 8,
            'descriptor_dispatch_included_as_visits': True,
            'limits': ['A descriptor visit is reported separately, not assumed to cost zero or one hardware load.',
                       'Packed loads are aligned u64 reads; the rank base is one u32 read.',
                       'Bounds include identity resolution when requested; binary-address lookup worsens O(1) direct field access.',
                       'Data-control tests exclude descriptor-static format dispatch, which is charged by descriptor visits.',
                       'No cache misses, compiler effects, syscall latency, wall time or RSS prediction is inferred.',
                       'The binary resolver is a declared design bound, not an instrumented scanner implementation.']}


def _mask_c(text):
    """Blank C comments/literals, preserving positions and newlines for counts."""
    chars = list(text)
    at = 0
    while at < len(text):
        if text.startswith('//', at):
            end = text.find('\n', at)
            end = len(text) if end < 0 else end
        elif text.startswith('/*', at):
            found = text.find('*/', at + 2)
            if found < 0:
                raise ValueError('unterminated C comment')
            end = found + 2
        elif text[at] in ('"', "'"):
            quote, end = text[at], at + 1
            while end < len(text):
                if text[end] == '\\':
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise ValueError('unterminated C literal')
            # Keep a token at the opening quote, so standalone literal lines are
            # counted as code without interpreting their contents as branches.
            chars[at] = 'S'
            for pos in range(at + 1, min(end, len(text))):
                if chars[pos] != '\n':
                    chars[pos] = ' '
            at = end
            continue
        else:
            at += 1
            continue
        for pos in range(at, end):
            if chars[pos] != '\n':
                chars[pos] = ' '
        at = end
    return ''.join(chars)


def source_metrics(text, language):
    """Count explicit lexical sites; these are not formal cyclomatic complexity."""
    if language == 'python':
        tree = ast.parse(text)
        tokens = [t for t in tokenize.generate_tokens(io.StringIO(text).readline)
                  if t.type not in (tokenize.COMMENT, tokenize.STRING, tokenize.NL,
                                    tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                                    tokenize.ENDMARKER, tokenize.ENCODING)]
        words = [t.string for t in tokens]
        lines = {t.start[0] for t in tokens}
        branch_names = ('if', 'elif', 'except', 'case', 'match')
        loop_names = ('for', 'while')
        short_circuit = sum(words.count(x) for x in ('and', 'or'))
        preprocess = 0
        functions = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        for node in ast.walk(tree))
    elif language == 'c':
        masked = _mask_c(text)
        lines = {i for i, line in enumerate(masked.splitlines(), 1) if line.strip()}
        preprocess = len(re.findall(r'^\s*#\s*(?:if|ifdef|ifndef|elif)\b', masked, re.M))
        # Directive tokens are a separate lexical category. Their continuations
        # do not masquerade as executed runtime branches.
        runtime, continuation = [], False
        for line in masked.splitlines():
            directive = continuation or line.lstrip().startswith('#')
            continuation = directive and line.rstrip().endswith('\\')
            runtime.append('' if directive else line)
        words = re.findall(r'[A-Za-z_]\w*|&&|\|\||[?(){}]', '\n'.join(runtime))
        branch_names, loop_names = ('if', 'case', 'switch'), ('for', 'while', 'do')
        short_circuit = words.count('&&') + words.count('||') + words.count('?')
        functions = None  # C definitions need a real parser; no regex estimate.
    else:
        raise ValueError('language must be c or python')
    allocation_sites = sum(1 for index, word in enumerate(words[:-1])
                           if word in ALLOCATORS and words[index + 1] == '(')
    branches = {name: words.count(name) for name in branch_names}
    loops = {name: words.count(name) for name in loop_names}
    return {'physical_lines': len(text.splitlines()),
            'nonblank_noncomment_code_lines': len(lines),
            'branch_keyword_sites': branches, 'branch_keyword_sites_total': sum(branches.values()),
            'loop_keyword_sites': loops, 'loop_keyword_sites_total': sum(loops.values()),
            'short_circuit_or_conditional_operator_sites': short_circuit,
            'explicit_allocation_or_release_call_sites': allocation_sites,
            'preprocessor_conditional_sites': preprocess,
            'python_function_definitions': functions,
            'scope': 'lexical maintenance-complexity indicators; not cyclomatic complexity or an asymptotic proof'}


def measure_source(path):
    path = Path(path)
    if path.suffix not in ('.c', '.h', '.py'):
        raise ValueError('source suffix must be .c, .h or .py')
    raw = path.read_bytes()
    language = 'python' if path.suffix == '.py' else 'c'
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'language': language, **source_metrics(raw.decode('utf-8'), language)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='append', required=True, metavar='LABEL=PATH')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = {}
    for value in args.source:
        label, separator, path = value.partition('=')
        if not separator or not label or not path or label in result:
            parser.error('each source needs a unique nonempty LABEL=PATH')
        result[label] = measure_source(path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'sources': result,
        'limits': ['Compare equivalent source scopes; whole files can contain unrelated functionality.',
                   'Keyword sites do not measure dynamic frequency or executed work.',
                   'Use field resource bounds and native measurements for algorithm/runtime decisions.']}, indent=2) + '\n')
    print(json.dumps({'sources_measured': len(result), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
