#!/usr/bin/env python3
"""Executable parameter/resource audit of the linked counting construction.

This evaluates exact natural-number parameters and source-derived size formulas.
It does NOT execute the counter, check its Lean proof, or prove that every
possible high-level redesign is impractical. It verifies the inspected files
against the pinned repository's Git blobs before drawing source-specific claims.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time

from canonical_input import parse_dimacs, canonical_bit_length

PIN = '4eaee87548250b2682affda7d05d947c05554bae'
PREFIX = 'lean/OAI/Algorithms/SubexponentialSAT/SqrtLogSpace/'
SOURCE_FILES = ('Asymptotics.lean', 'NativeLargeEntry.lean', 'FiniteFallback.lean',
                'NativeFrontend.lean', 'Final.lean', 'NativeLeafProgram.lean')


def natural(value):
    if type(value) is not int or value < 0:
        raise ValueError('expected a nonnegative integer')
    return value


def ceil_log2(value):
    natural(value)
    return (value - 1).bit_length() if value > 1 else 0


def schedule(variables):
    """Asymptotics.lean's Nat.clog/Nat.sqrt/Nat.div, including division by zero."""
    lam = ceil_log2(variables)
    nu = ceil_log2(lam)
    return {'lambda': lam, 'nu': nu, 'integer_sqrt_lambda': math.isqrt(lam),
            'schedule': math.isqrt(lam) // (nu * nu) if nu else 0}


def maximal_canonical_input(cutoff):
    """Maximum over ALL CNFs on at most B variables used by the finite fallback.

    All 2^(2B) clauses maximize positive encoded lengths. Each literal appears
    in exactly half those clauses. Substitution into the canonical length gives
    B+2+2^(2B)*(4B^2+6B+4). This domain is not restricted to width k.
    """
    natural(cutoff)
    if cutoff > 10000:
        raise ValueError('do not materialize an already impractical symbolic cutoff')
    return cutoff + 2 + (1 << (2 * cutoff)) * (4 * cutoff * cutoff + 6 * cutoff + 4)


def fallback_size(cutoff):
    maximum = maximal_canonical_input(cutoff)
    return {'cutoff': cutoff, 'maximum_canonical_bits': maximum,
            'scanner_state_count': '2^' + str(maximum + 1),
            'scanner_state_count_log2': maximum + 1,
            'program_label_factor_over_states': 2 * cutoff + 7,
            'interpretation': 'size of literal finite-control expansion; not a lower bound for all symbolic implementations'}


def dispatch_observation(variables):
    parameters = schedule(variables)
    return {'variables': variables, **parameters,
            'necessary_large_branch_condition_schedule_at_least_two': parameters['schedule'] >= 2,
            'proved_large_branch_eligible': False if parameters['schedule'] < 2 else None,
            'interpretation': ('necessarily finite fallback under the published cutoff contract'
                               if parameters['schedule'] < 2
                               else 'schedule condition alone is insufficient; the leaf cutoff is also required')}


def cutoff_witness():
    # This allocates an 80-kB integer, NOT that many variables, clauses or bits
    # of canonical input. The witness exploits a downward schedule jump.
    exponent = 639999
    actual = schedule(1 << exponent)
    assert actual == {'lambda': 639999, 'nu': 20, 'integer_sqrt_lambda': 799, 'schedule': 1}
    return {'n': '2^639999', 'n_bit_length': exponent + 1,
            'exact_parameters': actual,
            'implication': 'Any Ns with forall n>=Ns, schedule(n)>=2 must exceed 2^639999; the chosen cutoff is >=Ns.',
            'padding_input_lower_bound': 'more than 2^639999 logical bits in the unary variable header alone',
            'not_a_materialized_formula': True}


def inspect_source(root):
    head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN:
        raise ValueError('audit is pinned to source revision ' + PIN)
    observations, contents = {}, {}
    for name in SOURCE_FILES:
        path = PREFIX + name
        raw = (root / path).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        expected = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD:' + path], text=True).strip()
        if blob != expected:
            raise ValueError('source bytes differ from pinned Git blob: ' + path)
        contents[name] = raw.decode()
        observations[path] = {'sha256': hashlib.sha256(raw).hexdigest(), 'git_blob_sha': blob,
                              'bytes': len(raw), 'git_blob_identity_verified': True,
                              'url': 'https://github.com/openai/math/blob/' + PIN + '/' + path}
    guards = {
        'Asymptotics.lean': ('Nat.clog 2 n', 'Nat.sqrt (sparsifyLambda n) / sparsifyNu n ^ 2'),
        'NativeLargeEntry.lean': ('Filter.eventually_ge_atTop 2', 'max 20 (max Nleaf Ns)'),
        'FiniteFallback.lean': ('SAT.CNF (Fin n.val)', 'Option (BoundedWord (inputBound B))',
                                'noncomputable def tableCount', 'noncomputable def countProgram'),
        'NativeFrontend.lean': ('7 * (a.stacks ABI.countStack).length + 4 * n + 2 * body.length + 14',),
        'Final.lean': ('NativeLargeEntry.run k hk', 'Native.countingProgram cutoff k'),
    }
    for name, fragments in guards.items():
        for fragment in fragments:
            if fragment not in contents[name]:
                raise ValueError('inspected definition changed: ' + name + ': ' + fragment)
    return observations


def audit(cnf_path, math_source):
    start = time.perf_counter()
    sources = inspect_source(math_source)
    raw = cnf_path.read_bytes()
    formula = parse_dimacs(raw.decode('ascii'))
    logical_bits = canonical_bit_length(formula)
    body_bits = logical_bits - formula.num_variables - 1
    # NativeFrontend.ambient_eval states this exact structured trace length.
    ambient_steps = 7 * logical_bits + 4 * formula.num_variables + 2 * body_bits + 14
    ordinary_sizes = [{'ceiling_log2_n': lam,
                       'schedule': math.isqrt(lam) // (ceil_log2(lam) ** 2)}
                      for lam in range(3, 65)]
    assert all(row['schedule'] == 0 for row in ordinary_sizes)
    return {'schema_version': 1, 'source_revision': PIN, 'sources': sources,
            'audit_implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'canonical_codec_source_sha256': hashlib.sha256(
                Path(__file__).with_name('canonical_input.py').read_bytes()).hexdigest(),
            'input_sha256': hashlib.sha256(raw).hexdigest(), 'dimacs_bytes': len(raw),
            'variables': formula.num_variables, 'canonical_clauses': len(formula.clauses),
            'canonical_logical_bits': logical_bits,
            'dispatch': dispatch_observation(formula.num_variables),
            'fixture_dispatch': [dispatch_observation(n) for n in (97, 114, 115, 117)],
            'ordinary_size_range': {'lower_n': 5, 'upper_n': '2^64', 'schedule': 0,
                                    'checked_ceiling_log_intervals': ordinary_sizes},
            'cutoff_lower_bound_witness': cutoff_witness(),
            'finite_fallback_literal_sizes': [fallback_size(b) for b in (0, 1, 2, 20)],
            'formal_frontend': {'ambient_structured_steps': ambient_steps,
                'formula': '7*L+4*n+2*(L-n-1)+14 = 9*L+2*n+12',
                'scope': 'exact source-stated structured-step count for one frontend phase, not CPU instructions or measured elapsed time',
                'at_hypothetical_one_billion_steps_per_second_hours': ambient_steps / 1e9 / 3600,
                'rate_is_measured': False},
            'counter_execution': {'novel_outer_branch_executed': False,
                'finite_table_materialized': False, 'lean_proof_rechecked': False,
                'conventional_count_substitution_called_linked_method': False},
            'conclusion': 'No practical execution route established for the published parameterization on this query. A compact input adapter cannot change its fallback dispatch.',
            'limitations': ['This is an exact parameter and literal-construction audit, not an independent Lean proof check.',
                'A Program.code function need not be stored as a flat array; literal table sizes are not universal RAM lower bounds.',
                'An efficient symbolic fallback still needs an effective count computation; replacing it with conventional #SAT is not a run of the novel branch.',
                'Changing schedules, cutoffs, leaf algorithms or input macros requires separate correctness/resource justification.',
                'The underlying high-level ideas are not proved impossible to redesign into a practical algorithm.'],
            'audit_seconds': time.perf_counter() - start}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cnf', type=Path, required=True)
    parser.add_argument('--math-source', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.cnf, args.math_source)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'variables': result['variables'], 'schedule': result['dispatch']['schedule'],
                      'ambient_structured_steps': result['formal_frontend']['ambient_structured_steps'],
                      'conclusion': result['conclusion'], 'seconds': result['audit_seconds']}))


if __name__ == '__main__':
    main()
