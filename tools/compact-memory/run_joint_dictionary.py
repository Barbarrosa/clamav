#!/usr/bin/env python3
"""Reproduce bounded joint-dictionary experiments, never a scanner benchmark.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import random
import re
import subprocess
import time

import pysat
from pysat.solvers import Solver

from joint_budget_cnf import budget_cnf
from joint_token_dictionary import Problem, decode_image


ROOT = Path(__file__).resolve().parents[2]


def canonical_metrics(clauses):
    # ComparatorChallenges/SubexponentialSAT.lean: zero-based variable indexes,
    # unary Nat encoding, framed lists; canonicalize duplicate literals/clauses.
    clauses = set(tuple(sorted(set(clause))) for clause in clauses)
    n = max((abs(v) for c in clauses for v in c), default=0)
    occurrences = sum(map(len, clauses))
    length = n + 2 + 4 * len(clauses)
    length += sum(4 * (2 * (abs(v) - 1) + int(v > 0)) + 8
                  for c in clauses for v in c)
    return {'variables': n, 'clauses': len(clauses), 'literal_occurrences': occurrences,
            'maximum_clause_width': max(map(len, clauses), default=0),
            'lean_canonical_input_symbols': length}


def public_literal_rows():
    """Public literal-only fixtures, not a compiled official database export."""
    paths = sorted((ROOT / 'unit_tests/input/pe_allmatch/alert-sigs').glob('*.ndb'))
    rows, provenance = [], []
    for path in paths:
        for line in path.read_text().splitlines():
            fields = line.split(':')
            if len(fields) < 4 or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', fields[3]):
                continue
            row = bytes.fromhex(fields[3])
            if row not in rows:
                rows.append(row)
        provenance.append({'path': str(path.relative_to(ROOT)),
                           'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return rows, provenance


def sat_budget_search(problem):
    """Conventional SAT feasibility baseline; no model-counting implementation."""
    low, high = 0, problem.fixed_dictionary([]).objective_bytes
    calls, encoding_seconds, sat_seconds = [], 0.0, 0.0
    while low < high:
        budget = (low + high) // 2
        start = time.perf_counter()
        clauses = budget_cnf(problem.hard, problem.costs, budget)
        encoding_seconds += time.perf_counter() - start
        start = time.perf_counter()
        with Solver(name='m22', bootstrap_with=clauses) as solver:
            feasible = solver.solve()
            if feasible:
                layout = problem.layout_from_model(solver.get_model())
                assert layout.objective_bytes <= budget
        sat_seconds += time.perf_counter() - start
        calls.append({'budget': budget, 'feasible': feasible})
        if feasible:
            high = budget
        else:
            low = budget + 1
    return {'minimum_variable_bytes': low, 'calls': calls,
            'encoding_seconds': encoding_seconds, 'sat_seconds': sat_seconds}


def cases():
    public, provenance = public_literal_rows()
    rng = random.Random(378)
    return [
        ('complementarity', [b'cbccbccbc', b'cbccbcdaabdba', b'cbcdaabdbacbc',
                             b'aabdbaaabdbacbc', b'cbcaabdbacbcd'],
         [b'aabdba', b'aabdbacbc', b'aabdbacb', b'abdba', b'abdbacbc', b'bdbacbc', b'cbc'], None, None, []),
        ('public-literal-fixtures-8', public, None, None, 8, provenance),
        ('public-literal-fixtures-16', public, None, None, 16, provenance),
        ('public-literal-fixtures-64', public, None, None, 64, provenance),
        ('distinct', [rng.randbytes(24) for _ in range(8)], None, None, 16, []),
        ('tagged-wide', [bytes.fromhex('010002010080ffff41000010') + bytes([i, 0])
                         for i in range(8)], None, [True] * 8, 16, []),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--repeats', type=int, default=2000)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error('--repeats must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for name, rows, candidates, widths, cap, provenance in cases():
        start = time.perf_counter()
        problem = Problem(rows, widths=widths, candidates=candidates,
                          max_candidates=cap or 16,
                          max_fragment=32 if cap == 64 else 16)
        encoding_seconds = time.perf_counter() - start
        start = time.perf_counter()
        optimum = problem.solve()
        solve_seconds = time.perf_counter() - start
        layouts = {'raw': problem.fixed_dictionary([]), 'greedy': problem.greedy(),
                   'all_candidates': problem.fixed_dictionary(range(len(problem.candidates))),
                   'maxsat': optimum}
        directory = args.output / name
        directory.mkdir()
        metrics = {}
        for method, layout in layouts.items():
            image = layout.to_bytes()
            decoded, recovered_widths = decode_image(image)
            assert decoded == rows and recovered_widths == (widths or [False] * len(rows))
            path = directory / (method + '.bin')
            path.write_bytes(image)
            measurement = {'image_bytes': len(image), 'variable_bytes': layout.objective_bytes,
                           'dictionary_entries': len(layout.dictionary),
                           'dictionary_payload_bytes': sum(map(len, layout.dictionary)),
                           'scratch_bytes_per_decoder': layout.scratch_bytes,
                           'image_sha256': hashlib.sha256(image).hexdigest(),
                           'empty_cache_layout_bytes': len(image),
                           'hydrated_cache_layout_bytes': len(image),
                           'reload_two_image_bytes': 2 * len(image)}
            if args.probe:
                # Fresh native process per image; timings exclude offline solving.
                run = subprocess.run([str(args.probe.resolve()), str(path.resolve()), str(args.repeats)],
                                     check=True, capture_output=True, text=True, timeout=60)
                measurement['native'] = json.loads(run.stdout)
            metrics[method] = measurement
        if args.probe:
            assert len({m['native']['decoded_checksum'] for m in metrics.values()}) == 1
            for trace in range(4):
                assert len({m['native']['timings'][trace]['decoded_fnv64']
                            for m in metrics.values()}) == 1
        cnf_checks = []
        sat_search = None
        if name == 'complementarity':
            sat_search = sat_budget_search(problem)
            assert sat_search['minimum_variable_bytes'] == optimum.objective_bytes
            problem.wcnf().to_file(str(directory / 'problem.wcnf'))
            (directory / 'model.json').write_text(json.dumps(problem.last_model) + '\n')
            (directory / 'variable-map.json').write_text(json.dumps(problem.variable_map, indent=2) + '\n')
            for delta in [-1, 0]:
                budget = optimum.objective_bytes + delta
                start = time.perf_counter()
                clauses = budget_cnf(problem.hard, problem.costs, budget)
                encoding = time.perf_counter() - start
                start = time.perf_counter()
                with Solver(name='m22', bootstrap_with=clauses) as solver:
                    feasible = solver.solve()
                    if feasible:
                        recovered = problem.layout_from_model(solver.get_model())
                        assert recovered.objective_bytes <= budget
                assert feasible == (delta == 0)
                solve = time.perf_counter() - start
                formula_metrics = canonical_metrics(clauses)
                path = directory / ('budget-' + str(budget) + '.cnf')
                with path.open('w') as out:
                    out.write('p cnf %d %d\n' % (formula_metrics['variables'], len(clauses)))
                    for clause in clauses:
                        out.write(' '.join(map(str, clause)) + ' 0\n')
                cnf_checks.append({'variable_byte_budget': budget, 'feasible': feasible,
                                   'encoding_seconds': encoding, 'sat_seconds': solve,
                                   'dimacs_bytes': path.stat().st_size, **formula_metrics})
        result = {'case': name, 'rows': len(rows), 'source_payload_bytes': sum(map(len, rows)),
                  'candidates': len(problem.candidates), 'maxsat_variables': problem.nv,
                  'maximum_candidate_fragment_bytes': 32 if cap == 64 else 16,
                  'maxsat_hard_clauses': len(problem.hard), 'common_bytes': optimum.common_bytes,
                  'encoding_seconds': encoding_seconds, 'maxsat_seconds': solve_seconds,
                  'every_byte_and_width_verified': True, 'measurements': metrics,
                  'sat_budget_search': sat_search,
                  'budget_cnf_checks': cnf_checks, 'public_fixture_sources': provenance}
        results.append(result)
        print(json.dumps({k: v for k, v in result.items() if k not in ('public_fixture_sources', 'measurements')}) , flush=True)
    summary = {'scope': 'standalone token-byte representation experiment; no scanner integration',
               'source_commit': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
               'python': platform.python_version(), 'python_sat': pysat.__version__,
               'platform': platform.platform(), 'cases': results,
               'tool_sha256': {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                               for name in ['joint_token_dictionary.py', 'joint_budget_cnf.py',
                                            'run_joint_dictionary.py', 'probe_joint_dictionary.c']},
               'native_probe_sha256': hashlib.sha256(args.probe.read_bytes()).hexdigest() if args.probe else None,
               'limitations': ['Public literal fixtures are not compiled token exports or representative official databases.',
                               'Candidate pruning and the flat format restrict the modeled optimum.',
                               'Native decoder RSS includes process overhead; small-image differences are below page granularity.',
                               'No engine RSS, detection/order equivalence, full/restricted database qualification or solver speedup is established.']}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
