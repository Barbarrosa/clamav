#!/usr/bin/env python3
"""Export an actual weighted system model as <=3-CNF and run budget queries.

Private DIMACS bodies and witnesses may encode a captured database. Public
reports contain only dimensions, hashes, timing, status and verified byte cost.
This runs conventional Minisat22, not the linked Lean counting construction.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading
import time

from pysat.formula import CNF, WCNF
from pysat.solvers import Solver

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from joint_budget_cnf import budget_cnf


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def weighted_costs(formula):
    """RC2's soft [-v] penalty is exactly weight*v."""
    costs = []
    if len(formula.soft) != len(formula.wght):
        raise ValueError('soft clause/weight count mismatch')
    for clause, weight in zip(formula.soft, formula.wght):
        if len(clause) != 1 or clause[0] >= 0 or type(weight) is not int or weight < 0:
            raise ValueError('expected nonnegative weighted unit clauses [-positive_variable]')
        costs.append((-clause[0], weight))
    return costs


def verify_witness(model, hard, costs, budget, encoded=None):
    assignment = {abs(literal): literal > 0 for literal in model}
    if len(assignment) != len(model):
        raise ValueError('model repeats a variable')
    for clauses in [hard] + ([encoded] if encoded is not None else []):
        for clause in clauses:
            if not any(assignment.get(abs(literal)) == (literal > 0) for literal in clause):
                raise ValueError('witness violates a hard clause or lacks its assignments')
    if any(variable not in assignment for variable, _ in costs):
        raise ValueError('witness omits a cost variable')
    actual = sum(weight for variable, weight in costs if assignment[variable])
    if actual > budget:
        raise ValueError('witness exceeds exact byte budget')
    return actual


def write_dimacs(path, clauses):
    variables = max((abs(literal) for clause in clauses for literal in clause), default=0)
    maximum_width = max(map(len, clauses), default=0)
    if maximum_width > 3:
        raise AssertionError('budget encoding exceeds fixed width three')
    digest = hashlib.sha256()
    with Path(path).open('wb') as dest:
        header = f'p cnf {variables} {len(clauses)}\n'.encode()
        dest.write(header)
        digest.update(header)
        for clause in clauses:
            line = (' '.join(map(str, clause)) + ' 0\n').encode()
            dest.write(line)
            digest.update(line)
    return {'variables': variables, 'clauses': len(clauses),
            'literal_occurrences': sum(map(len, clauses)),
            'maximum_clause_width': maximum_width,
            'dimacs_bytes': Path(path).stat().st_size,
            'dimacs_sha256': digest.hexdigest()}


def run_query(formula, costs, budget, output, timeout=30.0):
    result = {'budget_bytes': budget, 'solver': 'Minisat22',
              'linked_counting_construction_executed': False,
              'solve_timeout_seconds': timeout}
    start = time.perf_counter()
    clauses = budget_cnf(formula.hard, costs, budget)
    result['encoding_seconds'] = time.perf_counter() - start
    path = output / f'budget-{budget}.cnf'
    start = time.perf_counter()
    result.update(write_dimacs(path, clauses))
    result['dimacs_write_seconds'] = time.perf_counter() - start
    result['dimacs_private_file'] = path.name
    start = time.perf_counter()
    with Solver(name='m22', bootstrap_with=clauses) as solver:
        result['solver_load_seconds'] = time.perf_counter() - start
        timer = threading.Timer(timeout, solver.interrupt)
        timer.daemon = True
        start = time.perf_counter()
        timer.start()
        try:
            feasible = solver.solve_limited(expect_interrupt=True)
            result['solve_seconds'] = time.perf_counter() - start
            result['solver_statistics'] = solver.accum_stats()
            result['status'] = 'unknown_timeout' if feasible is None else ('sat' if feasible else 'unsat')
            if feasible:
                model = solver.get_model()
                start = time.perf_counter()
                actual = verify_witness(model, formula.hard, costs, budget, clauses)
                result['witness_verification_seconds'] = time.perf_counter() - start
                result['verified_weighted_byte_cost'] = actual
                result['all_original_and_encoded_hard_clauses_verified'] = True
                witness = output / f'budget-{budget}-witness.json'
                witness.write_text(json.dumps(model) + '\n')
                result['witness_private_file'] = witness.name
                result['witness_sha256'] = file_sha256(witness)
        finally:
            timer.cancel()
    return result


def run_witness_check(formula, costs, budget, cnf_path, witness_path, output, timeout=30.0):
    """Extend a known original-model assignment with free encoder variables.

    This checks the reduction and the known witness. It is deliberately distinct
    from asking the SAT solver to find a solution without those assumptions.
    """
    original = json.loads(Path(witness_path).read_text())
    if (not isinstance(original, list) or
            any(type(v) is not int or v == 0 or abs(v) > formula.nv for v in original)):
        raise ValueError('expected signed original WCNF model assignments')
    original_cost = verify_witness(original, formula.hard, costs, budget)
    result = {'scope': 'known RC2 witness extension; not unassisted SAT search',
              'budget_bytes': budget, 'solver': 'Minisat22',
              'linked_counting_construction_executed': False,
              'known_original_weighted_byte_cost': original_cost,
              'original_witness_sha256': file_sha256(witness_path),
              'assumed_original_variables': len(original),
              'solve_timeout_seconds': timeout}
    start = time.perf_counter()
    encoded = CNF(from_file=str(cnf_path))
    result['dimacs_load_seconds'] = time.perf_counter() - start
    result['dimacs_sha256'] = file_sha256(cnf_path)
    result['encoding_auxiliary_variables_left_free'] = encoded.nv - len(original)
    start = time.perf_counter()
    with Solver(name='m22', bootstrap_with=encoded.clauses) as solver:
        result['solver_load_seconds'] = time.perf_counter() - start
        timer = threading.Timer(timeout, solver.interrupt)
        timer.daemon = True
        start = time.perf_counter()
        timer.start()
        try:
            feasible = solver.solve_limited(assumptions=original, expect_interrupt=True)
            result['solve_seconds'] = time.perf_counter() - start
            result['status'] = 'unknown_timeout' if feasible is None else ('sat' if feasible else 'unsat')
            result['solver_statistics'] = solver.accum_stats()
            if feasible:
                model = solver.get_model()
                start = time.perf_counter()
                actual = verify_witness(model, formula.hard, costs, budget, encoded.clauses)
                assignment = set(model)
                if not all(literal in assignment for literal in original):
                    raise AssertionError('extended witness differs from assumed original assignment')
                result['verified_weighted_byte_cost'] = actual
                result['all_original_and_encoded_hard_clauses_verified'] = True
                result['witness_verification_seconds'] = time.perf_counter() - start
                path = Path(output) / f'budget-{budget}-witness-extension.json'
                path.write_text(json.dumps(model) + '\n')
                result['witness_private_file'] = path.name
                result['witness_sha256'] = file_sha256(path)
        finally:
            timer.cancel()
    return result


def append_witness(wcnf_path, budget, output, report, witness_path, timeout=30.0):
    report = Path(report)
    result = json.loads(report.read_text())
    if result['wcnf_sha256'] != file_sha256(wcnf_path):
        raise ValueError('WCNF changed since the unassisted queries')
    query = next((q for q in result['queries'] if q['budget_bytes'] == budget), None)
    if query is None:
        raise ValueError('no existing DIMACS query for witness budget')
    cnf_path = Path(output) / query['dimacs_private_file']
    if file_sha256(cnf_path) != query['dimacs_sha256']:
        raise ValueError('DIMACS changed since the unassisted query')
    formula = WCNF(from_file=str(wcnf_path))
    costs = weighted_costs(formula)
    result['known_witness_extension'] = run_witness_check(
        formula, costs, budget, cnf_path, witness_path, output, timeout)
    report.write_text(json.dumps(result, indent=2) + '\n')
    check = result['known_witness_extension']
    print(json.dumps({'check': 'known RC2 witness extension',
                      'budget_bytes': budget, 'status': check['status'],
                      'solve_seconds': check['solve_seconds']}), flush=True)
    return result


def run(wcnf_path, budgets, output, report, timeout=30.0, witness=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = Path(report)
    report.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    formula = WCNF(from_file=str(wcnf_path))
    costs = weighted_costs(formula)
    result = {'scope': 'same complete captured system model; weighted byte budgets converted to <=3-CNF',
              'solver_executed': 'conventional Minisat22; no Lean counting program execution',
              'wcnf_sha256': file_sha256(wcnf_path), 'wcnf_bytes': Path(wcnf_path).stat().st_size,
              'original_variables': formula.nv, 'original_hard_clauses': len(formula.hard),
              'original_weighted_terms': len(costs),
              'wcnf_load_seconds': time.perf_counter() - start, 'queries': [],
              'limitations': ['Unknown after timeout is not an infeasibility conclusion.',
                              'UNSAT is a conventional solver result without an exported proof certificate.',
                              'Positive counts would establish feasibility, but no counts are computed here.',
                              'Equisatisfiable auxiliary variables do not count distinct physical layouts.',
                              'Budget covers exactly the WCNF objective; retained opaque allocations are separate.']}
    report.write_text(json.dumps(result, indent=2) + '\n')
    for budget in budgets:
        query = run_query(formula, costs, budget, output, timeout)
        result['queries'].append(query)
        report.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'budget_bytes': budget, 'status': query['status'],
                          'variables': query['variables'], 'clauses': query['clauses'],
                          'encoding_seconds': query['encoding_seconds'],
                          'solve_seconds': query['solve_seconds']}), flush=True)
    if witness is not None:
        return append_witness(wcnf_path, budgets[0], output, report, witness, timeout)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wcnf', type=Path, required=True)
    parser.add_argument('--budgets', required=True, help='comma-separated exact byte budgets')
    parser.add_argument('--private-output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=30.0)
    parser.add_argument('--witness', type=Path, help='optional known signed original RC2 model; checked separately')
    parser.add_argument('--witness-only', action='store_true',
                        help='append witness extension to an existing report without repeating unassisted searches')
    args = parser.parse_args()
    try:
        budgets = [int(value) for value in args.budgets.split(',')]
        if not budgets or len(budgets) != len(set(budgets)) or any(b < 0 for b in budgets):
            raise ValueError
    except ValueError:
        parser.error('--budgets requires distinct nonnegative integers')
    if not 0 < args.timeout <= 300:
        parser.error('--timeout must be positive and at most 300 seconds')
    if args.witness_only:
        if args.witness is None or len(budgets) != 1:
            parser.error('--witness-only needs --witness and exactly one budget')
        append_witness(args.wcnf, budgets[0], args.private_output, args.report, args.witness, args.timeout)
    else:
        run(args.wcnf, budgets, args.private_output, args.report, args.timeout, args.witness)


if __name__ == '__main__':
    main()
