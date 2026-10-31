"""Shared conventional solver baseline for the five bounded layout tests.

This does not execute the linked noncomputable Lean construction.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from joint_budget_cnf import budget_cnf
from pysat.card import CardEnc, EncType
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF
from pysat.solvers import Solver


class BooleanModel:
    def __init__(self):
        self.hard = []
        self.costs = []
        self.nv = 0

    def new(self):
        self.nv += 1
        return self.nv

    def at_most(self, literals, bound):
        literals = list(literals)
        if bound < 0:
            self.hard.append([])
        elif bound < len(literals):
            encoded = CardEnc.atmost(lits=literals, bound=bound, top_id=self.nv,
                                     encoding=EncType.seqcounter)
            self.hard.extend(encoded.clauses)
            self.nv = max(self.nv, encoded.nv)

    def exactly_one(self, literals):
        literals = list(literals)
        self.hard.append(literals)
        self.at_most(literals, 1)

    def wcnf(self):
        formula = WCNF()
        formula.extend(self.hard)
        for variable, weight in self.costs:
            if type(weight) is not int or weight < 0:
                raise ValueError('nonnegative integer byte weights required')
            if weight:
                formula.append([-variable], weight=weight)
        return formula

    def solve(self):
        start = time.perf_counter()
        with RC2(self.wcnf()) as solver:
            model = solver.compute()
            if model is None:
                raise ValueError('infeasible layout constraints')
            chosen = {v for v in model if v > 0}
            cost = sum(w for v, w in self.costs if v in chosen)
            if cost != solver.cost:
                raise AssertionError('chosen byte cost differs from MaxSAT optimum')
        return chosen, cost, {'solver': 'PySAT RC2', 'variables': self.nv,
                              'hard_clauses': len(self.hard),
                              'solve_seconds': time.perf_counter() - start}

    def verify_budget(self, optimum, artifact_prefix=None):
        """Check B-1 UNSAT and B SAT, with a 30-second limit per SAT query.

        Budget excludes any constant overhead outside this model. Counts concern
        all CNF variables, including encoder auxiliaries, not physical layouts.
        """
        checks = []
        for budget in (optimum - 1, optimum):
            start = time.perf_counter()
            clauses = budget_cnf(self.hard, self.costs, budget)
            encoding_seconds = time.perf_counter() - start
            variables = max((abs(v) for c in clauses for v in c), default=0)
            start = time.perf_counter()
            with Solver(name='m22', bootstrap_with=clauses) as solver:
                timer = threading.Timer(30.0, solver.interrupt)
                timer.daemon = True
                timer.start()
                try:
                    satisfiable = solver.solve_limited(expect_interrupt=True)
                    if satisfiable is None:
                        raise TimeoutError('SAT budget check timed out; no feasibility conclusion')
                    if satisfiable:
                        positive = {v for v in solver.get_model() if v > 0}
                        actual = sum(w for v, w in self.costs if v in positive)
                        if actual > budget:
                            raise AssertionError('recovered witness exceeds budget')
                finally:
                    timer.cancel()
            if satisfiable != (budget == optimum):
                raise AssertionError('SAT and MaxSAT optimum disagree')
            record = {'variable_byte_budget': budget, 'satisfiable': satisfiable,
                      'variables': variables, 'clauses': len(clauses),
                      'max_clause_width': max(map(len, clauses), default=0),
                      'encoding_seconds': encoding_seconds,
                      'sat_seconds': time.perf_counter() - start}
            if record['max_clause_width'] > 3:
                raise AssertionError('fixed clause width exceeded')
            if artifact_prefix is not None:
                path = Path(str(artifact_prefix) + '-' + str(budget) + '.cnf')
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('w') as out:
                    out.write(f'p cnf {variables} {len(clauses)}\n')
                    for clause in clauses:
                        out.write(' '.join(map(str, clause)) + ' 0\n')
                record['dimacs_bytes'] = path.stat().st_size
            checks.append(record)
        return {'engine': 'conventional Minisat22; not the linked counting program',
                'checks': checks}
