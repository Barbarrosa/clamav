#!/usr/bin/env python3
"""Export tiny count-faithful search queries with independently known answers.

All records and costs are synthetic oracle fixtures. These are not ClamAV RAM,
scanner timing, or release-qualification measurements. Exploratory relaxations
are enabled only to exercise alternative field choices in this tiny model.
This executes ordinary Minisat enumeration, not the linked counting algorithm.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
from types import SimpleNamespace

from pysat.solvers import Solver

from search_model import SearchModel
from field_synthesis import Candidate, STORE_XOR, ALIAS_ADD, HEADER, DESC


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def independent_oracle(budget, provider=None):
    """Enumerate declared choices using hand costs and an independent DFS.

    The native provider has no active field choices. The encoded provider has
    a fixed 120-byte header/descriptor/locator cost, plus 16 bytes for each raw
    field. An alias has no payload, but must eventually reach a stored field.
    """
    result = {}
    if provider != 'encoded' and 256 <= budget:
        result[('native',)] = 256
    if provider == 'native':
        return result
    for choices in itertools.product(('raw', 'alias'), repeat=2):
        def reaches_storage(field, visited):
            if field in visited:
                return False
            if choices[field] == 'raw':
                return True
            return reaches_storage(1 - field, visited | {field})
        if not all(reaches_storage(field, set()) for field in range(2)):
            continue
        cost = 120 + 16 * choices.count('raw')
        if cost <= budget:
            result[('encoded',) + choices] = cost
    return result


def fixture_model(catalog, contract, budget, provider=None):
    # Two equal binary-valued synthetic columns admit either a one-bit store
    # or an exact zero-offset alias to the other. This fixture checks choices
    # and costs; actual capture/decoder replay is performed by run_search.py.
    raw = Candidate(STORE_XOR, 1, 8, increment=1, payload_bytes=16)
    a_alias = Candidate(ALIAS_ADD, 0, 8, parent=1, increment=1)
    b_alias = Candidate(ALIAS_ADD, 0, 8, parent=0, increment=1)
    problem = SimpleNamespace(names=['a', 'b'], nrows=2,
                              candidates=[[raw, a_alias], [raw, b_alias]])
    if HEADER.size + 2 * DESC.size + 16 + 12 * 2 != 120:
        raise AssertionError('fixture hand costs require the documented field ABI')
    model = SearchModel([dict(name='tiny', problem=problem, native_bytes=256,
                              identity_objects=2)], catalog, contract,
        policy='explore', query_units=16, dependency_depth=2, identity_reads=45,
        allow_log_lookup=True, allow_component_regression=True, reader_lines=1,
        budgets={'steady_bytes': budget})
    if provider:
        model.formula.force(model.families[0][provider])
    return model


def identify_configuration(model, assignment):
    group = model.families[0]
    if assignment[group['native']]:
        if any(assignment[v] for field in group['selection'] for v in field):
            raise AssertionError('native provider leaves an active field choice')
        return ('native',)
    choices = []
    for variables in group['selection']:
        selected = [index for index, variable in enumerate(variables) if assignment[variable]]
        if len(selected) != 1:
            raise AssertionError('encoded field does not select exactly one program')
        choices.append('raw' if selected[0] == 0 else 'alias')
    return ('encoded',) + tuple(choices)


def evaluate_query(model, expected):
    """Enumerate all full models and independently rule out second extensions."""
    formula = model.formula
    signatures, extensions_checked = {}, 0
    with Solver(name='m22', bootstrap_with=formula.clauses) as solver:
        if formula.nv:
            solver.add_clause([formula.nv, -formula.nv])
        while solver.solve():
            signed = solver.get_model()
            values = {abs(literal): literal > 0 for literal in signed}
            if set(values) != set(range(1, formula.nv + 1)):
                raise AssertionError('solver omitted variables from the ambient universe')
            primary = {name: values[variable] for name, variable in formula.primary.items()}
            if formula.extend(primary) != values:
                raise AssertionError('solver model differs from deterministic extension')
            if any(not any(values[abs(literal)] == (literal > 0) for literal in clause)
                   for clause in formula.clauses):
                raise AssertionError('solver model violates an exported clause')
            signature = identify_configuration(model, values)
            if signature in signatures:
                raise AssertionError('multiple assignments count the same declared configuration')
            cost = model.costs(values)['steady_bytes']
            if signature not in expected or cost != expected[signature]:
                raise AssertionError('solver choice or physical cost differs from the hand oracle')
            # A second independent solver fixes ALL genuine choice variables and
            # blocks this full extension. SAT here would reveal multiplicity.
            assumptions = [variable if primary[name] else -variable
                           for name, variable in formula.primary.items()]
            with Solver(name='m22', bootstrap_with=formula.clauses) as checker:
                checker.add_clause([-literal for literal in signed])
                if checker.solve(assumptions=assumptions):
                    raise AssertionError('fixed primary choices have another auxiliary extension')
            extensions_checked += 1
            signatures[signature] = cost
            solver.add_clause([-literal for literal in signed])
    if signatures != expected:
        raise AssertionError('complete solver enumeration differs from independent configuration oracle')
    return {'count': len(signatures), 'enumeration_complete': True,
            'independent_configuration_oracle_agrees': True,
            'deterministic_extension_checks': extensions_checked,
            'independent_second_extension_unsat_checks': extensions_checked,
            'configurations': [{'choices': list(key), 'steady_bytes': value}
                               for key, value in sorted(signatures.items())]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    catalog = json.loads((HERE / 'catalog.json').read_text())
    contract = json.loads((HERE / 'baseline-contract.json').read_text())
    specifications = [('budget-135', 135, None, 0), ('budget-136', 136, None, 2),
                      ('budget-152', 152, None, 3), ('budget-256', 256, None, 4),
                      ('budget-256-native', 256, 'native', 1),
                      ('budget-256-encoded', 256, 'encoded', 3)]
    queries = []
    for name, budget, provider, expected_count in specifications:
        expected = independent_oracle(budget, provider)
        if len(expected) != expected_count:
            raise AssertionError('hand oracle changed its independently known answer')
        model = fixture_model(catalog, contract, budget, provider)
        checked = evaluate_query(model, expected)
        formula = model.formula
        if any(len(clause) > 3 for clause in formula.clauses):
            raise AssertionError('counting query exceeds fixed width three')
        cnf = args.output / (name + '.cnf')
        mapping = args.output / (name + '.variables.json')
        formula.to_file(cnf)
        mapping.write_text(json.dumps(formula.mapping(), indent=2) + '\n')
        queries.append({'name': name, 'budget_bytes': budget,
                        'forced_provider': provider, 'expected_count': expected_count,
                        **checked, 'variables': formula.nv,
                        'primary_variables': len(formula.primary),
                        'auxiliary_variables': len(formula.gates),
                        'clauses': len(formula.clauses),
                        'maximum_clause_width': max(map(len, formula.clauses), default=0),
                        'cnf': cnf.name, 'cnf_sha256': digest(cnf),
                        'variable_map': mapping.name, 'variable_map_sha256': digest(mapping)})
        print(json.dumps({'query': name, 'count': checked['count'],
                          'variables': formula.nv, 'clauses': len(formula.clauses)}), flush=True)
    code = [HERE / name for name in ('make_counting_fixtures.py', 'choice_cnf.py',
            'search_model.py', 'complexity_metrics.py', 'catalog.json', 'baseline-contract.json')]
    code.append(HERE.parent / 'system-model/field_synthesis.py')
    report = {'schema_version': 1,
              'scope': 'synthetic hand-counted configuration oracle; not ClamAV memory or performance measurements',
              'solver_executed': 'Minisat22 complete enumeration and conditioned uniqueness checks',
              'linked_counting_algorithm_executed': False,
              'counting_unit': 'one declared provider/program configuration; native fixes inactive fields false',
              'synthetic_costs': {'native_bytes': 256, 'encoded_fixed_bytes': 120,
                                  'stored_field_payload_bytes': 16, 'alias_payload_bytes': 0},
              'independent_oracle': 'enumerate provider/program tuples, reject dependency cycles with DFS, apply hand byte costs',
              'exploratory_relaxations': {'allow_log_lookup': True,
                  'allow_component_regression': True,
                  'scope': 'tiny synthetic oracle only, not approval of scanner behavior or speed'},
              'source_sha256': {str(path.relative_to(ROOT)): digest(path) for path in code},
              'queries': queries,
              'all_expected_counts_and_unique_extensions_verified': True}
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
