#!/usr/bin/env python3
"""Prepare and run bounded, count-faithful searches on a private engine capture.

Search results are component storage proposals. Unknown scanner behavior, source
ownership, actual RSS and hardware performance remain explicit qualifications.
The linked Lean counting construction is not executed.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from dataclasses import asdict
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
from types import SimpleNamespace

from pysat.examples.rc2 import RC2
from pysat.formula import WCNF
from pysat.solvers import Solver

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / 'system-model'))
from capture import load_capture
from field_synthesis import FieldProblem, FieldStore, build_image, OP_NAMES
from run_system_model import private_directory, write_locator
from complexity_metrics import analyze_field_programs, measure_source
from search_model import SearchModel


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        while block := source.read(1 << 20):
            value.update(block)
    return value.hexdigest()


def retained_cost(capture, path, workers):
    original_directories = sum(int(target.get(key, 0)) for target in capture.layout['targets']
        for key in ('native_pattern_directory_bytes', 'native_candidate_directory_bytes',
                    'native_logical_directory_bytes', 'retained_transition_cleanup_capacity_bytes',
                    'logical_slot_directory_bytes'))
    nodes = next(f.native_bytes for f in capture.families if f.name == 'nodes')
    null_slots = sum(int(t['native_node_arena_bytes']) for t in capture.layout['targets']) - nodes
    ledger = [json.loads(line) for line in (path / 'resident-ledger.jsonl').read_text().splitlines()]
    hashes = sum(int(row.get('payload_bytes', 0)) + int(row.get('metadata_capacity_bytes', 0))
                 for row in ledger if row.get('kind') == 'hash')
    filters = sum(int(row.get('filter_bytes', 0)) for row in ledger if row.get('kind') == 'ac')
    retained = capture.retained_known_payload_bytes + original_directories + null_slots + hashes + filters
    tracking = workers * 12 * sum(int(t.get('logical_slots', 0)) for t in capture.layout['targets'])
    return retained, tracking


def optimize(model):
    problem = WCNF()
    problem.extend(model.formula.clauses)
    for literal, weight in model.terms['steady_bytes']:
        if weight and type(literal) is not bool:
            problem.append([-literal], weight=weight)
    start = time.perf_counter()
    with RC2(problem) as solver:
        assignment = solver.compute()
        if assignment is None:
            return None, time.perf_counter() - start
        values = {abs(v): v > 0 for v in assignment}
        objective = solver.cost + model.constants['steady_bytes']
    complete = model.formula.extend({name: values[variable] for name, variable in model.formula.primary.items()})
    if complete is None or complete != values:
        raise AssertionError('optimizer assignment differs from the deterministic circuit extension')
    if model.costs(complete)['steady_bytes'] != objective:
        raise AssertionError('objective differs from reconstructed choice costs')
    return complete, time.perf_counter() - start


def enumerate_bounded(formula, limit, seconds):
    """Conventional count baseline; truncated enumeration is only a lower bound."""
    import threading
    start, models, finished = time.perf_counter(), 0, False
    with Solver(name='m22', bootstrap_with=formula.clauses) as solver:
        if formula.nv:
            solver.add_clause([formula.nv, -formula.nv])
        timer = threading.Timer(seconds, solver.interrupt)
        timer.daemon = True
        timer.start()
        try:
            while models <= limit:
                feasible = solver.solve_limited(expect_interrupt=True)
                if feasible is None:
                    break
                if not feasible:
                    finished = True
                    break
                if models == limit:
                    break
                values = solver.get_model()
                solver.add_clause([-v for v in values])
                models += 1
        finally:
            timer.cancel()
    return {'solver': 'Minisat22 enumeration, not linked counting algorithm',
            'configurations_counted': models, 'complete': finished,
            'interpretation': 'exact count' if finished else 'lower bound; enumeration limited',
            'seconds': time.perf_counter() - start}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--private-output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--policy', choices=('preserve', 'explore'), default='preserve')
    parser.add_argument('--query-units', type=int, default=64)
    parser.add_argument('--dependency-depth', type=int, default=4)
    parser.add_argument('--identity-reads', type=int, default=45)
    parser.add_argument('--max-new-opcodes', type=int, default=4)
    parser.add_argument('--max-new-indices', type=int, default=2)
    parser.add_argument('--max-reader-lines', type=int, default=400)
    parser.add_argument('--max-new-formats', type=int, default=1)
    parser.add_argument('--max-decoder-cases', type=int, default=7)
    parser.add_argument('--allow-log-lookup', action='store_true',
                        help='explicit exploratory relaxation of baseline O(1) source-identity field access')
    parser.add_argument('--allow-component-regression', action='store_true',
                        help='explicitly explore a category with a known isolated-reader slowdown; never a parity claim')
    parser.add_argument('--steady-budget', type=int)
    parser.add_argument('--conversion-budget', type=int)
    parser.add_argument('--reload-budget', type=int)
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--fix', action='append', default=[], metavar='PRIMARY=true|false',
                        help='condition a declared primary choice; names are in variables.json')
    parser.add_argument('--exclude-config', type=Path, action='append', default=[],
                        help='exclude a complete previously tested configuration bound to this choice schema')
    parser.add_argument('--enumerate-limit', type=int, default=0)
    parser.add_argument('--enumerate-seconds', type=float, default=10)
    args = parser.parse_args()
    if args.workers < 0 or args.enumerate_limit < 0 or args.enumerate_seconds <= 0:
        parser.error('worker/enumeration bounds must be valid')
    if (args.allow_log_lookup or args.allow_component_regression) and args.policy != 'explore':
        parser.error('relaxations are available only for explicitly exploratory searches')
    private_directory(args.capture)
    private = private_directory(args.private_output)
    args.report.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    catalog = json.loads((HERE / 'catalog.json').read_text())
    contract = json.loads((HERE / 'baseline-contract.json').read_text())
    capture = load_capture(args.capture)
    input_hashes = {p.name: digest(p) for p in args.capture.iterdir() if p.is_file()}
    retained, tracking = retained_cost(capture, args.capture, args.workers)
    sources = {family.name: family for family in capture.families}
    families = []
    for family in capture.families:
        # Reuse validated candidate generation, not its old nonunique SAT helpers.
        problem = FieldProblem(family.columns, family.source_bits, max_depth=64)
        objects = capture.manifest['transition_rows'] if family.name == 'transition_values' else family.rows
        families.append(dict(name=family.name, problem=problem, native_bytes=family.native_bytes,
                             identity_objects=objects))
    definition = {'catalog_sha256': digest(HERE / 'catalog.json'), 'input_sha256': input_hashes,
                  'families': [{'name': f['name'], 'native_bytes': f['native_bytes'],
                    'identity_objects': f['identity_objects'], 'names': f['problem'].names,
                    'candidates': [[asdict(c) for c in options] for options in f['problem'].candidates]}
                    for f in families]}
    # This file contains native constants. Only its digest is public.
    definition_bytes = json.dumps(definition, sort_keys=True, separators=(',', ':')).encode()
    schema_hash = hashlib.sha256(definition_bytes).hexdigest()
    (private / 'private-choice-definitions.json').write_bytes(definition_bytes)
    blocked = []
    for path in args.exclude_config:
        supplied = json.loads(path.read_text())
        if supplied.get('choice_schema_sha256') != schema_hash:
            parser.error('excluded configuration belongs to a different capture/choice schema')
        evidence_hash = supplied.get('evidence_sha256', '')
        if (not isinstance(evidence_hash, str) or len(evidence_hash) != 64
                or any(c not in '0123456789abcdef' for c in evidence_hash)):
            parser.error('excluded configuration needs its evidence SHA-256')
        blocked.append(supplied['primary'])
    reader = measure_source(HERE.parent / 'system-model/probe_field_store.c')
    budgets = {name: value for name, value in [('steady_bytes', args.steady_budget),
        ('conversion_peak_bytes', args.conversion_budget), ('reload_peak_bytes', args.reload_budget)] if value is not None}
    fixed_choices = {}
    for condition in args.fix:
        name, separator, value = condition.rpartition('=')
        if not separator or value not in ('true', 'false') or name in fixed_choices:
            parser.error('--fix needs unique PRIMARY=true or PRIMARY=false conditions')
        fixed_choices[name] = value == 'true'
    model = SearchModel(families, catalog, contract, policy=args.policy,
        query_units=args.query_units, dependency_depth=args.dependency_depth,
        identity_reads=args.identity_reads, max_new_opcodes=args.max_new_opcodes,
        max_new_indices=args.max_new_indices, max_reader_lines=args.max_reader_lines,
        max_new_formats=args.max_new_formats, max_decoder_cases=args.max_decoder_cases,
        reader_lines=reader['nonblank_noncomment_code_lines'],
        allow_log_lookup=args.allow_log_lookup, allow_component_regression=args.allow_component_regression,
        retained_bytes=retained,
        scan_tracking_bytes=tracking, budgets=budgets, fixed_choices=fixed_choices,
        blocked_configurations=blocked)
    values, solve_seconds = optimize(model)
    report = {'schema_version': 1, 'policy': args.policy, 'limits': model.limits,
              'fixed_choices': fixed_choices, 'requested_budgets': budgets,
              'choice_schema_sha256': schema_hash,
              'exclusion_files': {p.name: digest(p) for p in args.exclude_config},
              'counting_unit': 'declared provider/program/catalog configurations, not semantic equivalence classes',
              'linked_counting_algorithm_executed': False,
              'scope': 'captured native field/identity model; not engine RSS or scanner deployment',
              'catalog_audit': model.audit, 'capture_dimensions': capture.manifest,
              'retained_known_bytes': retained, 'scan_tracking_known_bytes': tracking,
              'source_sha256': {p.name: digest(p) for p in HERE.glob('*') if p.suffix in ('.py', '.json')},
              'input_sha256': input_hashes,
              'reader_source_complexity': reader,
              'solver': 'PySAT RC2', 'solve_seconds': solve_seconds,
              'status': 'satisfiable' if values is not None else 'unsatisfiable_within_declared_choices'}
    if values is not None:
        costs = model.costs(values)
        replay, physical_provider = [], 0
        for group, selected in model.selected(values):
            source = group['source']
            family = sources[source['name']]
            if selected is None:
                physical_provider += family.native_bytes
                replay.append({'family': family.name, 'provider': 'native', 'rows': family.rows})
                continue
            image = build_image(source['problem'], selected)
            store = FieldStore(image, source['problem'].names)
            verified = family.verify(SimpleNamespace(reconstruct=store.reconstruct, get=store.get))
            (private / (family.name + '.fields')).write_bytes(image)
            addresses = family.addresses
            if family.name == 'transition_values':
                import numpy as np
                addresses = np.fromfile(args.capture / 'transition_addresses.bin', dtype='<u8')
            locator = write_locator(addresses, private / (family.name + '.locator'))
            if locator['bytes'] != group['locator_bytes']:
                raise AssertionError('actual resolver storage differs from formula')
            physical_provider += len(image) + locator['bytes']
            public = [{'field': name, 'operation': OP_NAMES[p.op], 'width': p.width,
                       'parent': None if p.parent == (1 << 32) - 1 else source['problem'].names[p.parent],
                       'payload_bytes': p.payload_bytes,
                       'argument_sha256': hashlib.sha256(struct.pack('<Q', p.arg)).hexdigest()}
                      for name, p in zip(source['problem'].names, selected)]
            complexity = analyze_field_programs(selected, family.rows,
                identity_strategy='binary_address', identity_objects=source['identity_objects'])
            replay.append({'family': family.name, 'provider': 'encoded', 'image_bytes': len(image),
                           'identity_locator_bytes': locator['bytes'], 'programs': public,
                           'complexity': complexity, **verified})
        if physical_provider + retained + tracking != costs['steady_bytes']:
            raise AssertionError('physical selected storage differs from memory objective')
        report.update(costs=costs, selected_catalog=model.public_choices(values), families=replay,
            physical_provider_bytes_verified=physical_provider,
            reconstructed_all_selected_fields=True,
            qualification={'scanner_correctness': 'not established by captured field replay',
                           'original_clamav_performance_parity': 'missing source-bound whole-scanner measurements',
                           'deployment_allowed': False,
                           'lookup_growth_relaxed': bool(args.allow_log_lookup),
                           'known_component_regression_category_relaxed': bool(args.allow_component_regression)})
        # A supplied budget remains a budget query (including near-optimal
        # alternatives); otherwise export the optimum found by this run.
        query_budget = args.steady_budget if args.steady_budget is not None else costs['steady_bytes']
        if args.steady_budget is None:
            model.apply_budgets({'steady_bytes': query_budget})
        report['query_steady_budget_bytes'] = query_budget
        extended = model.formula.extend({name: values[variable]
                                         for name, variable in model.formula.primary.items()})
        if extended is None:
            raise AssertionError('optimizer witness fails exported budget')
        witness = [v if extended[v] else -v for v in range(1, model.formula.nv + 1)]
        (private / 'witness.json').write_text(json.dumps(witness) + '\n')
        configuration = {'choice_schema_sha256': schema_hash,
                         'primary': {name: extended[v] for name, v in model.formula.primary.items()},
                         'evidence_sha256': None,
                         'note': 'Fill evidence hash only after a scoped evaluation justifies excluding this exact configuration.'}
        (args.report / 'selected-configuration.json').write_text(json.dumps(configuration, indent=2) + '\n')
        mapping = [{'family': f['source']['name'], 'native': f['native'], 'encoded': f['encoded'],
                    'candidates': [[asdict(c) for c in options] for options in f['source']['problem'].candidates],
                    'variables': f['selection']} for f in model.families]
        (private / 'private-candidates.json').write_text(json.dumps(mapping) + '\n')
        report['witness_sha256'] = digest(private / 'witness.json')
        report['unique_circuit_extension_verified'] = True
        if args.enumerate_limit:
            report['count_baseline'] = enumerate_bounded(model.formula, args.enumerate_limit, args.enumerate_seconds)
            report['count_baseline']['independently_replayed_witness_lower_bound'] = 1
    body = model.formula.dimacs().encode('ascii')
    (private / 'query.cnf').write_bytes(body)
    # Only Boolean formulas/maps are public. The private candidate map contains
    # native constants; raw captures and images are never copied to reports.
    (args.report / 'query.cnf.gz').write_bytes(gzip.compress(body, mtime=0))
    (args.report / 'variables.json').write_text(json.dumps(model.formula.mapping(), indent=2) + '\n')
    report['formula'] = model.formula.mapping()
    report['formula'].pop('primary')
    report['formula'].pop('auxiliary')
    report['formula_sha256'] = hashlib.sha256(body).hexdigest()
    report['wall_seconds'] = time.perf_counter() - started
    if sys.platform.startswith('linux'):
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        report['optimizer_process_observation'] = {
            'user_cpu_seconds': usage.ru_utime, 'system_cpu_seconds': usage.ru_stime,
            'highwater_rss_bytes': usage.ru_maxrss * 1024,
            'scope': 'this offline Python/native-solver process, including capture pages and construction; not scanner RAM'}
    report['limitations'] = [
        'Only candidate field programs have current capture-derived serializers and nonoverlapping costs; other catalog choices remain explicit gated research variables.',
        'The preserved baseline is this capture of the retained branch, distinct from original upstream performance qualification.',
        'Query units charge declared resource primitives and lookup bounds, not instructions, cache behavior or CPU latency.',
        'Growth regression is blocked by default; explicit logarithmic-lookup relaxation produces unqualified research proposals.',
        'Known live extents and one worker tracking subset are accounted; other scanner, allocator and construction scratch memory is unknown, not zero.',
        'Conversion/reload curves assume captured equal-size generations; all-changed updates and real RSS need measurements.',
        'The MaxSAT optimum is within the generated candidate family; no independent UNSAT optimality certificate is exported.',
        'Full-equivalence helper variables preserve configuration counts; different program descriptions can still implement equivalent semantics.']
    (args.report / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'policy': args.policy,
                      'costs': report.get('costs'), 'variables': model.formula.nv,
                      'clauses': len(model.formula.clauses), 'seconds': report['wall_seconds']}))


if __name__ == '__main__':
    main()
