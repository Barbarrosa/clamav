"""Count-faithful choices over captured native fields and declared contracts.

This is an offline GET/identity model, not a replacement scanner. Every helper
is a deterministic circuit output. Native providers fix inactive field choices
to false. Derived resource predicates are functions of choices, not free levels.
SPDX-License-Identifier: GPL-2.0-only
"""
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
import json
import math
import sys

from choice_cnf import Formula
from complexity_metrics import local_query_units

SYSTEM = Path(__file__).resolve().parents[1] / 'system-model'
sys.path.insert(0, str(SYSTEM))
from field_synthesis import (ALIAS_ADD, ALIAS_XOR, SPARSE, NIL, HEADER, DESC)


def catalog_audit(catalog, contract):
    """Keep evidence status separate from available calibrated implementations."""
    if catalog.get('schema_version') != 1 or contract.get('schema_version') != 1:
        raise ValueError('unsupported catalog/contract schema')
    required = set(contract['correctness_properties'])
    seen, result = set(), []
    for group in catalog['groups']:
        if not isinstance(group['id'], str) or group['id'] in seen:
            raise ValueError('duplicate/invalid catalog group')
        seen.add(group['id'])
        choices, identifiers = group['choices'], set()
        for choice in choices:
            identifier = choice['id']
            if identifier in identifiers:
                raise ValueError('duplicate catalog choice')
            identifiers.add(identifier)
            if not required.issubset(choice['correctness']):
                raise ValueError('incomplete correctness declaration')
            if any(s not in ('passed', 'failed', 'unknown', 'inherited')
                   for s in choice['correctness'].values()):
                raise ValueError('invalid correctness status')
            reasons = []
            if choice['status'] == 'rejected':
                reasons.append('known rejected implementation')
            if 'failed' in choice['correctness'].values():
                reasons.append('known correctness failure')
            if choice['status'] == 'unimplemented':
                reasons.append('implementation missing')
            if choice['performance'].get('component_parity') == 'failed':
                reasons.append('known component performance failure')
            if any(s not in ('passed', 'inherited') for s in choice['correctness'].values()):
                reasons.append('scanner correctness qualification missing')
            if choice['performance']['whole_scanner_parity'] != 'passed':
                reasons.append('source-bound upstream performance qualification missing')
            result.append({'group': group['id'], 'choice': identifier,
                           'retained_fallback': identifier == group['baseline_choice'],
                           'strict_qualification_blockers': reasons,
                           'historical_sizes_are_solver_coefficients': False})
        if group['baseline_choice'] not in identifiers:
            raise ValueError('catalog group has no retained fallback')
    return result


class SearchModel:
    """Bounded physical field-program choices plus explicit surrounding choices.

    Families: {name, problem: FieldProblem, native_bytes, identity_objects}.
    Other catalog groups stay at their retained fallback until a serializer,
    nonoverlapping cost adapter and correctness checker are supplied. Their
    unknown sizes are never silently added as free alternatives.
    """
    def __init__(self, families, catalog, contract, *, policy='preserve',
                 query_units=64, dependency_depth=4, identity_reads=45,
                 max_new_opcodes=4, max_new_indices=2, max_reader_lines=400,
                 max_new_formats=1, max_decoder_cases=7,
                 reader_lines=0, allow_log_lookup=False, allow_component_regression=False, retained_bytes=0,
                 scan_tracking_bytes=0, budgets=None, fixed_choices=None, blocked_configurations=None):
        if policy not in ('preserve', 'explore'):
            raise ValueError('policy must be preserve or explore')
        if allow_component_regression and policy != 'explore':
            raise ValueError('known component regressions require explicit exploratory policy')
        for value in (query_units, dependency_depth, identity_reads, max_new_opcodes,
                      max_new_indices, max_reader_lines, max_new_formats, max_decoder_cases, reader_lines, retained_bytes,
                      scan_tracking_bytes):
            if type(value) is not int or value < 0:
                raise ValueError('limits must be nonnegative integers')
        if query_units > 256 or dependency_depth > 64:
            raise ValueError('bounded synthesis limits exceed supported construction')
        self.audit = catalog_audit(catalog, contract)
        self.formula, self.families, self.groups = Formula(), [], {}
        self.terms = {name: [] for name in ('steady_bytes', 'conversion_peak_bytes',
                                           'reload_peak_bytes', 'new_opcode_kinds',
                                           'new_index_kinds', 'new_format_kinds',
                                           'prototype_decoder_cases', 'prototype_reader_lines')}
        self.constants = {'steady_bytes': retained_bytes + scan_tracking_bytes,
                          'conversion_peak_bytes': retained_bytes + scan_tracking_bytes
                              + sum(f['native_bytes'] for f in families),
                          'reload_peak_bytes': 2 * retained_bytes + scan_tracking_bytes
                              + sum(f['native_bytes'] for f in families)}
        self.policy = policy
        self.limits = dict(query_units=query_units, dependency_depth=dependency_depth,
                           identity_reads=identity_reads, max_new_opcodes=max_new_opcodes,
                           max_new_indices=max_new_indices, max_reader_lines=max_reader_lines,
                           max_new_formats=max_new_formats, max_decoder_cases=max_decoder_cases,
                           allow_log_lookup=allow_log_lookup,
                           allow_component_regression=allow_component_regression)
        for group in catalog['groups']:
            choices = {c['id']: self.formula.new_primary('catalog/' + group['id'] + '/' + c['id'])
                       for c in group['choices']}
            self.groups[group['id']] = choices
            self.formula.exactly_one(list(choices.values()))
            if group['id'] not in ('field_provider', 'lookup'):
                self.formula.force(choices[group['baseline_choice']])
            for choice in group['choices']:
                if choice['status'] in ('rejected', 'unimplemented'):
                    self.formula.force(-choices[choice['id']])
                if ('failed' in choice['correctness'].values()
                        or choice['performance'].get('whole_scanner_parity') == 'failed'):
                    self.formula.force(-choices[choice['id']])
                if choice['performance'].get('component_parity') == 'failed' and not allow_component_regression:
                    self.formula.force(-choices[choice['id']])
        names = [f['name'] for f in families]
        if len(set(names)) != len(names):
            raise ValueError('duplicate family')
        all_encoded, all_derived, opcodes = [], [], {}
        for family in families:
            p, name = family['problem'], family['name']
            native = self.formula.new_primary('provider/' + name + '/native')
            encoded = self.formula.new_primary('provider/' + name + '/encoded')
            self.formula.exactly_one([native, encoded])
            objects = family['identity_objects']
            locator_bytes = 16 + 12 * objects
            if type(objects) is not int or objects < 0:
                raise ValueError('identity object count must be a nonnegative integer')
            lookup = 2 * objects.bit_length() + 1 if objects else 0
            # Every currently implemented encoded provider preserves source
            # identities through the charged binary locator. Direct IDs are a
            # separately declared, unimplemented alternative, never free support.
            if policy == 'preserve' or not allow_log_lookup or lookup > identity_reads:
                self.formula.force(native)
            if p.nrows and query_units < 1:
                self.formula.force(-native)
            selection = []
            for field, options in enumerate(p.candidates):
                variables = [self.formula.new_primary('field/' + name + '/' + p.names[field] + '/' + str(i))
                             for i in range(len(options))]
                self.formula.exactly_one([native] + variables)
                selection.append(variables)
                for variable, candidate in zip(variables, options):
                    self.terms['steady_bytes'].append((variable, candidate.payload_bytes))
                    self.terms['conversion_peak_bytes'].append((variable, candidate.payload_bytes))
                    self.terms['reload_peak_bytes'].append((variable, 2 * candidate.payload_bytes))
                    opcodes.setdefault(candidate.op, []).append(variable)
                    if candidate.op in (ALIAS_XOR, ALIAS_ADD, SPARSE):
                        all_derived.append(variable)
            fixed = HEADER.size + DESC.size * len(p.names) + locator_bytes
            self.terms['steady_bytes'] += [(native, family['native_bytes']), (encoded, fixed)]
            self.terms['conversion_peak_bytes'].append((encoded, fixed))
            self.terms['reload_peak_bytes'] += [(native, family['native_bytes']), (encoded, 2 * fixed)]

            @lru_cache(None)
            def within(field, limit, metric):
                if limit < 0:
                    return False
                alternatives = []
                for variable, candidate in zip(selection[field], p.candidates[field]):
                    increment = (local_query_units(candidate, p.nrows) if metric == 'units'
                                 else int(candidate.parent != NIL))
                    if increment > limit:
                        continue
                    parent = True if candidate.parent == NIL else within(
                        candidate.parent, limit - increment, metric)
                    alternatives.append(self.formula.and_(variable, parent))
                return self.formula.any_(alternatives)

            for field in range(len(p.names)):
                self.formula.imply(encoded, within(field, query_units - lookup, 'units'))
                self.formula.imply(encoded, within(field, dependency_depth, 'depth'))
            self.families.append(dict(source=family, native=native, encoded=encoded,
                                      selection=selection, fixed_bytes=fixed,
                                      locator_bytes=locator_bytes, identity_reads=lookup))
            all_encoded.append(encoded)
        self.any_encoded = self.formula.any_(all_encoded)
        derived = self.formula.any_(all_derived)
        field_group, lookup_group = self.groups['field_provider'], self.groups['lookup']
        self.formula.equivalent(field_group['native'], self.formula.not_(self.any_encoded))
        self.formula.equivalent(field_group['derived_sparse'], derived)
        self.formula.equivalent(field_group['packed_direct'], self.formula.and_(self.any_encoded, self.formula.not_(derived)))
        self.formula.equivalent(lookup_group['native'], self.formula.not_(self.any_encoded))
        self.formula.equivalent(lookup_group['research_binary_locator'], self.any_encoded)
        for op, variables in sorted(opcodes.items()):
            active = self.formula.any_(variables)
            self.terms['new_opcode_kinds'].append((active, 1))
        sparse = self.formula.any_(opcodes.get(SPARSE, []))
        self.terms['new_index_kinds'] = [(self.any_encoded, 1), (sparse, 1)]
        self.terms['new_format_kinds'] = [(self.any_encoded, 1)]
        self.terms['prototype_decoder_cases'] = [(self.any_encoded, 7)]
        self.terms['prototype_reader_lines'] = [(self.any_encoded, reader_lines)]
        for key, limit in (('new_opcode_kinds', max_new_opcodes), ('new_index_kinds', max_new_indices),
                           ('new_format_kinds', max_new_formats), ('prototype_decoder_cases', max_decoder_cases),
                           ('prototype_reader_lines', max_reader_lines)):
            self.formula.at_most_weighted(self.terms[key], limit)
        self.apply_budgets(budgets or {})
        for name, value in (fixed_choices or {}).items():
            if name not in self.formula.primary or type(value) is not bool:
                raise ValueError('conditions must name primary choices and Boolean values')
            literal = self.formula.primary[name]
            self.formula.force(literal if value else -literal)
        for configuration in blocked_configurations or []:
            if (not isinstance(configuration, dict) or set(configuration) != set(self.formula.primary)
                    or any(type(value) is not bool for value in configuration.values())):
                raise ValueError('a blocked configuration must explicitly assign every primary choice')
            self.formula.clause(*[-variable if configuration[name] else variable
                                  for name, variable in self.formula.primary.items()])

    def apply_budgets(self, budgets):
        for key, limit in budgets.items():
            if key not in self.terms or type(limit) is not int or limit < 0:
                raise ValueError('unsupported budget or invalid limit')
            self.formula.at_most_weighted(self.terms[key], limit - self.constants.get(key, 0))

    def costs(self, assignment):
        def truth(literal):
            return literal if type(literal) is bool else assignment[abs(literal)] == (literal > 0)
        return {name: self.constants.get(name, 0) + sum(weight for literal, weight in terms if truth(literal))
                for name, terms in self.terms.items()}

    def selected(self, assignment):
        result = []
        for family in self.families:
            p = family['source']['problem']
            if assignment[family['native']]:
                result.append((family, None))
            else:
                result.append((family, [next(c for c, v in zip(options, variables) if assignment[v])
                                       for options, variables in zip(p.candidates, family['selection'])]))
        return result

    def public_choices(self, assignment):
        return {group: next(choice for choice, variable in choices.items() if assignment[variable])
                for group, choices in self.groups.items()}
