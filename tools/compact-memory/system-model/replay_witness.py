#!/usr/bin/env python3
"""Independently turn a private solver assignment back into native GET values.

No captured values or pointer arguments are printed. This checks the actual
assignment, not just the byte count reported by an optimizer.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
from pysat.formula import WCNF

from capture import load_capture
from field_synthesis import Candidate, FieldStore, build_image


def complete_assignment(assignment, required_variables):
    """Require explicit source variables; allow extended CNF auxiliaries."""
    if not isinstance(assignment, list) or any(type(v) is not int or v == 0 for v in assignment):
        raise ValueError('assignment must contain nonzero integer literals')
    values = {abs(v): v > 0 for v in assignment}
    if len(values) != len(assignment):
        raise ValueError('duplicate or contradictory assignment variable')
    if any(v not in values for v in range(1, required_variables + 1)):
        raise ValueError('assignment omits an original system variable')
    return values


def replay(capture_path, plan_path, assignment_path):
    assignment = json.loads(Path(assignment_path).read_text())
    formula = WCNF(from_file=str(Path(plan_path) / 'system.wcnf'))
    values = complete_assignment(assignment, formula.nv)
    positive = {v for v in assignment if v > 0}
    if any(not any(values[abs(v)] == (v > 0) for v in clause)
           for clause in formula.hard):
        raise ValueError('assignment does not satisfy system constraints')
    objective = sum(weight for clause, weight in zip(formula.soft, formula.wght)
                    if not any(values[abs(v)] == (v > 0) for v in clause))
    capture = load_capture(capture_path)
    families = {f.name: f for f in capture.families}
    mapping = json.loads((Path(plan_path) / 'system.candidates.json').read_text())
    results, physical_bytes = [], 0
    for group in mapping:
        native, encoded = group['native_variable'] in positive, group['synthesized_variable'] in positive
        if native == encoded:
            raise ValueError('exactly one family provider must be selected')
        family = families[group['family']]
        if native:
            physical_bytes += family.native_bytes
            results.append({'family': family.name, 'provider': 'native', 'rows': family.rows})
            continue
        names, selected = [], []
        for field in group['fields']:
            choices = [option for option in field['options'] if option['variable'] in positive]
            if len(choices) != 1:
                raise ValueError('exactly one field program must be selected')
            names.append(field['name'])
            selected.append(Candidate(**choices[0]['program']))
        problem = SimpleNamespace(names=names, columns=[np.asarray(family.columns[n], dtype=np.uint64)
                                                       for n in names], nrows=family.rows)
        image = build_image(problem, selected)
        locator_bytes = (Path(plan_path).parent / (family.name + '.locator')).stat().st_size
        physical_bytes += len(image) + locator_bytes
        store = FieldStore(image, names)
        result = family.verify(SimpleNamespace(reconstruct=store.reconstruct, get=store.get))
        results.append({'family': family.name, 'provider': 'synthesized', 'image_bytes': len(image),
                        'identity_locator_bytes': locator_bytes,
                        'image_sha256': hashlib.sha256(image).hexdigest(), **result})
    if physical_bytes != objective:
        raise ValueError('rebuilt provider and locator bytes differ from weighted objective')
    return {'every_selected_provider_verified': True, 'variable_byte_objective': objective,
            'physical_provider_bytes_verified': physical_bytes,
            'assignment_sha256': hashlib.sha256(Path(assignment_path).read_bytes()).hexdigest(),
            'families': results,
            'scope': 'complete captured native field/identity replay; not a scanner deployment test'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--assignment', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = replay(args.capture, args.plan, args.assignment)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
