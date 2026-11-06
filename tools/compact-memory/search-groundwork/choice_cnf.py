"""Count-faithful, width-at-most-three Boolean choice constraints.

Each auxiliary variable is the output of a full-equivalence AND or XOR gate
whose inputs already exist. Consequently every complete assignment of declared
primary variables has exactly one auxiliary extension before hard constraints,
and either one or zero satisfying extensions afterwards. This is stronger than
equisatisfiability: ordinary model counts concern primary Boolean configurations
without multiplicity from arithmetic or clause-splitting helpers.

The caller must still declare what a configuration means. Equivalent physical
layouts represented by different primary choices remain different configurations.
No scanner semantics, hardware timing, or algorithm implementation is proved here.
This module has no solver dependency and does not execute the linked algorithm.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def _integer(value):
    return type(value) is int


class Formula:
    """A deterministic Boolean circuit with hard constraints and unique helpers.

    Literals are nonzero signed integer variable IDs or Boolean constants.
    All IDs must have been allocated by this formula. Public collections are
    copies, so callers cannot accidentally add unconstrained helper variables.
    New primary variables may be interleaved with gates; IDs are never renumbered.
    """

    def __init__(self):
        self._nv = 0
        self._primary = {}
        self._clauses = []
        self._gates = []
        self._gate_cache = {}

    @property
    def nv(self):
        return self._nv

    @property
    def primary(self):
        return dict(self._primary)

    @property
    def clauses(self):
        return [list(clause) for clause in self._clauses]

    @property
    def gates(self):
        """Topological tuples ``(operation, output, left, right)``."""
        return tuple(self._gates)

    def _literal(self, value):
        if type(value) is bool:
            return value
        if not _integer(value) or value == 0 or abs(value) > self._nv:
            raise ValueError('literal must be a Boolean constant or an existing nonzero variable ID')
        return value

    def new_primary(self, name):
        if not isinstance(name, str) or not name or name in self._primary:
            raise ValueError('primary variable names must be nonempty unique strings')
        self._nv += 1
        self._primary[name] = self._nv
        return self._nv

    def not_(self, literal):
        literal = self._literal(literal)
        return not literal if type(literal) is bool else -literal

    def _emit(self, *literals):
        clause = []
        for literal in literals:
            literal = self._literal(literal)
            if literal is True:
                return
            if literal is False:
                continue
            if -literal in clause:
                return
            if literal not in clause:
                clause.append(literal)
        if len(clause) > 3:
            raise AssertionError('internal clause exceeds width three')
        self._clauses.append(tuple(clause))

    def _gate(self, operation, left, right):
        # Inputs are nonconstant by this point. Commutative canonicalization
        # shares gates and makes output reproducible for the same call sequence.
        left, right = sorted((left, right))
        key = (operation, left, right)
        if key in self._gate_cache:
            return self._gate_cache[key]
        self._nv += 1
        output = self._nv
        self._gate_cache[key] = output
        self._gates.append((operation, output, left, right))
        if operation == 'and':
            self._emit(-output, left)
            self._emit(-output, right)
            self._emit(output, -left, -right)
        elif operation == 'xor':
            self._emit(left, right, -output)
            self._emit(-left, -right, -output)
            self._emit(left, -right, output)
            self._emit(-left, right, output)
        else:
            raise AssertionError('unknown deterministic gate')
        return output

    def and_(self, left, right):
        left, right = self._literal(left), self._literal(right)
        if left is False or right is False:
            return False
        if left is True:
            return right
        if right is True:
            return left
        if left == right:
            return left
        if left == -right:
            return False
        return self._gate('and', left, right)

    def or_(self, left, right):
        return self.not_(self.and_(self.not_(left), self.not_(right)))

    def xor(self, left, right):
        left, right = self._literal(left), self._literal(right)
        if left is False:
            return right
        if right is False:
            return left
        if left is True:
            return self.not_(right)
        if right is True:
            return self.not_(left)
        if left == right:
            return False
        if left == -right:
            return True
        return self._gate('xor', left, right)

    def all_(self, literals):
        result = True
        for literal in literals:
            result = self.and_(result, literal)
        return result

    def any_(self, literals):
        result = False
        for literal in literals:
            result = self.or_(result, literal)
        return result

    def force(self, literal):
        self._emit(literal)

    def clause(self, *literals):
        """Require a disjunction, using uniquely determined OR gates if long."""
        literals = [self._literal(literal) for literal in literals]
        if len(literals) <= 3:
            self._emit(*literals)
        else:
            self.force(self.any_(literals))

    def imply(self, antecedent, consequent):
        self._emit(self.not_(antecedent), consequent)

    def equivalent(self, left, right):
        self.imply(left, right)
        self.imply(right, left)

    def exactly_one(self, literals):
        """Require exactly one true occurrence, with a deterministic prefix."""
        prefix = False
        for literal in literals:
            literal = self._literal(literal)
            self.force(self.not_(self.and_(prefix, literal)))
            prefix = self.or_(prefix, literal)
        self.force(prefix)

    def weighted_le(self, terms, limit):
        """Return the exact predicate ``sum(weight * truth(lit)) <= limit``.

        Coefficients are nonnegative integers. Signed literals, constants and
        repeated terms are accepted. Binary arithmetic needs logarithmic width
        in the total weight, rather than unary arrays proportional to a budget.
        Oversized terms are handled as exact false-required conditions without
        expanding the arithmetic to their potentially huge numeric widths.
        """
        if not _integer(limit):
            raise ValueError('weighted limit must be an integer')
        weights = {}
        constant = 0
        for term in terms:
            try:
                literal, weight = term
            except (TypeError, ValueError) as exc:
                raise ValueError('weighted terms must be literal/weight pairs') from exc
            literal = self._literal(literal)
            if not _integer(weight) or weight < 0:
                raise ValueError('weights must be nonnegative integers')
            if literal is True:
                constant += weight
            elif literal is not False and weight:
                weights[literal] = weights.get(literal, 0) + weight

        # a*x + b*not(x) = min(a,b) + abs(a-b)*the-more-expensive-literal.
        normalized = []
        for variable in sorted({abs(literal) for literal in weights}):
            positive, negative = weights.get(variable, 0), weights.get(-variable, 0)
            constant += min(positive, negative)
            if positive != negative:
                normalized.append((variable if positive > negative else -variable,
                                   abs(positive - negative)))
        remaining = limit - constant
        if remaining < 0:
            return False
        oversized = [self.not_(literal) for literal, weight in normalized if weight > remaining]
        active = [(literal, weight) for literal, weight in normalized if weight <= remaining]
        total = sum(weight for _, weight in active)
        if total <= remaining:
            return self.all_(oversized)

        width = total.bit_length()
        accumulator = [False] * width
        for literal, weight in active:
            carry = False
            output = []
            for bit, left in enumerate(accumulator):
                right = literal if (weight >> bit) & 1 else False
                pair = self.xor(left, right)
                output.append(self.xor(pair, carry))
                if bit + 1 < width:
                    carry = self.or_(self.and_(left, right), self.and_(pair, carry))
            accumulator = output

        # Process bits low to high: each higher comparison overrides lower
        # bits when unequal. Full gate equivalences determine every helper.
        within = True
        for bit, value in enumerate(accumulator):
            within = (self.or_(self.not_(value), within) if (remaining >> bit) & 1
                      else self.and_(self.not_(value), within))
        return self.and_(self.all_(oversized), within)

    def at_most_weighted(self, terms, limit, condition=True):
        """Enforce a weighted limit, optionally only when ``condition`` holds."""
        condition = self._literal(condition)
        predicate = self.weighted_le(terms, limit)
        self.imply(condition, predicate)
        return predicate

    @staticmethod
    def _value(literal, assignment):
        if type(literal) is bool:
            return literal
        return assignment[abs(literal)] == (literal > 0)

    def extend(self, primary_values):
        """Evaluate the unique extension; return None if a hard constraint fails.

        This is a circuit evaluator, not a SAT solver or counting algorithm.
        The mapping must contain every primary name exactly once, with Boolean
        values. A complete returned assignment can be checked against DIMACS.
        """
        if (not isinstance(primary_values, dict) or set(primary_values) != set(self._primary)
                or any(type(value) is not bool for value in primary_values.values())):
            raise ValueError('supply exactly all primary names with Boolean values')
        assignment = {variable: primary_values[name] for name, variable in self._primary.items()}
        for operation, output, left, right in self._gates:
            a, b = self._value(left, assignment), self._value(right, assignment)
            assignment[output] = (a and b) if operation == 'and' else (a != b)
        if any(not any(self._value(literal, assignment) for literal in clause)
               for clause in self._clauses):
            return None
        return assignment

    def dimacs(self):
        return '\n'.join([f'p cnf {self._nv} {len(self._clauses)}'] +
                         [' '.join(map(str, clause)) + (' ' if clause else '') + '0'
                          for clause in self._clauses]) + '\n'

    def to_file(self, path):
        Path(path).write_text(self.dimacs())

    def digest(self):
        return hashlib.sha256(self.dimacs().encode('ascii')).hexdigest()

    def mapping(self):
        return {'variables': self._nv, 'primary': self.primary,
                'auxiliary': [gate[1] for gate in self._gates],
                'clauses': len(self._clauses),
                'maximum_clause_width': max(map(len, self._clauses), default=0),
                'counting_unit': 'complete assignment of declared primary Boolean variables',
                'auxiliary_extension': 'unique by topological full-equivalence gates'}
