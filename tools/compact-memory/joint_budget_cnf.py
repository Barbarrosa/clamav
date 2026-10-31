#!/usr/bin/env python3
"""Encode a weighted Boolean budget as clauses of width at most three.

This is an offline experiment utility, with no solver or scanner dependency.
``budget_cnf(hard, costs, budget)`` preserves the primary assignments satisfying
``hard`` and ``sum(weight * variable) <= budget``, existentially quantifying new
variables. Original clauses wider than three are split with fresh variables.

The result is equisatisfiable under each primary assignment. Its model count
must not be described as the number of database layouts: encoders, auxiliary
assignments and alternative descriptions can change that interpretation.
SPDX-License-Identifier: GPL-2.0-only
"""


def _integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


class _Circuit:
    def __init__(self, last_variable):
        self.last_variable = last_variable
        self.clauses = []

    def fresh(self):
        self.last_variable += 1
        return self.last_variable

    def clause(self, *literals):
        """Simplify constants only in generated circuit clauses."""
        result = []
        for literal in literals:
            if literal is True:
                return
            if literal is False:
                continue
            if -literal in result:
                return
            if literal not in result:
                result.append(literal)
        self.clauses.append(result)

    @staticmethod
    def negate(literal):
        return not literal if isinstance(literal, bool) else -literal

    def conjunction(self, left, right):
        if left is False or right is False:
            return False
        if left is True:
            return right
        if right is True or left == right:
            return left
        if left == -right:
            return False
        result = self.fresh()
        self.clause(-result, left)
        self.clause(-result, right)
        self.clause(result, -left, -right)
        return result

    def exclusive_or(self, left, right):
        if left is False:
            return right
        if right is False:
            return left
        if left is True:
            return self.negate(right)
        if right is True:
            return self.negate(left)
        if left == right:
            return False
        if left == -right:
            return True
        result = self.fresh()
        self.clause(left, right, -result)
        self.clause(-left, -right, -result)
        self.clause(left, -right, result)
        self.clause(-left, right, result)
        return result

    def disjunction(self, left, right):
        return self.negate(self.conjunction(self.negate(left), self.negate(right)))

    def width_three(self):
        """Split long disjunctions, retaining empty, unit and binary clauses."""
        result = []
        for clause in self.clauses:
            remaining = list(clause)
            while len(remaining) > 3:
                continuation = self.fresh()
                result.append(remaining[:2] + [continuation])
                remaining = [-continuation] + remaining[2:]
            result.append(remaining)
        return result


def budget_cnf(hard: list[list[int]], costs: list[tuple[int, int]],
               budget: int) -> list[list[int]]:
    """Return <=3-CNF encoding ``hard AND sum(weight*v) <= budget``.

    ``hard`` is a list of signed, nonzero integer-literal clauses. ``costs`` is
    a list of ``(positive_variable, nonnegative_integer_weight)`` pairs; repeated
    variables are combined. Zero weights are allowed. A negative budget is
    unsatisfiable. Inputs are not mutated, and all auxiliaries exceed every input
    variable, including zero-weight variables. Invalid inputs raise ValueError.

    A binary ripple adder uses O(n*log(sum(weights)+1)) gates. Overweight terms
    are first forced false; huge numeric weights therefore need no unary arrays.
    A constant comparator excludes every first bit that would exceed the budget.
    """
    if not _integer(budget):
        raise ValueError('budget must be an integer')
    last_variable = 0
    original = []
    for clause in hard:
        saved = []
        for literal in clause:
            if not _integer(literal) or literal == 0:
                raise ValueError('hard clauses require nonzero integer literals')
            saved.append(literal)
            last_variable = max(last_variable, abs(literal))
        original.append(saved)
    weights = {}
    for variable, weight in costs:
        if (not _integer(variable) or variable <= 0 or
                not _integer(weight) or weight < 0):
            raise ValueError('costs require positive variables and nonnegative weights')
        last_variable = max(last_variable, variable)
        weights[variable] = weights.get(variable, 0) + weight
    circuit = _Circuit(last_variable)
    circuit.clauses.extend(original)
    if budget < 0:
        circuit.clauses.append([])
        return circuit.width_three()

    active = []
    for variable, weight in sorted(weights.items()):
        if weight > budget:
            circuit.clauses.append([-variable])
        elif weight:
            active.append((variable, weight))
    total = sum(weight for _, weight in active)
    if total <= budget:
        return circuit.width_three()

    width = total.bit_length()
    accumulator = [False] * width
    for variable, weight in active:
        carry = False
        summed = []
        for bit, left in enumerate(accumulator):
            right = variable if (weight >> bit) & 1 else False
            pair = circuit.exclusive_or(left, right)
            summed.append(circuit.exclusive_or(pair, carry))
            if bit + 1 < width:
                carry = circuit.disjunction(circuit.conjunction(left, right),
                                            circuit.conjunction(pair, carry))
        accumulator = summed

    # If budget bit i is zero, setting sum bit i requires some higher one bit
    # of the budget to have become zero in the sum. Higher zero-bit violations
    # are excluded by their own clauses. This is the lexicographic comparator.
    higher_ones = []
    for bit in reversed(range(width)):
        if (budget >> bit) & 1:
            higher_ones.append(circuit.negate(accumulator[bit]))
        else:
            circuit.clause(circuit.negate(accumulator[bit]), *higher_ones)
    return circuit.width_three()
