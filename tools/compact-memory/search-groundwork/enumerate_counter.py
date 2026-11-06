#!/usr/bin/env python3
"""Conventional bounded Minisat enumeration backend for small count fixtures.

This implements run_counter.py's hash-bound JSON protocol. It is not the linked
counting construction and supplies no independently checkable count certificate.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
from canonical_input import parse_dimacs
from choice_cnf import Formula
from run_search import enumerate_bounded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--limit', type=int, default=10000)
    parser.add_argument('--seconds', type=float, default=10)
    args = parser.parse_args()
    if args.limit < 0 or args.seconds <= 0:
        parser.error('invalid enumeration limits')
    raw = args.input.read_bytes()
    parsed = parse_dimacs(raw.decode('ascii'))
    # Reuse bounded enumeration with a minimal declared formula interface;
    # canonical literal codes use zero-based variables and sign bits.
    class Query:
        nv = parsed.num_variables
        clauses = [[(value // 2 + 1) * (1 if value % 2 else -1) for value in clause]
                   for clause in parsed.clauses]
    result = enumerate_bounded(Query(), args.limit, args.seconds)
    output = {'status': 'exact' if result['complete'] else 'unknown',
              'input_sha256': hashlib.sha256(raw).hexdigest()}
    if result['complete']:
        output['count'] = str(result['configurations_counted'])
    print(json.dumps(output))


if __name__ == '__main__':
    main()
