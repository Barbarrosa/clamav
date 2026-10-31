#!/usr/bin/env python3
"""Run the five offline formulations serially, with tests and provenance.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

import pysat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def run_command(command, log, timeout=180):
    start = time.perf_counter()
    with log.open('w') as out:
        subprocess.run(command, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                       check=True, timeout=timeout)
    return {'command': command, 'wall_seconds': time.perf_counter() - start,
            'log': log.name, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-probe', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    runs = [run_command([sys.executable, '-m', 'unittest', 'discover', '-s', str(HERE),
                         '-p', 'test_*.py', '-v'], output / 'tests.log')]
    # Existing solver infrastructure is part of the evidence for the reduction.
    for script in ['test_joint_budget_cnf.py', 'test_joint_token_dictionary.py']:
        runs.append(run_command([sys.executable, str(HERE.parent / script)],
                                output / (script.removesuffix('.py') + '.log')))
    token_command = [sys.executable, str(HERE / 'tokens.py'), '--output', str(output)]
    if args.native_probe:
        token_command += ['--probe', str(args.native_probe.resolve())]
    runs.append(run_command(token_command, output / 'tokens.log'))
    for module, name in [('name_blocks', 'names'), ('transitions', 'transitions'),
                         ('candidate_tails', 'candidates'), ('scalar_blocks', 'scalars')]:
        command = [sys.executable, str(HERE / (module + '.py')), '--output', str(output / (name + '.json'))]
        runs.append(run_command(command, output / (name + '.log')))
    scripts = list(HERE.glob('*.py')) + [HERE.parent / 'joint_budget_cnf.py',
                                       HERE.parent / 'joint_token_dictionary.py',
                                       HERE.parent / 'probe_joint_dictionary.c']
    results = {name: hashlib.sha256((output / (name + '.json')).read_bytes()).hexdigest()
               for name in ['tokens', 'names', 'transitions', 'candidates', 'scalars']}
    summary = {
        'scope': 'five bounded offline memory-layout experiments; no scanner integration',
        'solver_executed': 'PySAT RC2 and Minisat22; linked Lean counting construction not executed',
        'source_base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'python': platform.python_version(), 'python_sat': pysat.__version__,
        'platform': platform.platform(), 'runs': runs,
        'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(scripts)},
        'result_sha256': results,
        'native_probe_sha256': hashlib.sha256(args.native_probe.read_bytes()).hexdigest()
                                if args.native_probe else None,
        'limitations': ['Fixtures are public literal/synthetic data, not official compiled databases.',
                        'Image and persistent decoded payload counts exclude process/allocator/solver peak.',
                        'Bounded <=3-CNF audits use small representative problems; larger runs use RC2.',
                        'No practical advantage of the linked algorithm or whole-engine memory saving is established.']}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'experiments_passed': 5, 'output': str(output)}, indent=2))


if __name__ == '__main__':
    main()
