#!/usr/bin/env python3
"""Reproducible Linux whole-engine comparison; synthetic data, not a release gate."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_revision(source_tree):
    # Release/source archives can be built without a Git checkout.
    try:
        result = subprocess.run(['git', '-C', source_tree, 'rev-parse', 'HEAD'],
                                text=True, capture_output=True)
    except FileNotFoundError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-build', type=Path, required=True)
    parser.add_argument('--baseline-revision', help='Revision of a frozen reference library')
    parser.add_argument('--baseline-slots', type=int, choices=(4, 64), default=64,
                        help='Four for the earlier compact fork; 64 for upstream')
    parser.add_argument('--fork-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rows', type=int, default=20000)
    parser.add_argument('--rounds', type=int, default=30)
    parser.add_argument('--iterations', type=int, default=5)
    parser.add_argument('--input-mib', type=int, default=4)
    parser.add_argument('--seed', type=int, default=260526)
    args = parser.parse_args()
    if min(args.rows, args.rounds, args.iterations, args.input_mib) < 1:
        parser.error('counts must be positive')
    if args.rounds < 2:
        parser.error('at least two paired rounds are required')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parents[2]
    rng = random.Random(args.seed)
    db = out / 'synthetic.ldb'
    with db.open('w') as stream:
        for row in range(args.rows):
            parts = [hashlib.sha256(f'compact/{row}/{part}'.encode()).digest()[:8].hex()
                     for part in range(4)]
            stream.write(f'CompactBench.{row};Target:0;0&1&2&3;' + ';'.join(parts) + '\n')
    files = {
        'small_clean': out / 'small-clean.bin',
        'large_clean': out / 'large-clean.bin',
        'detected': out / 'detected.bin',
    }
    files['small_clean'].write_bytes(rng.randbytes(4096))
    files['large_clean'].write_bytes(rng.randbytes(args.input_mib * 1024 * 1024))
    # Harmless marker bytes. Detection comes only from the generated rules above.
    files['detected'].write_bytes(b''.join(hashlib.sha256(f'compact/0/{part}'.encode()).digest()[:8]
                                         for part in range(4)) + rng.randbytes(4096))
    builds = {'baseline': args.baseline_build.resolve(), 'fork': args.fork_build.resolve()}
    executables = {}
    build_metadata = {}
    for label, build in builds.items():
        binary = out / ('bench-' + label)
        library = build / 'libclamav'
        subprocess.run(['cc', '-O2', str(source / 'tools/compact-memory/engine_bench.c'),
                        '-I' + str(source / 'libclamav'), '-I' + str(build),
                        '-L' + str(library), '-Wl,-rpath,' + str(library), '-lclamav',
                        '-o', str(binary)], check=True)
        executables[label] = binary
        cache = build / 'CMakeCache.txt'
        library_file = (library / 'libclamav.so').resolve()
        relevant_keys = ('CMAKE_BUILD_TYPE', 'CMAKE_C_COMPILER', 'CMAKE_C_FLAGS',
                         'CMAKE_CXX_FLAGS', 'ENABLE_', 'DISABLE_', 'BYTECODE_RUNTIME')
        configuration = {line.split(':', 1)[0]: line.split('=', 1)[1]
                         for line in cache.read_text().splitlines()
                         if line.startswith(relevant_keys) and ':' in line and '=' in line}
        source_tree = next(line.split('=', 1)[1] for line in cache.read_text().splitlines()
                           if line.startswith('CMAKE_HOME_DIRECTORY:'))
        build_metadata[label] = {'path': str(build), 'cache_sha256': sha(cache),
                                 'source_revision': (args.baseline_revision if label == 'baseline' and args.baseline_revision
                                                     else source_revision(source_tree)),
                                 'executable_sha256': sha(binary),
                                 'library_sha256': sha(library_file),
                                 'configuration': configuration}
    raw, summary = [], {}
    for case, file in files.items():
        paired = []
        # Randomize order within each pair, preserving paired observations.
        for trial in range(args.rounds):
            order = list(builds)
            rng.shuffle(order)
            observations = {}
            for label in order:
                command = [str(executables[label]), str(db), str(file), str(args.iterations),
                           str(source / 'certs')]
                result = subprocess.run(command, text=True, capture_output=True)
                if result.returncode:
                    raise RuntimeError(f'{label} {case} exited {result.returncode}: {result.stderr}')
                observation = json.loads(result.stdout)
                expected = 1 if case == 'detected' else 0
                if observation['verdict'] != expected or observation['signatures'] != args.rows:
                    raise RuntimeError(f'unexpected verdict/signature count: {case} {label}')
                observations[label] = observation
                raw.append({'case': case, 'trial': trial, 'build': label, **observation})
            paired.append(observations)
            print(f'{case}: pair {trial + 1}/{args.rounds}', flush=True)
        stats = {}
        for field in ['load_seconds', 'compile_seconds', 'scan_seconds',
                      'compiled_rss_kib', 'peak_rss_kib']:
            before = [p['baseline'][field] for p in paired]
            after = [p['fork'][field] for p in paired]
            # A bootstrap interval on paired log ratios, not on unpaired medians.
            ratios = [math.log(b / a) for a, b in zip(before, after) if a > 0 and b > 0]
            resampled = sorted(math.exp(statistics.mean(rng.choices(ratios, k=len(ratios))))
                               for _ in range(5000))
            stats[field] = {'baseline_median': statistics.median(before),
                            'fork_median': statistics.median(after),
                            'paired_geomean_ratio': math.exp(statistics.mean(ratios)),
                            'paired_bootstrap_95pct': [resampled[125], resampled[4874]]}
        summary[case] = stats
    report = {'kind': 'synthetic_same_host_comparison', 'seed': args.seed,
              'host': {'uname': list(os.uname()),
                       'cpu_model': next((line.split(':', 1)[1].strip()
                                          for line in Path('/proc/cpuinfo').read_text().splitlines()
                                          if line.startswith('model name')), 'unknown'),
                       'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]},
              'benchmark_source_sha256': sha(source / 'tools/compact-memory/engine_bench.c'),
              'rows': args.rows, 'subsignatures_per_row': 4, 'rounds': args.rounds,
              'iterations_per_process': args.iterations,
              'state_payload_bytes': {'baseline': args.rows * args.baseline_slots * 12,
                                      'compact': args.rows * 4 * 12},
              'database_sha256': sha(db),
              'input_sha256': {key: sha(value) for key, value in files.items()},
              'builds': build_metadata, 'summary': summary, 'raw': raw,
              'limitations': ['Generated logical signatures are not a production database.',
                              'Cache disabled in both builds; all-match and all parsers enabled.',
                              'RSS is per-process Linux accounting, not whole-cgroup/reload accounting.',
                              'Intervals describe this experiment, not all-input performance guarantees.']}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
