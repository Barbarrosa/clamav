#!/usr/bin/env python3
"""Serial, randomized fresh-process memory measurements on a supplied database.

Uses the public-API engine_bench.c. Sample maxima are not worst-case bounds;
these short trials do not qualify performance or malware-detection equivalence.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import re
import statistics
import shutil
import subprocess


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='append', required=True, help='LABEL=BUILD_DIRECTORY')
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--seed', type=int, default=261027)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100000 or args.rounds < 1:
        parser.error('invalid iteration or round count')
    source = Path(__file__).resolve().parents[2]
    database, target, out = args.database.resolve(), args.input.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    builds, metadata, binaries = {}, {}, {}
    for item in args.build:
        label, separator, path = item.partition('=')
        if not separator or not re.fullmatch('[a-z0-9_-]+', label) or label in builds:
            parser.error('each build must have a unique simple LABEL=PATH')
        build = Path(path).resolve()
        builds[label] = build
        library = build / 'libclamav'
        binary = out / ('bench-' + label)
        subprocess.run(['cc', '-O2', str(source / 'tools/compact-memory/engine_bench.c'),
                        '-I' + str(source / 'libclamav'), '-I' + str(build),
                        '-L' + str(library), '-Wl,-rpath,' + str(library), '-lclamav',
                        '-o', str(binary)], check=True)
        binaries[label] = binary
        metadata[label] = {'build': str(build), 'library_sha256': sha((library / 'libclamav.so').resolve()),
                           'cmake_cache_sha256': sha(build / 'CMakeCache.txt'),
                           'binary_sha256': sha(binary),
                           'compiler_comment': (subprocess.check_output(
                               ['readelf', '-p', '.comment', str((library / 'libclamav.so').resolve())],
                               text=True) if shutil.which('readelf') else None)}
    env = os.environ.copy()
    # A caller's loader override must not silently select the wrong comparison library.
    env.pop('LD_LIBRARY_PATH', None)
    rng, raw, reference = random.Random(args.seed), [], None
    with (out / 'observations.jsonl').open('w') as log:
        for trial in range(args.rounds):
            order = list(builds)
            rng.shuffle(order)
            for label in order:
                command = [str(binaries[label]), str(database), str(target), str(args.iterations),
                           str(source / 'certs')]
                result = subprocess.run(command, env=env, capture_output=True, text=True, check=True)
                record = json.loads(result.stdout)
                identity = (record['signatures'], record['verdict'])
                if reference is None:
                    reference = identity
                if identity != reference:
                    raise RuntimeError('Signature count or verdict differs between runs')
                record = {'trial': trial, 'build': label, **record}
                raw.append(record)
                log.write(json.dumps(record) + '\n')
                log.flush()
                print(f'round {trial + 1}/{args.rounds}: {label}', flush=True)
    summary = {}
    for label in builds:
        summary[label] = {}
        for field in ('compiled_rss_kib', 'peak_rss_kib', 'load_seconds', 'compile_seconds', 'scan_seconds'):
            values = [r[field] for r in raw if r['build'] == label]
            summary[label][field] = {'mean': statistics.mean(values), 'median': statistics.median(values),
                                     'minimum': min(values), 'maximum': max(values)}
    files = sorted(p for p in database.iterdir() if p.suffix in ('.cvd', '.cld')) if database.is_dir() else [database]
    report = {'kind': 'fresh_process_memory_smoke_test',
              'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'limitations': 'Sample maxima are not worst-case bounds; short trials do not qualify performance.',
              'host': list(os.uname()),
              'seed': args.seed, 'rounds': args.rounds, 'iterations': args.iterations,
              'input': {'path': str(target), 'bytes': target.stat().st_size, 'sha256': sha(target)},
              'database': [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in files],
              'benchmark_source_sha256': sha(source / 'tools/compact-memory/engine_bench.c'),
              'builds': metadata, 'summary': summary, 'observations': raw}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
