#!/usr/bin/env python3
"""Scan with all databases (default), or opt in with --database-profile=pdf-jpeg-png-pe-exclusions.

The restricted profile always uses all-match and preserves evidence holds.
Exit 0 means the scan process completed; read each JSON outcome for its verdict.
This flag belongs to this adapter, not to upstream clamscan or clamd.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import os
from pathlib import Path
from select_db import sha, validate_generation

PROFILES = ('full', 'pdf-jpeg-png-pe-exclusions')


def command(*, probe, lib, certs, files, generation=None, database=None,
            database_profile='full', allmatch=False, broad=False,
            repetitions=1, reload_overlap=False):
    """Build a validated command. No full-engine validation runs in this process.

    Generation preparation, including its full-load test, is a separate job.
    exec in main replaces Python so no idle adapter process survives the load.
    """
    if database_profile not in PROFILES:
        raise ValueError('unknown database profile')
    if (generation is None) == (database is None):
        raise ValueError('supply exactly one of generation or database')
    restricted = database_profile == 'pdf-jpeg-png-pe-exclusions'
    if restricted and generation is None:
        raise ValueError('pdf-jpeg-png-pe-exclusions requires a verified --generation')
    if restricted and broad:
        raise ValueError('pdf-jpeg-png-pe-exclusions only accepts the PDF/JPEG/PNG root profile')
    if not 1 <= repetitions <= 10000:
        raise ValueError('repetitions must be between 1 and 10000')
    if generation is not None:
        generation = Path(generation).resolve()
        manifest = validate_generation(generation, lib)
        if manifest['full_load_validation'].get('probe_sha256') != sha(probe):
            raise ValueError('scanner probe changed; regenerate the generation')
        database = generation / 'databases'
    skip = str(generation / 'skip.tsv') if restricted else '-'
    return [str(Path(probe).resolve()), str(Path(database).resolve()),
            str(Path(certs).resolve()), skip, str(Path(files).resolve()),
            str(repetitions), str(int(broad)), '0', str(int(reload_overlap)),
            'all' if restricted or allmatch else 'first']


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('probe', 'lib', 'certs', 'files'):
        p.add_argument('--' + key, type=Path, required=True)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--generation', type=Path, help='prepared signed-input generation')
    source.add_argument('--database', type=Path, help='original full database directory')
    p.add_argument('--database-profile', choices=PROFILES, default='full',
                   help='full (default) loads all enabled rules; pdf-jpeg-png-pe-exclusions accepts PDF/JPEG/PNG roots, omits eligible PE-only groups and reports all matches')
    p.add_argument('--allmatch', action='store_true', help='all matches in full mode (automatic in pdf-jpeg-png-pe-exclusions mode)')
    p.add_argument('--broad', action='store_true', help='broader root policy, full mode only')
    p.add_argument('--repetitions', type=int, default=1)
    p.add_argument('--reload-overlap', action='store_true', help='measure replacement construction while the old engine remains loaded')
    return p


def main():
    p = parser()
    try:
        cmd = command(**vars(p.parse_args()))
    except (ValueError, OSError, KeyError) as exc:
        p.error(str(exc))
    os.execv(cmd[0], cmd)


if __name__ == '__main__':
    main()
