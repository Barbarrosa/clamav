#!/usr/bin/env python3
"""Name fork builds with the qualified upstream engine version plus build metadata.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess


NUMBER = r'(?:0|[1-9][0-9]*)'
PRERELEASE_ID = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER = (NUMBER + r'\.' + NUMBER + r'\.' + NUMBER
          + r'(?:-' + PRERELEASE_ID + r'(?:\.' + PRERELEASE_ID + r')*)?'
          + r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?')
LIBRARY_DIRECTORIES = ('libclamav', 'libfreshclam', 'libclamunrar_iface',
                       'libclamunrar', 'libclammspack')


def valid_semver(version):
    return isinstance(version, str) and re.fullmatch(SEMVER, version) is not None


def native_tag(version):
    """Return the canonical fork tag, refusing unqualified or ambiguous versions."""
    if not valid_semver(version):
        raise ValueError('Release version is not a canonical semantic version')
    suffix = re.search(r'\+(?:[0-9A-Za-z-]+\.)*compact\.([1-9][0-9]*)$', version)
    if suffix is None or int(suffix[1]) > 2**63 - 1:
        raise ValueError('Release version must end with a canonical compact fork revision')
    return 'clamav-' + version


def release_identity(upstream_version, revision, core_version=None):
    if not valid_semver(upstream_version):
        raise ValueError('Upstream engine version is not a canonical semantic version')
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise ValueError('Fork revision must be a positive signed-64-bit release sequence')
    upstream_core = re.match(NUMBER + r'\.' + NUMBER + r'\.' + NUMBER, upstream_version)[0]
    if core_version is not None and (not isinstance(core_version, str)
            or not re.fullmatch(NUMBER + r'\.' + NUMBER + r'\.' + NUMBER, core_version)
            or upstream_core != core_version):
        raise ValueError('Built engine version differs from its generated upstream version header')
    version = upstream_version + ('.' if '+' in upstream_version else '+') + 'compact.' + str(revision)
    return {'upstream_version': upstream_version, 'fork_revision': revision,
            'version': version, 'tag': native_tag(version)}


version_identity = release_identity


def built_identity(build, revision):
    build = Path(build).resolve()
    header = (build / 'clamav-version.h').read_text()
    versions = re.findall(r'^\s*#\s*define\s+CLAMAV_VERSION\s+"([^"\r\n]+)"\s*$', header, re.M)
    if len(versions) != 1:
        raise ValueError('A unique generated CLAMAV_VERSION is required')
    scanner = build / 'compact-adapter' / 'compact-scan'
    if not scanner.is_file():
        raise ValueError('The matching compiled compact-scan is required')
    environment = os.environ.copy()
    for name in ('LD_PRELOAD', 'LD_AUDIT'):
        environment.pop(name, None)
    environment['LD_LIBRARY_PATH'] = ':'.join(str(build / directory) for directory in LIBRARY_DIRECTORIES)
    environment['COMPACT_PARENT_PID'] = str(os.getpid())
    result = json.loads(subprocess.check_output([str(scanner), 'doctor'], text=True,
                                               env=environment, timeout=30))
    if (not isinstance(result, dict) or result.get('protocol') != 1
            or result.get('status') != 'ready' or result.get('completed') is not True):
        raise ValueError('The compiled engine did not return a complete identity')
    return release_identity(result.get('engine_version'), revision, versions[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--revision', type=int, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        identity = built_identity(args.build, args.revision)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    raw = json.dumps(identity, sort_keys=True, indent=2) + '\n'
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(raw)
    print(raw, end='')


if __name__ == '__main__':
    main()
