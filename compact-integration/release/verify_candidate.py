#!/usr/bin/env python3
"""Validate exact qualified CI transport before protected promotion.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import time


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('Unsafe candidate member')
    return path


def verify(archive, expected, destination, repository, commit, channel, version, tag):
    if not re.fullmatch('[0-9a-f]{64}', expected) or sha256(archive) != expected:
        raise ValueError('Candidate archive digest mismatch')
    destination = Path(destination)
    if destination.exists():
        raise ValueError('Promotion destination must be new')
    destination.mkdir(parents=True)
    with tarfile.open(archive, 'r:gz') as tar:
        seen, total = set(), 0
        for member in tar:
            path = relative(member.name)
            if path.parts[0] != 'candidate' or path in seen:
                raise ValueError('Unexpected or duplicate candidate member')
            seen.add(path)
            if len(seen) > 4096 or member.size < 0:
                raise ValueError('Invalid candidate inventory')
            if not (member.isfile() or member.isdir()):
                raise ValueError('Candidate links/devices are forbidden')
            total += member.size
            if total > 8 * 1024 ** 3:
                raise ValueError('Candidate exceeds transport budget')
            tar.extract(member, destination, set_attrs=True, numeric_owner=False)
    root = destination / 'candidate'
    index = json.loads((root / 'bundle-index.json').read_text())
    expected_paths = set()
    for item in index:
        path = relative(item['path'])
        if path in expected_paths:
            raise ValueError('Duplicate indexed path')
        expected_paths.add(path)
        file = root.joinpath(*path.parts)
        if not file.is_file() or file.stat().st_size != item['size'] or sha256(file) != item['sha256']:
            raise ValueError('Candidate content mismatch: ' + str(path))
    actual_paths = {PurePosixPath(p.relative_to(root).as_posix())
                    for p in root.rglob('*') if p.is_file()}
    if actual_paths != expected_paths | {PurePosixPath('bundle-index.json')}:
        raise ValueError('Unindexed promotion content')
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('protocol') != 1 or type(manifest.get('expires_at')) is not int or manifest['expires_at'] <= time.time():
        raise ValueError('Expired or unsupported release manifest')
    if any(manifest.get(k) != v for k, v in {
        'repository': repository, 'integration_sha': commit, 'channel': channel,
        'version': version, 'tag': tag}.items()):
        raise ValueError('Candidate identity differs from selected qualified run')
    report = json.loads((root / 'qualification.json').read_text())
    if report.get('passed') is not True or report.get('integration_sha') != commit:
        raise ValueError('Qualification is absent or for another commit')
    if channel == 'stable' and report.get('stable_release_qualified') is not True:
        raise ValueError('Stable release gates remain incomplete')
    provenance = json.loads((root / 'provenance.json').read_text())
    if provenance.get('source_complete') is not True:
        raise ValueError('Corresponding source collection is incomplete')
    return root


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'destination'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('sha256', 'repository', 'commit', 'channel', 'version', 'tag'):
        p.add_argument('--' + name, required=True)
    a = p.parse_args()
    print(verify(a.archive, a.sha256, a.destination, a.repository,
                 a.commit, a.channel, a.version, a.tag))
