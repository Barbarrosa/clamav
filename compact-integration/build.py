#!/usr/bin/env python3
"""Materialize exact upstream + checked patches; never edit the tracking checkout."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def checked_relative(path):
    p = PurePosixPath(path)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise ValueError('Unsafe integration path: ' + path)
    return p


def patch_images(source, patch, *, after=False):
    """Git apply permits offsets; Git blob identities prohibit that drift."""
    current = None
    diffs = 0
    preimages = 0
    for line in patch.read_text().splitlines():
        if line.startswith('diff --git '):
            match = re.fullmatch(r'diff --git a/(\S+) b/(\S+)', line)
            if not match or match[1] != match[2]:
                raise ValueError('Renames and quoted paths require an explicit adapter')
            current = checked_relative(match[1])
            diffs += 1
        elif line.startswith('index '):
            match = re.fullmatch(r'index ([0-9a-f]+)\.\.([0-9a-f]+)(?: \d+)?', line)
            if not match or current is None:
                raise ValueError('Malformed patch identity')
            path = source.joinpath(*current.parts)
            old = match[2] if after else match[1]
            preimages += 1
            if set(old) == {'0'}:
                if path.exists() or path.is_symlink():
                    raise ValueError('Patch expected an absent file: ' + str(current))
            else:
                if not path.is_file() or path.is_symlink():
                    raise ValueError('Patch preimage is not a regular file: ' + str(current))
                actual = subprocess.check_output(['git', 'hash-object', str(path)], text=True).strip()
                if not actual.startswith(old):
                    raise ValueError('Exact patch ' + ('postimage' if after else 'preimage') + ' changed: ' + str(current))
    if diffs == 0 or diffs != preimages:
        raise ValueError('Every changed path must have an exact Git blob preimage')


def patch_preimages(source, patch):
    patch_images(source, patch)


def materialize(destination, manifest, *, pristine=False):
    destination = destination.resolve()
    if destination.exists():
        raise ValueError('Output must not exist; use a fresh disposable source tree')
    checkout = ROOT.parent
    commit = manifest['upstream_commit']
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Upstream must be a pinned full Git SHA')
    run(['git', '-C', checkout, 'cat-file', '-e', commit + '^{commit}'])
    destination.mkdir(parents=True)
    proc = subprocess.Popen(['git', '-C', str(checkout), 'archive', commit], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode='r|') as archive:
            for member in archive:
                checked_relative(member.name)
                if member.issym() or member.islnk():
                    link = PurePosixPath(member.linkname)
                    if link.is_absolute() or '..' in link.parts:
                        raise ValueError('Unsafe archive link')
                if not (member.isfile() or member.isdir() or member.issym()):
                    raise ValueError('Unsupported source archive member')
                archive.extract(member, destination, set_attrs=True, numeric_owner=False)
        if proc.wait():
            raise RuntimeError('Git archive failed')
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.poll() is None:
            proc.kill(); proc.wait()
    run(['git', 'init', '--quiet', destination])
    if not pristine:
        for item in manifest['patches']:
            rel = checked_relative(item['file'])
            patch = ROOT.joinpath(*rel.parts)
            if not re.fullmatch('[0-9a-f]{64}', item['sha256']) or digest(patch) != item['sha256']:
                raise ValueError('Patch checksum is unqualified or changed: ' + str(rel))
            patch_preimages(destination, patch)
            run(['git', '-C', destination, 'apply', '--check', patch])
            run(['git', '-C', destination, 'apply', patch])
            patch_images(destination, patch, after=True)
        shutil.copytree(ROOT / 'native', destination / 'compact-adapter')
        with (destination / 'CMakeLists.txt').open('a') as f:
            f.write('\n# Generated integration build tree only.\nadd_subdirectory(compact-adapter)\n')
    (destination / 'compact-source.json').write_text(json.dumps({
        'upstream_commit': commit, 'integration_version': manifest['integration_version'],
        'patches': [] if pristine else manifest['patches'], 'variant': 'upstream' if pristine else 'optimized',
        'manifest_sha256': digest(ROOT / 'manifest.json')}, indent=2) + '\n')
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--pristine', action='store_true')
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--cmake-option', action='append', default=[])
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    source = materialize(args.output, manifest, pristine=args.pristine)
    if args.configure or args.build:
        build = (args.build_dir or source.with_name(source.name + '-build')).resolve()
        options = [] if args.pristine else ['-D' + k + '=' + v for k, v in manifest['default_options'].items()]
        options += ['-D' + v for v in args.cmake_option]
        run(['cmake', '-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
             '-DENABLE_MAN_PAGES=OFF', '-DENABLE_SYSTEMD=OFF', '-DCVD_CERTS_DIRECTORY=' + str(source / 'certs')]
             + options)
        if args.build:
            run(['cmake', '--build', build, '--parallel', str(args.jobs)])
        print(json.dumps({'source': str(source), 'build': str(build)}))


if __name__ == '__main__':
    main()
