#!/usr/bin/env python3
"""Prepare an unsigned, reviewable native release candidate. Never publishes.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
from urllib.parse import quote

from collect_dependencies import collect, digest
from versioning import SEMVER, built_identity

PLATFORM = 'linux-x86_64-glibc2.36'
IGNORED = {'.git', '.pytest_cache', '__pycache__', 'target', 'node_modules'}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def archive(path, roots, epoch=0):
    with Path(path).open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for directory, prefix in roots:
                directory = Path(directory).resolve()
                for item in sorted(directory.rglob('*')):
                    rel = item.relative_to(directory)
                    if any(part in IGNORED for part in rel.parts) or item.suffix in {'.pyc', '.log'}:
                        continue
                    if item.is_symlink() and not item.resolve().is_relative_to(directory):
                        raise ValueError('Source symlink leaves distribution: ' + str(rel))
                    info = tar.gettarinfo(str(item), str(Path(prefix) / rel))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = epoch
                    if info.isfile():
                        with item.open('rb') as stream:
                            tar.addfile(info, stream)
                    else:
                        tar.addfile(info)


def find_one(build, filename):
    found = sorted({p.resolve() for p in Path(build).rglob(filename) if p.is_file()})
    if len(found) != 1:
        raise ValueError(f'Expected one {filename}; found {len(found)}')
    return found[0]


def copy_file(source, payload, relative, executable=False, strip=False):
    dest = payload / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    with dest.open('rb') as stream:
        is_elf = stream.read(4) == b'\x7fELF'
    if strip and is_elf:
        subprocess.run(['strip', '--strip-unneeded', str(dest)], check=True)
    os.chmod(dest, 0o755 if executable else 0o644)
    return dest


def write_launcher(payload, executable):
    launcher = payload / 'bin' / executable
    launcher.parent.mkdir(exist_ok=True)
    launcher.write_text('#!/bin/sh\nset -eu\n'
                        'bundle=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
                        'export LD_LIBRARY_PATH="$bundle/lib"\n'
                        'export CURL_CA_BUNDLE="$bundle/lib/tls-ca-bundle.crt"\n'
                        f'exec "$bundle/lib/{executable}.real" "$@"\n')
    launcher.chmod(0o755)


def copy_tls_ca_bundle(payload):
    # Use only public roots shipped by the pinned Debian package. The generated
    # system bundle may also contain private local/proxy roots from the builder.
    files = subprocess.check_output(['dpkg-query', '-L', 'ca-certificates'], text=True).splitlines()
    certificates = sorted(Path(p) for p in files
        if Path(p).parent == Path('/usr/share/ca-certificates/mozilla') and p.endswith('.crt'))
    if not certificates:
        raise ValueError('Pinned Debian TLS root certificates are missing')
    bundle = payload / 'lib/tls-ca-bundle.crt'
    bundle.parent.mkdir(parents=True, exist_ok=True)
    with bundle.open('wb') as stream:
        for certificate in certificates:
            data = certificate.read_bytes().strip()
            if (not data.startswith(b'-----BEGIN CERTIFICATE-----')
                    or not data.endswith(b'-----END CERTIFICATE-----')
                    or data.count(b'-----BEGIN CERTIFICATE-----') != 1):
                raise ValueError('Unexpected packaged TLS root: ' + str(certificate))
            stream.write(data + b'\n')
    bundle.chmod(0o644)
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'output', 'qualification', 'changelog'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('upstream-sha', 'integration-sha', 'version', 'repository'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--expires-at', type=int, required=True)
    parser.add_argument('--channel', choices=('preview', 'stable'), default='preview')
    parser.add_argument('--dependency-sources', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(SEMVER, args.version):
        parser.error('Version must be an immutable semantic version')
    if args.sequence < 1 or args.expires_at <= int(time.time()):
        parser.error('Positive sequence and future expiration are required')
    for sha in (args.upstream_sha, args.integration_sha):
        if not re.fullmatch('[0-9a-f]{40}', sha):
            parser.error('Full source commit identities are required')
    if args.output.exists():
        parser.error('Candidate output must not already exist')
    if args.output.resolve().is_relative_to(args.source.resolve()):
        parser.error('Release output must be outside the source tree')
    if not args.changelog.is_file() or args.changelog.stat().st_size == 0:
        parser.error('A nonempty generated release changelog is required')
    source_identity = json.loads((args.source / 'compact-source.json').read_text())
    recipe_manifest_path = Path(__file__).resolve().parents[1] / 'manifest.json'
    recipe_manifest = json.loads(recipe_manifest_path.read_text())
    if (source_identity.get('upstream_commit') != args.upstream_sha
            or args.upstream_sha != recipe_manifest.get('upstream_commit')
            or source_identity.get('integration_version') != recipe_manifest.get('integration_version')
            or source_identity.get('manifest_sha256') != digest(recipe_manifest_path)
            or source_identity.get('variant') != 'optimized'
            or not (args.source / 'compact-adapter/scan.c').is_file()):
        parser.error('An exact materialized optimized source tree is required')
    identity = built_identity(args.build, args.sequence)
    if args.version != identity['version']:
        parser.error('Release version must match the built upstream engine and fork sequence')
    report = json.loads(args.qualification.read_text())
    if report.get('integration_sha') != args.integration_sha or report.get('passed') is not True:
        parser.error('Qualification report must identify this tested source and pass')
    if args.channel == 'stable' and report.get('stable_release_qualified') is not True:
        parser.error('Stable qualification remains incomplete')
    output = args.output.resolve()
    output.mkdir(parents=True)
    payload = output / 'payload'
    payload.mkdir()
    elf_files = []
    for executable in ('compact-scan', 'compact-update'):
        original = find_one(args.build, executable)
        elf_files.append(original)
        copy_file(original, payload, 'lib/' + executable + '.real', True, True)
        write_launcher(payload, executable)
    names = ('libclamav', 'libfreshclam', 'libclammspack', 'libclamunrar', 'libclamunrar_iface')
    for name in names:
        found = sorted({p.resolve() for p in args.build.rglob(name + '.so*') if p.is_file()})
        if len(found) != 1:
            raise ValueError('Expected one version of ' + name)
        original = found[0]
        elf_files.append(original)
        match = re.fullmatch(re.escape(name) + r'\.so\.(\d+)\..*', original.name)
        soname = name + '.so.' + match[1] if match else original.name
        copy_file(original, payload, 'lib/' + soname, strip=True)
        if name.startswith('libclamunrar'):
            copy_file(original, payload, 'lib/' + name + '.so', strip=True)
    for cert in sorted((args.source / 'certs').glob('*.crt')):
        copy_file(cert, payload, 'certs/' + cert.name)
    if not (payload / 'certs' / 'clamav.crt').is_file():
        raise ValueError('ClamAV verification certificate is missing')
    copy_tls_ca_bundle(payload)
    for notice in [args.source / 'COPYING.txt', *sorted((args.source / 'COPYING').glob('*'))]:
        if notice.is_file():
            copy_file(notice, payload, 'notices/clamav/' + notice.name)
    dependencies = collect(elf_files, args.build, payload,
                           args.dependency_sources or output / 'dependency-sources',
                           data_owners=('/usr/sbin/update-ca-certificates',))
    write_json(output / 'dependencies.json', dependencies)
    tag = identity['tag']
    base_url = 'https://github.com/' + args.repository + '/releases/download/' + quote(tag, safe='') + '/'
    files = []
    for path in sorted(payload.rglob('*')):
        if path.is_file():
            relative = path.relative_to(payload).as_posix()
            sha = digest(path)
            asset = sha[:16] + '--' + path.name
            dest = output / 'assets' / asset
            dest.parent.mkdir(exist_ok=True)
            if not dest.exists():
                shutil.copyfile(path, dest)
            elif digest(dest) != sha:
                raise ValueError('Conflicting release asset name: ' + asset)
            files.append({'path': relative, 'sha256': sha, 'size': path.stat().st_size,
                          'mode': '0500' if path.stat().st_mode & 0o111 else '0400',
                          'url': base_url + quote(asset, safe='')})
    manifest = {'protocol': 1, 'sequence': args.sequence, 'expires_at': args.expires_at,
                'channel': args.channel, 'version': args.version, 'platform': PLATFORM,
                'files': files, 'upstream_sha': args.upstream_sha,
                'integration_sha': args.integration_sha, 'repository': args.repository,
                'upstream_version': identity['upstream_version'],
                'fork_revision': identity['fork_revision'],
                'integration_version': recipe_manifest['integration_version'],
                'tag': tag, 'experimental': args.channel != 'stable',
                'subset_release_qualified': report.get('subset_release_qualified') is True,
                'platform_requirements': {'architecture': 'x86_64', 'libc': 'glibc',
                                          'minimum_glibc': '2.36', 'other_sonames': dependencies['platform_sonames']}}
    write_json(output / 'manifest.json', manifest)
    shutil.copyfile(args.qualification, output / 'qualification.json')
    shutil.copyfile(args.changelog, output / 'CHANGELOG.md')
    manifest['changelog_sha256'] = digest(output / 'CHANGELOG.md')
    write_json(output / 'provenance.json', {
        'source': {'upstream_sha': args.upstream_sha, 'integration_sha': args.integration_sha},
        'release': identity, 'integration_version': recipe_manifest['integration_version'],
        'platform': PLATFORM, 'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
        'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(),
        'github_run_id': os.environ.get('GITHUB_RUN_ID'),
        'source_complete': dependencies['source_complete'], 'prepared_unsigned': True,
        'qualification_sha256': digest(output / 'qualification.json')})
    packages = [{'SPDXID': 'SPDXRef-ClamAV', 'name': 'ClamAV compact integration',
                 'versionInfo': args.version, 'downloadLocation': 'https://github.com/' + args.repository,
                 'licenseDeclared': 'GPL-2.0-only', 'filesAnalyzed': False}]
    for i, item in enumerate(dependencies['sources']):
        packages.append({'SPDXID': 'SPDXRef-Debian-' + str(i), 'name': item['name'],
                         'versionInfo': item['version'], 'downloadLocation': 'https://deb.debian.org/debian',
                         'licenseDeclared': 'NOASSERTION', 'filesAnalyzed': False})
    vendor = output / 'rust-vendor'
    config = subprocess.check_output(['cargo', 'vendor', '--locked', '--versioned-dirs',
                                     '--manifest-path', str(args.source / 'Cargo.toml'),
                                     str(vendor)], text=True)
    materials = output / 'source-build-materials'
    materials.mkdir()
    config = re.sub(r'^directory = .*$', 'directory = "../rust-vendor"', config, flags=re.M)
    (materials / 'cargo-vendor-config.toml').write_text(config)
    for recipe in ('Dockerfile', 'debian-packages.lock'):
        shutil.copyfile(Path(__file__).parent / recipe, materials / recipe)
    cargo = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--offline',
        '--format-version=1', '--manifest-path', str(args.source / 'Cargo.toml')], text=True))
    for i, crate in enumerate(cargo['packages']):
        packages.append({'SPDXID': 'SPDXRef-Rust-' + str(i), 'name': crate['name'],
                         'versionInfo': crate['version'], 'downloadLocation': crate.get('repository') or 'NOASSERTION',
                         'licenseDeclared': crate.get('license') or 'NOASSERTION', 'filesAnalyzed': False})
    write_json(output / 'sbom.spdx.json', {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT', 'name': tag,
        'documentNamespace': 'https://github.com/' + args.repository + '/releases/' + tag,
        'creationInfo': {'creators': ['Tool: compact-integration-package'],
                         'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
        'packages': packages})
    (materials / 'README.txt').write_text(
        'Exact modified ClamAV source, signed Debian source package inputs, and vendored Rust dependencies.\n'
        'For an offline rebuild, copy cargo-vendor-config.toml to clamav/.cargo/config.toml.\n'
        'Configure clamav with CMake/Ninja, the options in compact-source.json and the documented Debian builder.\n'
        'The native adapter is included as clamav/compact-adapter.\n')
    archive(output / (tag + '-source.tar.gz'),
            [(args.source, tag + '/clamav'),
             (args.dependency_sources or output / 'dependency-sources', tag + '/dependency-sources'),
             (vendor, tag + '/rust-vendor'), (materials, tag)])
    smoke_environment = os.environ.copy()
    for name in ('LD_PRELOAD', 'LD_AUDIT'):
        smoke_environment.pop(name, None)
    smoke_environment['COMPACT_PARENT_PID'] = str(os.getpid())
    doctor = subprocess.check_output([str(payload / 'bin/compact-scan'), 'doctor'], text=True,
                                     env=smoke_environment, timeout=30)
    packaged_identity = json.loads(doctor)
    if (not isinstance(packaged_identity, dict) or packaged_identity.get('protocol') != 1
            or packaged_identity.get('status') != 'ready' or packaged_identity.get('completed') is not True
            or packaged_identity.get('engine_version') != identity['upstream_version']):
        raise ValueError('Packaged engine version differs from the qualified build identity')
    write_json(output / 'packaged-smoke.json', packaged_identity)
    source_archive = output / (tag + '-source.tar.gz')
    manifest['source_archives'] = [{'name': source_archive.name, 'sha256': digest(source_archive),
                                    'size': source_archive.stat().st_size,
                                    'url': base_url + quote(source_archive.name, safe='')}]
    for name in ('sbom.spdx.json', 'provenance.json', 'qualification.json'):
        manifest[name.replace('.', '_') + '_sha256'] = digest(output / name)
    write_json(output / 'manifest.json', manifest)
    # Complete source is already retained in its distribution archive. Remove
    # only this invocation's temporary copies, keeping external source caches.
    for temporary in (vendor, materials, payload):
        shutil.rmtree(temporary)
    if args.dependency_sources is None:
        shutil.rmtree(output / 'dependency-sources')
    # Installer consumes individual verified files; the tar is a distribution
    # artifact for CI transport only, never an installer extraction format.
    index = [{'path': p.relative_to(output).as_posix(), 'size': p.stat().st_size,
              'sha256': digest(p)} for p in sorted(output.rglob('*')) if p.is_file()]
    write_json(output / 'bundle-index.json', index)
    archive(output.parent / (tag + '-candidate.tar.gz'), [(output, 'candidate')])
    print(json.dumps({'status': 'pending-signature', 'manifest_sha256': digest(output / 'manifest.json'),
                      'files': len(files), 'source_complete': True}))


if __name__ == '__main__':
    main()
