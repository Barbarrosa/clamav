#!/usr/bin/env python3
"""Collect ELF runtime dependencies and their matching Debian source packages.

Only run on the pinned Debian build image. No database or upload content is used.
SPDX-License-Identifier: GPL-2.0-only
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.parse
import urllib.request

PLATFORM = {
    'linux-vdso.so.1', 'ld-linux-x86-64.so.2', 'libc.so.6', 'libm.so.6',
    'libdl.so.2', 'libpthread.so.0', 'librt.so.1', 'libutil.so.1',
    'libresolv.so.2', 'libgcc_s.so.1', 'libstdc++.so.6',
}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def package_for(path):
    path = Path(path)
    candidates = [str(path), str(path.resolve())]
    if str(path).startswith('/usr/lib/'):
        candidates.append(str(path)[4:])
    for candidate in candidates:
        proc = subprocess.run(['dpkg-query', '-S', candidate], text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if proc.returncode == 0:
            binary = proc.stdout.splitlines()[0].split(': ', 1)[0]
            fmt = '${source:Package}\t${source:Version}\t${Version}\t${binary:Package}'
            source, version, binary_version, binary = command(
                ['dpkg-query', '-W', '-f=' + fmt, binary]).split('\t')
            return {'source': source, 'source_version': version,
                    'package': binary, 'version': binary_version}
    raise RuntimeError('Cannot identify dependency owner: ' + str(path))


def enable_deb_src():
    """Add source indexes for the same official Debian repos inside the builder."""
    original = Path('/etc/apt/sources.list.d/debian.sources')
    if os.geteuid() != 0 or not original.is_file():
        raise RuntimeError('Source indexes must be enabled in the disposable Debian builder')
    text = original.read_text()
    for uri in re.findall(r'^URIs:\s*(.*)$', text, re.M):
        if not re.fullmatch(r'https?://(?:deb|security)\.debian\.org/(?:debian|debian-security)/?', uri.strip()):
            raise RuntimeError('Unexpected Debian repository: ' + uri)
    text, count = re.subn(r'^Types: deb$', 'Types: deb-src', text, flags=re.M)
    if not count:
        raise RuntimeError('No official Debian binary repository entries found')
    Path('/etc/apt/sources.list.d/compact-deb-src.sources').write_text(text)
    subprocess.run(['apt-get', 'update', '-qq'], check=True)


def snapshot_sources(name, version, folder):
    """Fetch the same pruned version by immutable official snapshot hashes."""
    base = 'https://snapshot.debian.org'
    url = base + '/mr/package/' + urllib.parse.quote(name, safe='') + '/' + urllib.parse.quote(version, safe='') + '/srcfiles'
    with urllib.request.urlopen(url, timeout=60) as response:
        metadata = json.load(response)
    if metadata.get('package') != name or metadata.get('version') != version:
        raise RuntimeError('Snapshot returned another source identity')
    records = []
    for entry in metadata['result']:
        sha1 = entry['hash']
        if not re.fullmatch('[0-9a-f]{40}', sha1):
            raise RuntimeError('Invalid immutable source hash')
        with urllib.request.urlopen(base + '/mr/file/' + sha1 + '/info', timeout=60) as response:
            locations = json.load(response)['result']
        location = next((x for x in locations if x['archive_name'] in ('debian', 'debian-security')), None)
        if not location or Path(location['name']).name != location['name'] or not 0 < location['size'] <= 512 * 1024 ** 2:
            raise RuntimeError('Unsafe source snapshot metadata')
        destination = folder / location['name']
        source_url = base + '/file/' + sha1
        with urllib.request.urlopen(source_url, timeout=120) as response, destination.open('wb') as stream:
            count, checksum = 0, hashlib.sha1()
            while block := response.read(1024 * 1024):
                count += len(block)
                if count > location['size']:
                    raise RuntimeError('Snapshot source exceeded its recorded size')
                checksum.update(block)
                stream.write(block)
        if count != location['size'] or checksum.hexdigest() != sha1:
            raise RuntimeError('Immutable snapshot file integrity mismatch')
        records.append({'name': destination.name, 'snapshot_sha1': sha1, 'sha256': digest(destination),
                        'url': source_url, 'first_seen': location['first_seen']})
    descriptors = list(folder.glob('*.dsc'))
    if len(descriptors) != 1:
        raise RuntimeError('Expected one source descriptor')
    descriptor = descriptors[0].read_text()
    if re.search(r'^Source:\s*(\S+)', descriptor, re.M)[1] != name or re.search(r'^Version:\s*(\S+)', descriptor, re.M)[1] != version:
        raise RuntimeError('Snapshot source descriptor identity mismatch')
    section = re.search(r'^Checksums-Sha256:\n((?:[ \t].*\n)+)', descriptor, re.M)
    if not section:
        raise RuntimeError('Source descriptor lacks SHA-256 checksums')
    for line in section[1].splitlines():
        checksum, size, filename = line.split()
        file = folder / filename
        if Path(filename).name != filename or file.stat().st_size != int(size) or digest(file) != checksum:
            raise RuntimeError('Source archive differs from its SHA-256 descriptor')
    return records


def copy_notice(metadata, payload):
    doc = Path('/usr/share/doc') / metadata['package'].split(':')[0] / 'copyright'
    if not doc.is_file():
        raise RuntimeError('Missing redistribution notice: ' + str(doc))
    notice = payload / 'notices' / 'debian' / (metadata['package'].replace(':', '_') + '.copyright')
    notice.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(doc, notice)
    return str(notice.relative_to(payload))


def collect(elf_paths, build, payload, source_output, download_sources=True, data_owners=()):
    build, payload, source_output = map(lambda p: Path(p).resolve(),
                                        (build, payload, source_output))
    source_output.mkdir(parents=True, exist_ok=True)
    libraries, requirements = {}, set()
    for elf in elf_paths:
        result = command(['ldd', str(elf)])
        if 'not found' in result:
            raise RuntimeError('Unresolved ELF dependency: ' + result)
        for soname, location in re.findall(r'^\s*(\S+)\s+=>\s+(/\S+)\s+\(', result, re.M):
            if soname in PLATFORM:
                requirements.add(soname)
                continue
            real = Path(location).resolve()
            if real.is_relative_to(build):
                continue
            metadata = package_for(location)
            previous = libraries.get(soname)
            if previous and previous['sha256'] != digest(real):
                raise RuntimeError('Conflicting dependency SONAME: ' + soname)
            dest = payload / 'lib' / soname
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(real, dest)
            os.chmod(dest, 0o644)
            notice = copy_notice(metadata, payload)
            libraries[soname] = {**metadata, 'path': 'lib/' + soname,
                                 'sha256': digest(dest), 'notice': notice}
    data_packages = []
    for owner in data_owners:
        metadata = package_for(owner)
        data_packages.append({**metadata, 'notice': copy_notice(metadata, payload)})
    packages = {}
    for lib in [*libraries.values(), *data_packages]:
        key = (lib['source'], lib['source_version'])
        packages[key] = {'name': key[0], 'version': key[1]}
    for (name, version), metadata in packages.items():
        folder = source_output / (name + '--' + version.replace(':', '_'))
        folder.mkdir(parents=True, exist_ok=True)
        if download_sources:
            result = subprocess.run(['apt-get', 'source', '--download-only', '--only-source',
                                     name + '=' + version], cwd=folder)
            if result.returncode:
                metadata['snapshot_files'] = snapshot_sources(name, version, folder)
        archives = sorted(p for p in folder.iterdir() if p.is_file())
        if not any(p.suffix == '.dsc' for p in archives) or not any('.tar.' in p.name for p in archives):
            raise RuntimeError('Incomplete matching dependency source: ' + name + '=' + version)
        metadata['files'] = [{'name': p.name, 'size': p.stat().st_size,
                              'sha256': digest(p)} for p in archives]
    return {'libraries': [libraries[k] for k in sorted(libraries)],
            'data_packages': data_packages,
            'sources': [packages[k] for k in sorted(packages)],
            'platform_sonames': sorted(requirements), 'source_complete': True}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable-deb-src', action='store_true')
    args = parser.parse_args()
    if args.enable_deb_src:
        enable_deb_src()
