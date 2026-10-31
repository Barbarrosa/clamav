#!/usr/bin/env python3
"""Extract signature databases from a pinned official ClamAV image layer.

Does not run the image. Registry digests authenticate the downloaded bytes over
TLS; ClamAV must still verify and load the databases before measurements.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, help='Pinned linux image manifest sha256:digest')
    parser.add_argument('--layer', type=int, required=True, help='Database layer index in that manifest')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    url = 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:clamav/clamav:pull'
    with urllib.request.urlopen(url, timeout=30) as response:
        token = json.load(response)['token']

    def request(kind, digest):
        if not digest.startswith('sha256:') or len(digest) != 71:
            raise ValueError('Expected a SHA-256 registry digest')
        int(digest[7:], 16)
        return urllib.request.Request(
            'https://registry-1.docker.io/v2/clamav/clamav/' + kind + '/' + digest,
            headers={'Authorization': 'Bearer ' + token,
                     'Accept': 'application/vnd.oci.image.manifest.v1+json'})

    with urllib.request.urlopen(request('manifests', args.manifest), timeout=30) as response:
        manifest_bytes = response.read(1024 * 1024)
    if hashlib.sha256(manifest_bytes).hexdigest() != args.manifest[7:]:
        raise ValueError('Manifest digest mismatch')
    manifest = json.loads(manifest_bytes)
    if not 0 <= args.layer < len(manifest['layers']):
        raise ValueError('Database layer index is out of range')
    layer = manifest['layers'][args.layer]
    if layer['mediaType'] not in ('application/vnd.oci.image.layer.v1.tar+gzip',
                                   'application/vnd.docker.image.rootfs.diff.tar.gzip'):
        raise ValueError('Expected a gzip-compressed filesystem layer')
    allowed = {f'var/lib/clamav/{name}.{ext}' for name in ('main', 'daily', 'bytecode')
               for ext in ('cvd', 'cld')}
    records = []
    with tempfile.TemporaryDirectory(dir=args.output, prefix='image-db-') as directory:
        archive = Path(directory) / 'layer.tar.gz'
        digest = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(request('blobs', layer['digest']), timeout=30) as response, archive.open('wb') as dest:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > layer['size']:
                    raise ValueError('Layer exceeds manifest size')
                digest.update(chunk)
                dest.write(chunk)
        if size != layer['size'] or digest.hexdigest() != layer['digest'][7:]:
            raise ValueError('Layer size or digest mismatch')
        with tarfile.open(archive, 'r:gz') as tar:
            seen = set()
            for member in tar:
                name = member.name.removeprefix('./')
                if name not in allowed:
                    continue
                if not member.isfile() or name in seen:
                    raise ValueError('Duplicate or non-regular database entry')
                seen.add(name)
                target = args.output / Path(name).name
                if target.exists():
                    raise FileExistsError(target)
                staged = Path(directory) / target.name
                with tar.extractfile(member) as source, staged.open('wb') as dest:
                    shutil.copyfileobj(source, dest, 1024 * 1024)
                if staged.stat().st_size != member.size:
                    raise ValueError('Truncated database entry')
                h = hashlib.sha256()
                with staged.open('rb') as source:
                    while chunk := source.read(1024 * 1024):
                        h.update(chunk)
                staged.replace(target)
                records.append({'name': target.name, 'bytes': member.size, 'sha256': h.hexdigest()})
    if not records:
        raise ValueError('No databases found in selected layer')
    result = {'image': 'clamav/clamav', 'manifest_digest': args.manifest,
              'layer': layer, 'databases': records, 'clamav_verification': 'required before use'}
    (args.output / 'database-provenance.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
