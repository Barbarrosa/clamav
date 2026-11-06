#!/usr/bin/env python3
"""Extract hash-checked public benchmark fixtures only. GPL-2.0-only."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def prepare(archive, output, per_group):
    if output.exists() and any(output.iterdir()):
        raise ValueError('output must be absent or empty')
    if per_group < 1:
        raise ValueError('per-group must be positive')
    output.mkdir(parents=True, exist_ok=True)
    records = []
    with tarfile.open(archive, 'r:gz') as tf:
        manifest = json.load(tf.extractfile('manifest.json'))
        for group in ('accepted', 'positive', 'adverse'):
            for entry in manifest[group][:per_group]:
                member = PurePosixPath(entry['member'])
                if member.is_absolute() or '..' in member.parts or member.parts[0] != group:
                    raise ValueError('unsafe corpus member')
                info = tf.getmember(str(member))
                if not info.isfile() or info.size != entry['bytes']:
                    raise ValueError('corpus member type/size mismatch')
                data = tf.extractfile(info).read()
                if hashlib.sha256(data).hexdigest() != entry['sha256']:
                    raise ValueError('corpus member hash mismatch')
                dest = output.joinpath(*member.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                records.append({'group': group, 'member': str(member),
                                'bytes': len(data), 'sha256': entry['sha256']})
    (output / 'files.txt').write_text(''.join(str(output.resolve() / r['member']) + '\n' for r in records))
    report = {'schema_version': 1, 'scope': 'public synthetic fixtures; no private submissions',
              'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
              'selection': 'first N entries per accepted/positive/adverse group in archived manifest order',
              'requested_per_group': per_group, 'files': records}
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=Path(__file__).resolve().parents[3] /
                        'docs/subset-selector-results/three-way-performance/corpus.tar.gz')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--per-group', type=int, default=8)
    args = parser.parse_args()
    report = prepare(args.archive, args.output, args.per_group)
    print(json.dumps({'files': len(report['files']), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
