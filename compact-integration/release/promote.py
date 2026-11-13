#!/usr/bin/env python3
"""Verify a qualified GitHub run and publish already-signed exact artifacts.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True).strip()


def check_run(repository, run_id, workflow):
    run = json.loads(gh('api', f'repos/{repository}/actions/runs/{run_id}'))
    repo = json.loads(gh('api', f'repos/{repository}'))
    if (run['conclusion'] != 'success' or run['event'] not in ('push', 'workflow_dispatch')
            or run['head_branch'] != repo['default_branch']
            or run['head_repository']['full_name'] != repository
            or run['path'] != '.github/workflows/' + workflow):
        raise ValueError('Run is not successful qualification from the trusted default branch')
    return run['head_sha']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'run-id', 'workflow'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--public-key-b64')
    parser.add_argument('--check-run-only', action='store_true')
    a = parser.parse_args()
    commit = check_run(a.repository, a.run_id, a.workflow)
    if a.check_run_only:
        print(commit)
        return
    if not a.candidate:
        parser.error('--candidate required for publication')
    manifest = json.loads((a.candidate / 'manifest.json').read_text())
    if manifest['integration_sha'] != commit or manifest['repository'] != a.repository:
        raise ValueError('Artifact and qualified run identities differ')
    signature = a.candidate / 'manifest.sig'
    if not signature.is_file() or signature.stat().st_size != 64:
        raise ValueError('A protected Ed25519 signature is required before publication')
    if not a.public_key_b64:
        parser.error('--public-key-b64 is required for publication')
    verifier = '''$key=base64_decode($argv[1],true); if($key===false || strlen($key)!==SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)exit(2);
exit(sodium_crypto_sign_verify_detached(file_get_contents($argv[2]),file_get_contents($argv[3]),$key)?0:3);'''
    subprocess.run(['php', '-r', verifier, a.public_key_b64, str(signature), str(a.candidate / 'manifest.json')], check=True)
    tag = manifest['tag']
    # Existing versions are immutable. Do not edit assets or force tag updates.
    existing_tag = subprocess.run(['gh', 'api', f'repos/{a.repository}/git/ref/tags/{tag}'],
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if existing_tag.returncode == 0:
        obj = json.loads(existing_tag.stdout)['object']
        for _ in range(16):
            if obj['type'] != 'tag':
                break
            obj = json.loads(gh('api', f'repos/{a.repository}/git/tags/{obj["sha"]}'))['object']
        if obj['type'] != 'commit' or obj['sha'] != commit:
            raise ValueError('An existing tag points elsewhere; versions are immutable')
    existing_release = subprocess.run(['gh', 'release', 'view', tag, '--repo', a.repository, '--json', 'isDraft'],
                                      text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if existing_release.returncode == 0 and json.loads(existing_release.stdout)['isDraft'] is not True:
        raise ValueError('Release is already published; versions and assets are immutable')
    body = a.candidate / 'release-notes.txt'
    body.write_text(f"Experimental {manifest['version']} ({manifest['channel']}).\n\n"
                    f"Integration commit: {commit}\nUpstream: {manifest.get('upstream_sha', 'plugin source')}\n"
                    "Individual native files are verified against the signed manifest before installation.\n"
                    "Corresponding source, licenses, SBOM and build provenance accompany this release.\n"
                    "Reduced automatic disposition and SiteGround hosting qualification remain gated.\n")
    files = [str(a.candidate / n) for n in ('manifest.json', 'manifest.sig', 'qualification.json', 'provenance.json')]
    files += [str(p) for p in sorted(a.candidate.glob('*.tar.gz'))]
    files += [str(p) for p in sorted(a.candidate.glob('*.zip'))]
    files += [str(p) for p in sorted(a.candidate.glob('*spdx.json'))]
    if (a.candidate / 'assets').is_dir():
        files += [str(p) for p in sorted((a.candidate / 'assets').iterdir()) if p.is_file()]
    if existing_tag.returncode != 0:
        gh('api', '--method', 'POST', f'repos/{a.repository}/git/refs', '-f', 'ref=refs/tags/' + tag, '-f', 'sha=' + commit)
    args = ['release', 'create', tag, '--repo', a.repository, '--target', commit,
            '--title', tag, '--notes-file', str(body), '--verify-tag', '--draft']
    if manifest['channel'] == 'preview':
        args.append('--prerelease')
    if existing_release.returncode != 0:
        gh(*args)
    gh('release', 'upload', tag, '--repo', a.repository, '--clobber', *files)
    gh('release', 'edit', tag, '--repo', a.repository, '--draft=false',
       '--prerelease=' + ('true' if manifest['channel'] == 'preview' else 'false'))


if __name__ == '__main__':
    main()
