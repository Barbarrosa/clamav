#!/usr/bin/env python3
"""Publish exact qualified artifacts without modifying existing public releases.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote

from versioning import native_tag, valid_semver, version_identity


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True, stderr=subprocess.PIPE).strip()


def api_optional(endpoint):
    """Only a genuine GitHub 404 means absence; authentication/network errors fail."""
    try:
        return json.loads(gh('api', endpoint))
    except subprocess.CalledProcessError as error:
        message = error.stderr or ''
        if isinstance(message, bytes):
            message = message.decode('utf-8', errors='replace')
        if re.search(r'\(HTTP 404\)', message):
            return None
        raise


def trusted_run(repository, run_id, workflow, qualification_job=None):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid GitHub repository')
    if not re.fullmatch(r'[1-9][0-9]*', str(run_id)):
        raise ValueError('Invalid qualification run ID')
    run = json.loads(gh('api', f'repos/{repository}/actions/runs/{run_id}'))
    repo = json.loads(gh('api', f'repos/{repository}'))
    completed = run.get('status') == 'completed' and run.get('conclusion') == 'success'
    current = (qualification_job is not None and run.get('status') == 'in_progress'
               and run.get('conclusion') is None)
    if (not (completed or current) or run.get('event') not in ('push', 'workflow_dispatch')
            or run.get('head_branch') != repo['default_branch']
            or run.get('head_repository', {}).get('full_name') != repository
            or run.get('path') != '.github/workflows/' + workflow
            or not re.fullmatch('[0-9a-f]{40}', run.get('head_sha', ''))):
        raise ValueError('Run is not qualified from the trusted default branch')
    if qualification_job is not None:
        attempt = run.get('run_attempt')
        if type(attempt) is not int or attempt < 1:
            raise ValueError('Qualification run attempt is absent')
        # A publisher-only retry omits already-successful dependency jobs. Examine the
        # most recent actual qualification, never allowing an older pass to hide failure.
        for previous_attempt in range(attempt, max(0, attempt - 10), -1):
            jobs = json.loads(gh('api', f'repos/{repository}/actions/runs/{run_id}'
                                 f'/attempts/{previous_attempt}/jobs?per_page=100'))
            if jobs.get('total_count', 101) > 100:
                raise ValueError('Qualification job inventory exceeds its review bound')
            matches = [job for job in jobs.get('jobs', []) if job.get('name') == qualification_job]
            if not matches:
                continue
            if (len(matches) != 1 or matches[0].get('status') != 'completed'
                    or matches[0].get('conclusion') != 'success'):
                raise ValueError('The latest qualification job did not uniquely succeed')
            break
        else:
            raise ValueError('No successful qualification job within the bounded attempt history')
    return run


def check_run(repository, run_id, workflow, qualification_job=None):
    return trusted_run(repository, run_id, workflow, qualification_job)['head_sha']


def verify_signature(candidate, public_key_b64):
    signature = candidate / 'manifest.sig'
    if not signature.is_file() or signature.stat().st_size != 64 or not public_key_b64:
        raise ValueError('A protected Ed25519 signature and public key are required before publication')
    verifier = '''$key=base64_decode($argv[1],true); if($key===false || strlen($key)!==SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)exit(2);
exit(sodium_crypto_sign_verify_detached(file_get_contents($argv[2]),file_get_contents($argv[3]),$key)?0:3);'''
    subprocess.run(['php', '-r', verifier, public_key_b64, str(signature),
                    str(candidate / 'manifest.json')], check=True)


def release_content(candidate, manifest, run, run_id, public_key_b64, allow_unsigned_preview):
    """Validate publication identity and return the immutable notes and asset list."""
    canonical = manifest.get('tag', '').startswith('clamav-')
    if manifest.get('channel') not in ('preview', 'stable'):
        raise ValueError('Unsupported release channel')
    if canonical:
        if (manifest['tag'] != native_tag(manifest.get('version'))
                or version_identity(manifest.get('upstream_version'), manifest.get('fork_revision'))['version']
                   != manifest['version']
                or type(manifest.get('sequence')) is not int
                or manifest['sequence'] != manifest['fork_revision']
                or manifest['sequence'] != run.get('run_number')):
            raise ValueError('Fork version, upstream version, and qualification sequence differ')
    elif (not valid_semver(manifest.get('version'))
          or manifest.get('tag') != 'compact-v' + manifest['version']):
        raise ValueError('Invalid native release tag')
    report = json.loads((candidate / 'qualification.json').read_text())
    provenance = json.loads((candidate / 'provenance.json').read_text())
    if (report.get('passed') is not True or report.get('integration_sha') != run['head_sha']
            or provenance.get('source_complete') is not True):
        raise ValueError('Successful qualification and complete corresponding source are required')
    if canonical and str(provenance.get('github_run_id')) != str(run_id):
        raise ValueError('Candidate provenance belongs to another qualification run')
    if manifest['channel'] == 'stable' and report.get('stable_release_qualified') is not True:
        raise ValueError('Stable release gates remain incomplete')
    unsigned = allow_unsigned_preview
    if unsigned:
        if (manifest['channel'] != 'preview' or public_key_b64
                or (candidate / 'manifest.sig').exists() or not canonical):
            raise ValueError('Unsigned publication is only allowed for unconfigured development previews')
    else:
        verify_signature(candidate, public_key_b64)
    changelog = candidate / 'CHANGELOG.md'
    if canonical or 'changelog_sha256' in manifest:
        if (not changelog.is_file() or changelog.stat().st_size == 0
                or changelog.stat().st_size > 1024 * 1024
                or hashlib.sha256(changelog.read_bytes()).hexdigest() != manifest.get('changelog_sha256')):
            raise ValueError('The exact qualified changelog is required')
        notes = changelog.read_text(encoding='utf-8')
    else:
        notes = (f"Experimental {manifest['version']} ({manifest['channel']}).\n\n"
                 f"Integration commit: {run['head_sha']}\nUpstream: {manifest.get('upstream_sha')}\n\n"
                 "Corresponding source, licenses, SBOM and build provenance accompany this release.\n")
    if unsigned:
        notes = ("**Unsigned development prerelease.** GitHub Actions provenance accompanies the qualified "
                 "candidate. Trusted automatic installers reject this release because no protected "
                 "Ed25519 release signature is configured.\n\n" + notes)
    else:
        notes = ("The release manifest is signed with the protected channel Ed25519 key. "
                 "Installers verify its signature and individual asset hashes.\n\n" + notes)
    files = [candidate / name for name in ('manifest.json', 'qualification.json', 'provenance.json')]
    if not unsigned:
        files.append(candidate / 'manifest.sig')
    if changelog.is_file():
        files.append(changelog)
    for pattern in ('*.tar.gz', '*.zip', '*spdx.json'):
        files.extend(sorted(candidate.glob(pattern)))
    if (candidate / 'assets').is_dir():
        files.extend(sorted(p for p in (candidate / 'assets').iterdir() if p.is_file()))
    if (any(not path.is_file() or path.is_symlink() for path in files)
            or len({path.name for path in files}) != len(files)):
        raise ValueError('Publication assets are missing, linked, or ambiguous')
    return notes, files


def asset_bytes(repository, asset):
    if type(asset.get('id')) is not int or not 0 < asset.get('size', 0) <= 1024 * 1024:
        raise ValueError('Invalid release metadata asset')
    raw = subprocess.check_output(['gh', 'api', f'repos/{repository}/releases/assets/{asset["id"]}',
                                   '-H', 'Accept: application/octet-stream'], timeout=30)
    if len(raw) != asset['size'] or len(raw) > 1024 * 1024:
        raise ValueError('Published release metadata size differs')
    return raw


def published_matches(repository, release, candidate, files, notes):
    """A rerun may observe the same public release; it can never alter that release."""
    assets = release.get('assets', [])
    by_name = {asset['name']: asset for asset in assets}
    if (len(by_name) != len(assets) or set(by_name) != {path.name for path in files}
            or any(by_name[path.name].get('size') != path.stat().st_size for path in files)
            or release.get('body') != notes):
        raise ValueError('Published release identity or inventory differs; releases are immutable')
    verify_asset_digests(by_name, files)
    for name in ('manifest.json', 'manifest.sig', 'CHANGELOG.md', 'provenance.json', 'qualification.json'):
        local = candidate / name
        if local.is_file() and asset_bytes(repository, by_name[name]) != local.read_bytes():
            raise ValueError('Published release bytes differ; releases are immutable')


def verify_asset_digests(by_name, files):
    for path in files:
        digest = by_name[path.name].get('digest')
        if digest is not None:
            expected = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected:
                raise ValueError('Uploaded release asset digest differs')


def verify_draft_inventory(release, files, complete=False):
    assets = release.get('assets', [])
    by_name = {asset['name']: asset for asset in assets}
    expected = {path.name for path in files}
    if (len(by_name) != len(assets) or not set(by_name) <= expected
            or (complete and set(by_name) != expected)):
        raise ValueError('Draft contains unexpected or incomplete publication assets')
    if complete:
        if any(by_name[path.name].get('size') != path.stat().st_size for path in files):
            raise ValueError('Uploaded release asset size differs')
        verify_asset_digests(by_name, files)


def publish(repository, run_id, workflow, candidate, public_key_b64=None,
            allow_unsigned_preview=False, qualification_job=None):
    run = trusted_run(repository, run_id, workflow, qualification_job)
    candidate = Path(candidate)
    manifest = json.loads((candidate / 'manifest.json').read_text())
    commit = run['head_sha']
    if manifest.get('integration_sha') != commit or manifest.get('repository') != repository:
        raise ValueError('Artifact and qualified run identities differ')
    notes, files = release_content(candidate, manifest, run, run_id, public_key_b64, allow_unsigned_preview)
    tag = manifest['tag']
    encoded_tag = quote(tag, safe='')
    existing_tag = api_optional(f'repos/{repository}/git/ref/tags/{encoded_tag}')
    if existing_tag is not None:
        obj = existing_tag['object']
        for _ in range(16):
            if obj['type'] != 'tag':
                break
            obj = json.loads(gh('api', f'repos/{repository}/git/tags/{obj["sha"]}'))['object']
        if obj['type'] != 'commit' or obj['sha'] != commit:
            raise ValueError('An existing tag points elsewhere; versions are immutable')
    release = api_optional(f'repos/{repository}/releases/tags/{encoded_tag}')
    if release is not None:
        if existing_tag is None or release.get('tag_name') != tag:
            raise ValueError('Existing release has an inconsistent tag')
        if release.get('draft') is not True:
            if release.get('prerelease') is not (manifest['channel'] == 'preview'):
                raise ValueError('Published release channel differs')
            published_matches(repository, release, candidate, files, notes)
            print(f'Already published unchanged: {tag}')
            return
        verify_draft_inventory(release, files)
    if existing_tag is None:
        gh('api', '--method', 'POST', f'repos/{repository}/git/refs',
           '-f', 'ref=refs/tags/' + tag, '-f', 'sha=' + commit)
    with tempfile.TemporaryDirectory(prefix='compact-release-notes-') as temporary:
        body = Path(temporary) / 'release-notes.md'
        body.write_text(notes, encoding='utf-8')
        if release is None:
            args = ['release', 'create', tag, '--repo', repository, '--target', commit,
                    '--title', tag, '--notes-file', str(body), '--verify-tag', '--draft']
            if manifest['channel'] == 'preview':
                args.append('--prerelease')
            gh(*args)
        # Only private drafts may replace assets or notes when a publication was interrupted.
        gh('release', 'upload', tag, '--repo', repository, '--clobber', *(str(path) for path in files))
        uploaded = json.loads(gh('api', f'repos/{repository}/releases/tags/{encoded_tag}'))
        if uploaded.get('draft') is not True or uploaded.get('tag_name') != tag:
            raise ValueError('Release stopped being the expected private draft')
        verify_draft_inventory(uploaded, files, complete=True)
        gh('release', 'edit', tag, '--repo', repository, '--notes-file', str(body), '--draft=false',
           '--prerelease=' + ('true' if manifest['channel'] == 'preview' else 'false'))
    print(f'Published {tag}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'run-id', 'workflow'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--public-key-b64')
    parser.add_argument('--check-run-only', action='store_true')
    parser.add_argument('--qualification-job', help='Successful job in this run attempt, including in-progress runs')
    parser.add_argument('--allow-unsigned-preview', action='store_true')
    args = parser.parse_args()
    if args.check_run_only:
        print(check_run(args.repository, args.run_id, args.workflow, args.qualification_job))
        return
    if not args.candidate:
        parser.error('--candidate required for publication')
    publish(args.repository, args.run_id, args.workflow, args.candidate, args.public_key_b64,
            args.allow_unsigned_preview, args.qualification_job)


if __name__ == '__main__':
    main()
