#!/usr/bin/env python3
"""Open an auditable upstream-pin PR; never resolve drift or publish releases.
SPDX-License-Identifier: GPL-2.0-only
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(*args):
    return subprocess.check_output(list(args), text=True).strip()


def git(checkout, *args):
    return run('git', '-C', str(checkout), *args)


def remote_head(checkout, branch):
    """Fetch the existing immutable head, or distinguish an absent ref from failure."""
    ref = 'refs/heads/' + branch
    try:
        result = git(checkout, 'ls-remote', '--exit-code', '--heads', 'origin', ref)
    except subprocess.CalledProcessError as error:
        if error.returncode == 2:
            return None
        raise
    fields = result.split()
    if len(fields) != 2 or fields[1] != ref or not re.fullmatch('[0-9a-f]{40}', fields[0]):
        raise RuntimeError('Unexpected automation branch identity; refusing to overwrite it.')
    git(checkout, 'fetch', '--no-tags', 'origin', fields[0])
    return fields[0]


def ensure_qualification(repository, branch, head):
    """A PR or branch alone does not prove its native qualification was dispatched."""
    runs = json.loads(run('gh', 'run', 'list', '--repo', repository,
        '--workflow', 'compact-native.yml', '--branch', branch, '--commit', head,
        '--limit', '20', '--json', 'headSha,status,conclusion'))
    active = {'queued', 'in_progress', 'waiting', 'pending', 'requested'}
    for item in runs:
        if item['headSha'] == head and (item['status'] in active
                or item['status'] == 'completed' and item['conclusion'] == 'success'):
            print('Native qualification is already active or passed for ' + head + '.')
            return
    # GITHUB_TOKEN-created PRs do not trigger an ordinary push/PR run.
    # Explicit workflow_dispatch carries no signing secrets.
    run('gh', 'workflow', 'run', 'compact-native.yml', '--repo', repository, '--ref', branch)
    print('Dispatched native qualification for ' + head + '.')


def track(root, repository):
    checkout = root.parent
    manifest_file = root / 'manifest.json'
    manifest = json.loads(manifest_file.read_text())
    upstream = json.loads(run('gh', 'api', 'repos/Cisco-Talos/clamav/branches/main'))['commit']['sha']
    if not isinstance(upstream, str) or not re.fullmatch('[0-9a-f]{40}', upstream):
        raise ValueError('Upstream must resolve to a full Git commit identity.')
    if upstream == manifest['upstream_commit']:
        print('Upstream pin is current.')
        return
    branch = 'automation/upstream-' + upstream[:12]
    base = json.loads(run('gh', 'api', 'repos/' + repository))['default_branch']
    prs = json.loads(run('gh', 'pr', 'list', '--repo', repository, '--head', branch,
        '--state', 'open', '--json', 'number,url,baseRefName,headRefOid'))
    if len(prs) > 1 or prs and prs[0]['baseRefName'] != base:
        raise RuntimeError('Unexpected upstream PR base; manual review is required.')
    previous = manifest['upstream_commit']
    candidate = {**manifest, 'upstream_commit': upstream,
        'qualification': {'status': 'pending', 'coverage_qualified': False,
                          'siteground_qualified': False}}
    manifest_path = manifest_file.relative_to(checkout).as_posix()
    run('gh', 'auth', 'setup-git')
    head = remote_head(checkout, branch)
    if head is not None:
        existing = json.loads(git(checkout, 'show', head + ':' + manifest_path))
        if existing.get('upstream_commit') != upstream or existing.get('upstream_repository') != manifest['upstream_repository']:
            raise RuntimeError('Existing automation branch targets another upstream; refusing to overwrite it.')
        if prs:
            if prs[0]['headRefOid'] != head:
                raise RuntimeError('Upstream PR changed during inspection; retry without overwriting it.')
            print('Resuming upstream adaptation PR ' + prs[0]['url'] + '.')
        else:
            # A denied PR creation may leave a valid branch behind. Reuse its
            # exact commit rather than creating a timestamp-different sibling.
            # Compare from the common ancestor: default may since have advanced.
            ancestor = git(checkout, 'merge-base', 'HEAD', head)
            changed = git(checkout, 'diff', '--name-only', ancestor, head).splitlines()
            if changed != [manifest_path] or json.dumps(existing, sort_keys=True) != json.dumps(candidate, sort_keys=True):
                raise RuntimeError('Existing automation branch has additional changes; manual review is required.')
            print('Resuming existing upstream proposal branch at ' + head + '.')
    else:
        if prs:
            raise RuntimeError('The upstream PR branch is missing; manual review is required.')
        # Fetch the identity resolved above, not a possibly newer main tip.
        git(checkout, 'fetch', '--no-tags', manifest['upstream_repository'], upstream)
        git(checkout, 'cat-file', '-e', upstream + '^{commit}')
        git(checkout, 'checkout', '-b', branch)
        manifest_file.write_text(json.dumps(candidate, indent=2) + '\n')
        git(checkout, 'config', 'user.name', 'compact-upstream[bot]')
        git(checkout, 'config', 'user.email', 'compact-upstream[bot]@users.noreply.github.com')
        git(checkout, 'add', manifest_path)
        git(checkout, 'commit', '-m', 'Track upstream ' + upstream[:12] + ' for compact qualification')
        head = git(checkout, 'rev-parse', 'HEAD')
        git(checkout, 'push', 'origin', branch)
    body = (f'Pins upstream from `{previous}` to `{upstream}`.\n\n'
            'The existing patch checksums remain unchanged. Exact preimage checks and native '
            'qualification decide whether this integration still applies. Drift requires an '
            'explicit patch adaptation; the workflow also tests a separate unmodified upstream '
            'fallback. Reduced automatic disposition remains unqualified until its gates pass.\n\n'
            'No release, production deployment, or database publication is performed.\n')
    if not prs:
        with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False) as stream:
            stream.write(body)
            filename = stream.name
        try:
            print(run('gh', 'pr', 'create', '--repo', repository, '--base', base, '--head', branch,
                '--title', 'Qualify compact integration against upstream ' + upstream[:12], '--body-file', filename))
        finally:
            Path(filename).unlink()
    ensure_qualification(repository, branch, head)


def main():
    track(Path(__file__).resolve().parents[1], os.environ['GITHUB_REPOSITORY'])


if __name__ == '__main__':
    main()
