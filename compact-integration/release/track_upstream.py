#!/usr/bin/env python3
"""Open an auditable upstream-pin PR; never resolve drift or publish releases.
SPDX-License-Identifier: GPL-2.0-only
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    return subprocess.check_output(list(args), text=True).strip()


def main():
    repository = os.environ['GITHUB_REPOSITORY']
    root = Path(__file__).resolve().parents[1]
    manifest_file = root / 'manifest.json'
    manifest = json.loads(manifest_file.read_text())
    upstream = json.loads(run('gh', 'api', 'repos/Cisco-Talos/clamav/branches/main'))['commit']['sha']
    if upstream == manifest['upstream_commit']:
        print('Upstream pin is current.')
        return
    branch = 'automation/upstream-' + upstream[:12]
    prs = json.loads(run('gh', 'pr', 'list', '--repo', repository, '--head', branch, '--json', 'number'))
    if prs:
        print('An upstream adaptation PR already exists.')
        return
    base = json.loads(run('gh', 'api', 'repos/' + repository))['default_branch']
    run('git', 'fetch', '--no-tags', manifest['upstream_repository'], 'main')
    run('git', 'cat-file', '-e', upstream + '^{commit}')
    run('git', 'checkout', '-b', branch)
    previous = manifest['upstream_commit']
    manifest['upstream_commit'] = upstream
    manifest['qualification'] = {'status': 'pending', 'coverage_qualified': False,
                                 'siteground_qualified': False}
    manifest_file.write_text(json.dumps(manifest, indent=2) + '\n')
    run('git', 'config', 'user.name', 'compact-upstream[bot]')
    run('git', 'config', 'user.email', 'compact-upstream[bot]@users.noreply.github.com')
    run('git', 'add', str(manifest_file.relative_to(root.parent)))
    run('git', 'commit', '-m', 'Track upstream ' + upstream[:12] + ' for compact qualification')
    run('gh', 'auth', 'setup-git')
    run('git', 'push', 'origin', branch)
    body = (f'Pins upstream from `{previous}` to `{upstream}`.\n\n'
            'The existing patch checksums remain unchanged. Exact preimage checks and native '
            'qualification decide whether this integration still applies. Drift requires an '
            'explicit patch adaptation; the workflow also tests a separate unmodified upstream '
            'fallback. Reduced automatic disposition remains unqualified until its gates pass.\n\n'
            'No release, production deployment, or database publication is performed.\n')
    with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False) as stream:
        stream.write(body)
        filename = stream.name
    try:
        run('gh', 'pr', 'create', '--repo', repository, '--base', base, '--head', branch,
            '--title', 'Qualify compact integration against upstream ' + upstream[:12], '--body-file', filename)
    finally:
        Path(filename).unlink()
    # GITHUB_TOKEN-created PRs do not automatically start another push/PR run.
    # Explicit workflow_dispatch is supported and carries no signing secrets.
    run('gh', 'workflow', 'run', 'compact-native.yml', '--repo', repository, '--ref', branch)


if __name__ == '__main__':
    main()
