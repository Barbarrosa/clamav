#!/usr/bin/env python3
"""Generate bounded, source-linked native release notes; never publish.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import html
import json
from pathlib import Path
import re
import subprocess
import unicodedata
from urllib.parse import quote, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request


UPSTREAM = 'Cisco-Talos/clamav'
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_API_BYTES = 8 * 1024 * 1024
MAX_PAGES = 5
MAX_COMMITS = 100
SHA = re.compile(r'[0-9a-f]{40}')
REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*')
SEMVER = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
                    r'(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
                    r'(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?'
                    r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?')


def checked_repository(value):
    if not isinstance(value, str) or not REPOSITORY.fullmatch(value):
        raise ValueError('Expected an owner/repository identity')
    return value


def checked_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError('Full lowercase Git commit identities are required')
    return value


def checked_version(value):
    if not isinstance(value, str) or not SEMVER.fullmatch(value):
        raise ValueError('Expected an immutable semantic version')
    return value


def native_tag(tag):
    if not isinstance(tag, str):
        return False
    if tag.startswith('compact-v'):
        return SEMVER.fullmatch(tag[len('compact-v'):]) is not None
    if not tag.startswith('clamav-'):
        return False
    version = tag[len('clamav-'):]
    suffix = re.search(r'\+(?:[0-9A-Za-z-]+\.)*compact\.([1-9][0-9]*)$', version)
    return (SEMVER.fullmatch(version) is not None
            and suffix is not None and int(suffix[1]) <= 2**63 - 1)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate metadata key: ' + key)
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError('Invalid JSON constant: ' + value)

    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)


def validate_manifest(manifest, repository, tag=None):
    if not isinstance(manifest, dict):
        raise ValueError('Previous manifest must be an object')
    if manifest.get('repository') != repository:
        raise ValueError('Previous manifest repository differs')
    actual_tag = manifest.get('tag')
    if not native_tag(actual_tag) or (tag is not None and actual_tag != tag):
        raise ValueError('Previous manifest tag differs or is unsupported')
    version = checked_version(manifest.get('version'))
    prefix = 'clamav-' if actual_tag.startswith('clamav-') else 'compact-v'
    if actual_tag != prefix + version:
        raise ValueError('Previous manifest version and tag differ')
    checked_sha(manifest.get('integration_sha'))
    checked_sha(manifest.get('upstream_sha'))
    if prefix == 'clamav-':
        upstream_version = checked_version(manifest.get('upstream_version'))
        sequence = manifest.get('sequence')
        if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
            raise ValueError('Previous manifest requires a positive sequence')
        expected = upstream_version + ('.' if '+' in upstream_version else '+') + 'compact.' + str(sequence)
        if version != expected:
            raise ValueError('Previous manifest source version and fork sequence differ')
    return manifest


def manifest_url(repository, tag):
    return ('https://github.com/' + checked_repository(repository) + '/releases/download/'
            + quote(tag, safe='') + '/manifest.json')


class AssetRedirects(HTTPRedirectHandler):
    """GitHub releases redirect only to GitHub's HTTPS asset delivery hosts."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if (target.scheme != 'https' or target.hostname not in {
                'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
                or target.username or target.password or target.port not in (None, 443)
                or target.fragment):
            raise ValueError('Release asset redirected outside GitHub HTTPS delivery')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download_manifest(url, declared_size):
    if type(declared_size) is not int or not 0 < declared_size <= MAX_MANIFEST_BYTES:
        raise ValueError('Previous manifest asset size is missing or too large')
    request = Request(url, headers={'Accept': 'application/octet-stream',
                                    'User-Agent': 'clamav-compact-changelog'})
    with build_opener(AssetRedirects()).open(request, timeout=20) as response:
        data = response.read(MAX_MANIFEST_BYTES + 1)
    if len(data) != declared_size or len(data) > MAX_MANIFEST_BYTES:
        raise ValueError('Previous manifest asset size differs from release metadata')
    return strict_json(data)


def release_page(repository, page):
    endpoint = f'repos/{repository}/releases?per_page=10&page={page}'
    raw = subprocess.check_output(['gh', 'api', endpoint], timeout=30)
    if len(raw) > MAX_API_BYTES:
        raise ValueError('Release metadata response is too large')
    releases = strict_json(raw)
    if not isinstance(releases, list) or len(releases) > 10:
        raise ValueError('Expected a bounded page of GitHub releases')
    return releases


def previous_release(repository, current_tag):
    """Public metadata supplies a notes baseline, never an installation trust root."""
    checked_repository(repository)
    for page in range(1, MAX_PAGES + 1):
        releases = release_page(repository, page)
        for release in releases:
            if not isinstance(release, dict):
                raise ValueError('Malformed GitHub release metadata')
            tag = release.get('tag_name')
            if release.get('draft') is True or not native_tag(tag) or tag == current_tag:
                continue
            if release.get('draft') is not False or not release.get('published_at'):
                raise ValueError('Previous native release has no publication identity')
            assets = release.get('assets')
            if not isinstance(assets, list):
                raise ValueError('Previous native release has no asset metadata')
            matching = [asset for asset in assets if isinstance(asset, dict)
                        and asset.get('name') == 'manifest.json']
            if len(matching) != 1:
                raise ValueError('Previous native release requires one manifest asset')
            asset = matching[0]
            expected_url = manifest_url(repository, tag)
            if asset.get('browser_download_url') != expected_url:
                raise ValueError('Previous manifest asset URL differs from its release identity')
            return validate_manifest(download_manifest(expected_url, asset.get('size')), repository, tag)
        if len(releases) < 10:
            return None
    raise ValueError('No previous native release found within 50 releases; provide --previous-manifest')


def read_previous(path, repository):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError('Previous manifest is too large')
    return validate_manifest(strict_json(data), repository)


def git(checkout, *arguments):
    return subprocess.check_output(['git', '-C', str(checkout), *arguments],
                                   timeout=30, stderr=subprocess.PIPE)


def require_commit(checkout, sha):
    checked_sha(sha)
    try:
        git(checkout, 'cat-file', '-e', sha + '^{commit}')
    except subprocess.CalledProcessError as error:
        raise ValueError('Source commit is unavailable locally: ' + sha) from error


def commit_subjects(checkout, end, start=None, exclude=None):
    revision = checked_sha(end)
    if start:
        revision = checked_sha(start) + '..' + revision
    args = ['log', '-z', '--no-decorate', '--format=%H%x00%s', '--max-count=' + str(MAX_COMMITS + 1), revision]
    if exclude:
        args += ['--not', checked_sha(exclude)]
    args.append('--')
    fields = git(checkout, *args).decode('utf-8', errors='replace').split('\0')
    if fields[-1] != '' or len(fields) % 2 != 1:
        raise ValueError('Unexpected Git log output')
    pairs = list(zip(fields[0:-1:2], fields[1:-1:2]))
    commits = []
    for sha, subject in pairs[:MAX_COMMITS]:
        commits.append((checked_sha(sha), subject))
    return commits, len(pairs) > MAX_COMMITS


def safe_subject(subject):
    # Commit messages are untrusted text. Entities prevent mention/issue expansion;
    # Markdown punctuation and HTML cannot turn subjects into active page content.
    subject = ''.join(char for char in subject if not unicodedata.category(char).startswith('C'))
    subject = html.escape(subject, quote=False)
    subject = re.sub(r'([\\`*_\[\]()!>|])', r'\\\1', subject)
    return subject.replace('#', '&#35;').replace('@', '&#64;')


def commit_url(repository, sha):
    return 'https://github.com/' + repository + '/commit/' + sha


def compare_url(repository, start, end):
    return 'https://github.com/' + repository + '/compare/' + start + '...' + end


def change_section(title, commits, truncated, full_url, empty):
    lines = ['## ' + title, '']
    if commits:
        lines += ['- [' + sha[:12] + '](' + url + ') ' + safe_subject(subject)
                  for sha, subject, url in commits]
    else:
        lines.append(empty)
    if truncated:
        lines += ['', f'Showing the newest {MAX_COMMITS} commits; the complete range is linked below.']
    if full_url:
        lines += ['', '[Full comparison](' + full_url + ')']
    return lines


def generate(checkout, repository, commit, upstream_sha, version, previous=None):
    checked_repository(repository)
    checked_version(version)
    tag = 'clamav-' + version
    if not native_tag(tag):
        raise ValueError('New version must carry a compact.N build metadata qualifier')
    for sha in (commit, upstream_sha):
        require_commit(checkout, sha)
    if previous is not None:
        validate_manifest(previous, repository)
        for key in ('integration_sha', 'upstream_sha'):
            require_commit(checkout, previous[key])
    lines = ['# ' + tag, '', '## Release identity', '',
             '- Version: `' + version + '`',
             '- Upstream ClamAV: [' + upstream_sha + '](' + commit_url(UPSTREAM, upstream_sha) + ')',
             '- Fork integration: [' + commit + '](' + commit_url(repository, commit) + ')']
    if previous:
        previous_url = 'https://github.com/' + repository + '/releases/tag/' + quote(previous['tag'], safe='')
        lines += ['- Previous release: [' + previous['tag'] + '](' + previous_url + ')']
        upstream, truncated = commit_subjects(checkout, upstream_sha, previous['upstream_sha'])
        upstream_compare = compare_url(UPSTREAM, previous['upstream_sha'], upstream_sha)
        lines += ['', *change_section('Upstream changes',
            [(sha, subject, commit_url(UPSTREAM, sha)) for sha, subject in upstream], truncated,
            upstream_compare, 'The pinned upstream commit is unchanged.' if previous['upstream_sha'] == upstream_sha
            else 'No new upstream commits are reachable in this range.')]
    else:
        lines += ['', '## Upstream changes', '',
                  'Initial release: upstream history starts at the [pinned ClamAV commit]('
                  + commit_url(UPSTREAM, upstream_sha) + '). No earlier release baseline is available.']
    fork, truncated = commit_subjects(checkout, commit,
        previous['integration_sha'] if previous else None, exclude=upstream_sha)
    fork_compare = (compare_url(repository, previous['integration_sha'], commit) if previous
                    else compare_url(repository, upstream_sha, commit))
    lines += ['', *change_section('Fork and integration changes',
        [(sha, subject, commit_url(repository, sha)) for sha, subject in fork], truncated, fork_compare,
        'No new fork commits are reachable in this range.'), '',
        'Fork commit lists exclude commits reachable from the current upstream pin.', '',
        '## Qualification', '',
        'Experimental release. Consult the bundled qualification report for measured checks; '
        'SiteGround hosting and automatic disposition with reduced database profiles remain gated.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'commit', 'upstream-sha', 'version'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--checkout', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--previous-manifest', type=Path)
    args = parser.parse_args()
    try:
        checked_repository(args.repository)
        checked_sha(args.commit)
        checked_sha(args.upstream_sha)
        checked_version(args.version)
        previous = (read_previous(args.previous_manifest, args.repository) if args.previous_manifest
                    else previous_release(args.repository, 'clamav-' + args.version))
        notes = generate(args.checkout, args.repository, args.commit, args.upstream_sha, args.version, previous)
        args.output.write_text(notes, encoding='utf-8')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Changelog generation failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
