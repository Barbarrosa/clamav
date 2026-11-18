"""Verify release notes against real Git histories and bounded read-only metadata.
SPDX-License-Identifier: GPL-2.0-only
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from urllib.request import Request


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('changelog_under_test', ROOT / 'release/changelog.py')
CHANGELOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHANGELOG)


class ChangelogHistoryTests(unittest.TestCase):
    repository = 'example/native'
    version = '1.6.0-devel-20261118+compact.4'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='compact-changelog-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root / 'checkout'
        self.git('init', '--quiet', '-b', 'upstream', str(self.checkout), outside=True)
        self.git('config', 'user.name', 'Release fixture')
        self.git('config', 'user.email', 'fixture@example.test')
        self.original = self.commit('Initial upstream')
        self.upstream = self.commit('Upstream correctness fix')
        self.git('checkout', '--quiet', '-b', 'integration', self.original)
        self.old_fork = self.commit('Initial fork optimization')
        self.git('merge', '--quiet', '--no-ff', '-m', 'Refresh upstream pin', self.upstream)
        self.merge = self.git('rev-parse', 'HEAD')
        self.integration = self.commit('Fork resource tuning')
        self.previous = {'repository': self.repository, 'tag': 'compact-v0.1.1', 'version': '0.1.1',
                         'integration_sha': self.old_fork, 'upstream_sha': self.original}

    def git(self, *arguments, outside=False):
        command = ['git'] if outside else ['git', '-C', str(self.checkout)]
        return subprocess.check_output(command + list(arguments), text=True,
            env=dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0'),
            stderr=subprocess.DEVNULL).strip()

    def commit(self, subject):
        self.git('commit', '--quiet', '--allow-empty', '-m', subject)
        return self.git('rev-parse', 'HEAD')

    def generate(self, previous=None, **changes):
        args = dict(checkout=self.checkout, repository=self.repository, commit=self.integration,
                    upstream_sha=self.upstream, version=self.version, previous=previous)
        args.update(changes)
        return CHANGELOG.generate(**args)

    def test_real_ranges_separate_upstream_and_fork_history(self):
        notes = self.generate(self.previous)
        upstream, fork = notes.split('## Upstream changes\n', 1)[1].split('## Fork and integration changes\n')
        self.assertIn('Upstream correctness fix', upstream)
        self.assertNotIn('Fork resource tuning', upstream)
        self.assertIn('Fork resource tuning', fork)
        self.assertIn('Refresh upstream pin', fork)
        self.assertNotIn('Upstream correctness fix', fork)
        self.assertNotIn('Initial fork optimization', fork)
        self.assertIn(f'Cisco-Talos/clamav/compare/{self.original}...{self.upstream}', upstream)
        self.assertIn(f'{self.repository}/compare/{self.old_fork}...{self.integration}', fork)
        self.assertIn('SiteGround hosting', notes)
        self.assertIn('remain gated', notes)

    def test_initial_release_uses_pin_without_invented_upstream_history(self):
        notes = self.generate()
        self.assertIn('Initial release: upstream history starts at the', notes)
        self.assertNotIn('Upstream correctness fix', notes)
        self.assertIn('Initial fork optimization', notes)
        self.assertIn('Fork resource tuning', notes)
        self.assertIn(f'{self.repository}/compare/{self.upstream}...{self.integration}', notes)
        self.assertNotIn('Previous release:', notes)

    def test_unchanged_upstream_and_fork_are_explicit(self):
        previous = dict(self.previous, upstream_sha=self.upstream, integration_sha=self.integration)
        notes = self.generate(previous)
        self.assertIn('The pinned upstream commit is unchanged.', notes)
        self.assertIn('No new fork commits are reachable', notes)

    def test_fork_subjects_cannot_inject_markdown_html_mentions_or_controls(self):
        integration = self.commit('Bad [link](https://evil.test) <img> @someone #12 `code` *bold*\t\u202e end')
        notes = self.generate(self.previous, commit=integration)
        self.assertIn(r'\[link\]\(https://evil.test\)', notes)
        self.assertIn('&lt;img&gt;', notes)
        self.assertIn('&#64;someone &#35;12', notes)
        self.assertIn(r'\`code\` \*bold\*', notes)
        self.assertNotIn('\u202e', notes)
        self.assertNotIn('\t', notes)
        self.assertNotIn('<img>', notes)
        self.assertNotIn('@someone', notes)

    def test_commit_lists_are_bounded_and_link_complete_range(self):
        for index in range(102):
            self.integration = self.commit('Bounded fork ' + str(index))
        notes = self.generate(self.previous)
        fork = notes.split('## Fork and integration changes\n', 1)[1]
        self.assertEqual(sum(line.startswith('- [') for line in fork.splitlines()), 100)
        self.assertIn('Showing the newest 100 commits', fork)
        self.assertIn('Bounded fork 101', fork)
        self.assertNotIn('Bounded fork 0\n', fork)
        self.assertIn(f'{self.old_fork}...{self.integration}', fork)

    def test_unavailable_baseline_source_fails(self):
        with self.assertRaisesRegex(ValueError, 'unavailable locally'):
            self.generate(dict(self.previous, upstream_sha='f' * 40))

    def test_new_version_requires_fork_build_metadata(self):
        for version in ('1.6.0', '1.6.0-compact.4', '1.6.0+compact.0', '1.6.0+compact.9223372036854775808'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.generate(version=version)
        self.assertIn('1.6.0+vendor.2.compact.4', self.generate(version='1.6.0+vendor.2.compact.4'))

    def test_offline_cli_reads_manifest_and_writes_only_requested_notes(self):
        previous_path = self.root / 'manifest.json'
        previous_path.write_text(json.dumps(self.previous))
        output = self.root / 'CHANGELOG.md'
        argv = ['changelog.py', '--repository', self.repository, '--commit', self.integration,
                '--upstream-sha', self.upstream, '--version', self.version, '--checkout', str(self.checkout),
                '--previous-manifest', str(previous_path), '--output', str(output)]
        before = self.git('status', '--porcelain')
        with mock.patch('sys.argv', argv), mock.patch.object(CHANGELOG, 'previous_release') as discovery:
            CHANGELOG.main()
        discovery.assert_not_called()
        self.assertEqual(output.read_text(), self.generate(self.previous))
        self.assertEqual(self.git('status', '--porcelain'), before)


class ChangelogMetadataTests(unittest.TestCase):
    repository = 'example/native'
    tag = 'clamav-1.6.0-devel-20261118+compact.3'

    def setUp(self):
        self.manifest = {'repository': self.repository, 'tag': self.tag,
                         'version': self.tag[len('clamav-'):], 'upstream_version': '1.6.0-devel-20261118',
                         'sequence': 3, 'integration_sha': 'a' * 40, 'upstream_sha': 'b' * 40}
        self.data = json.dumps(self.manifest).encode()
        self.release = {'tag_name': self.tag, 'draft': False, 'published_at': '2026-11-18T12:00:00Z',
                        'assets': [{'name': 'manifest.json', 'size': len(self.data),
                                    'browser_download_url': CHANGELOG.manifest_url(self.repository, self.tag)}]}

    def test_fixed_encoded_origin_and_published_native_baseline(self):
        skipped = [{'tag_name': self.tag, 'draft': True}, {'tag_name': 'other-project-v1.0.0', 'draft': False}]
        with mock.patch.object(CHANGELOG, 'release_page', return_value=skipped + [self.release]), \
                mock.patch.object(CHANGELOG, 'download_manifest', return_value=self.manifest) as download:
            actual = CHANGELOG.previous_release(self.repository, 'clamav-1.6.0+compact.4')
        self.assertEqual(actual, self.manifest)
        download.assert_called_once_with(
            'https://github.com/example/native/releases/download/clamav-1.6.0-devel-20261118%2Bcompact.3/manifest.json',
            len(self.data))

    def test_current_release_is_skipped_on_rerun(self):
        with mock.patch.object(CHANGELOG, 'release_page', return_value=[self.release]), \
                mock.patch.object(CHANGELOG, 'download_manifest') as download:
            self.assertIsNone(CHANGELOG.previous_release(self.repository, self.tag))
        download.assert_not_called()

    def test_absent_previous_releases_is_initial_release(self):
        with mock.patch.object(CHANGELOG, 'release_page', return_value=[]):
            self.assertIsNone(CHANGELOG.previous_release(self.repository, self.tag))

    def test_pagination_is_bounded_and_does_not_claim_initial_after_fifty(self):
        with mock.patch.object(CHANGELOG, 'release_page', return_value=[{'tag_name': 'unrelated'}] * 10) as page:
            with self.assertRaisesRegex(ValueError, 'within 50'):
                CHANGELOG.previous_release(self.repository, self.tag)
        self.assertEqual(page.call_count, 5)
        self.assertEqual(page.call_args_list[-1], mock.call(self.repository, 5))

    def test_discovery_uses_only_read_only_gh_api(self):
        with mock.patch.object(CHANGELOG.subprocess, 'check_output', return_value=b'[]') as command:
            self.assertEqual(CHANGELOG.release_page(self.repository, 2), [])
        command.assert_called_once_with(['gh', 'api', 'repos/example/native/releases?per_page=10&page=2'], timeout=30)

    def test_api_failure_propagates_instead_of_empty_notes(self):
        with mock.patch.object(CHANGELOG, 'release_page', side_effect=subprocess.CalledProcessError(1, ['gh'])):
            with self.assertRaises(subprocess.CalledProcessError):
                CHANGELOG.previous_release(self.repository, 'clamav-1.6.0+compact.4')

    def test_unexpected_asset_origin_and_missing_asset_fail(self):
        mutations = [[], [dict(self.release['assets'][0], browser_download_url='https://evil.test/manifest.json')],
                     self.release['assets'] * 2]
        for assets in mutations:
            with self.subTest(assets=assets), \
                    mock.patch.object(CHANGELOG, 'release_page', return_value=[dict(self.release, assets=assets)]), \
                    mock.patch.object(CHANGELOG, 'download_manifest') as download:
                with self.assertRaises(ValueError):
                    CHANGELOG.previous_release(self.repository, 'clamav-1.6.0+compact.4')
                download.assert_not_called()

    def test_manifest_identity_is_validated(self):
        changes = [{'repository': 'other/native'}, {'tag': 'compact-v9.0.0'}, {'version': '9.0.0'},
                   {'upstream_sha': 'b' * 39}, {'integration_sha': '--all'}, {'sequence': True},
                   {'sequence': 2}, {'sequence': 2**63}, {'upstream_version': '1.5.0'}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                CHANGELOG.validate_manifest(dict(self.manifest, **change), self.repository, self.tag)

    def test_legacy_baseline_is_supported_without_upstream_version(self):
        legacy = dict(self.manifest, tag='compact-v0.1.1', version='0.1.1')
        del legacy['upstream_version']
        self.assertEqual(CHANGELOG.validate_manifest(legacy, self.repository), legacy)

    def test_duplicate_json_and_nonfinite_numbers_fail(self):
        for payload in ('{"version":"1", "version":"2"}', '{"sequence":NaN}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                CHANGELOG.strict_json(payload)

    def test_download_has_timeout_actual_and_declared_size_limits(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = self.data
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(CHANGELOG, 'build_opener', return_value=opener):
            self.assertEqual(CHANGELOG.download_manifest('https://github.com/test', len(self.data)), self.manifest)
            response.__enter__.return_value.read.assert_called_once_with(CHANGELOG.MAX_MANIFEST_BYTES + 1)
            self.assertEqual(opener.open.call_args.kwargs, {'timeout': 20})
        for size in (0, True, CHANGELOG.MAX_MANIFEST_BYTES + 1):
            with self.subTest(size=size), mock.patch.object(CHANGELOG, 'build_opener') as build:
                with self.assertRaises(ValueError):
                    CHANGELOG.download_manifest('https://github.com/test', size)
                build.assert_not_called()
        with mock.patch.object(CHANGELOG, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, 'size differs'):
                CHANGELOG.download_manifest('https://github.com/test', len(self.data) + 1)

    def test_unexpected_redirect_targets_are_rejected(self):
        handler = CHANGELOG.AssetRedirects()
        for target in ('http://github.com/file', 'https://evil.test/file', 'https://github.com:8443/file',
                       'https://user:password@github.com/file', 'https://github.com/file#fragment'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.redirect_request(Request('https://github.com/source'), None, 302, 'Found', {}, target)
        redirected = handler.redirect_request(Request('https://github.com/source'), None, 302, 'Found', {},
                                               'https://release-assets.githubusercontent.com/object?signature=abc')
        self.assertEqual(redirected.host, 'release-assets.githubusercontent.com')

    def test_metadata_bounds_and_source_arguments_fail_closed(self):
        for value in ('../private', 'example/native?token=bad', 'https://github.com/example/native'):
            with self.subTest(repository=value), self.assertRaises(ValueError):
                CHANGELOG.checked_repository(value)
        with mock.patch.object(CHANGELOG.subprocess, 'check_output', return_value=b'[' + b' ' * CHANGELOG.MAX_API_BYTES):
            with self.assertRaisesRegex(ValueError, 'too large'):
                CHANGELOG.release_page(self.repository, 1)
        with mock.patch.object(CHANGELOG.subprocess, 'check_output', return_value=b'{}'):
            with self.assertRaises(ValueError):
                CHANGELOG.release_page(self.repository, 1)


if __name__ == '__main__':
    unittest.main()
