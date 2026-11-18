"""Exercise interrupted upstream proposals with real local Git repositories.

Only the GitHub CLI boundary is simulated. Branch creation, commit identity,
fetching, divergence, and push behavior use temporary repositories, never network.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('track_upstream_under_test', ROOT / 'release/track_upstream.py')
TRACKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRACKER)


class UpstreamTrackingTests(unittest.TestCase):
    repository = 'example/native'
    manifest_path = 'compact-integration/manifest.json'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='compact-upstream-recovery-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.date = '2020-01-01T00:00:00+00:00'
        self.upstream = self.root / 'upstream'
        self.origin = self.root / 'origin.git'
        self.seed = self.root / 'seed'
        self.git('init', '--quiet', '-b', 'main', str(self.upstream))
        self.identity(self.upstream)
        (self.upstream / 'source.txt').write_text('old upstream\n')
        self.commit(self.upstream, 'Old upstream')
        self.previous = self.git('-C', str(self.upstream), 'rev-parse', 'HEAD')
        (self.upstream / 'source.txt').write_text('new upstream\n')
        self.commit(self.upstream, 'New upstream')
        self.target = self.git('-C', str(self.upstream), 'rev-parse', 'HEAD')
        self.branch = 'automation/upstream-' + self.target[:12]
        self.manifest = {
            'protocol': 1,
            'integration_version': '0.1.1',
            'upstream_repository': str(self.upstream),
            'upstream_commit': self.previous,
            'patches': [{'file': 'patches/010.patch', 'sha256': 'a' * 64}],
            'default_options': {'ENABLE_AC_FLAT_NODES': 'ON'},
            'qualification': {'status': 'relative-qualified-experimental',
                              'coverage_qualified': True, 'siteground_qualified': False},
        }
        self.git('init', '--quiet', '--bare', '-b', 'main', str(self.origin))
        self.git('init', '--quiet', '-b', 'main', str(self.seed))
        self.identity(self.seed)
        (self.seed / 'compact-integration').mkdir()
        self.write_manifest(self.seed, self.manifest)
        (self.seed / 'README').write_text('integration checkout\n')
        self.commit(self.seed, 'Initial integration')
        self.git('-C', str(self.seed), 'remote', 'add', 'origin', str(self.origin))
        self.git('-C', str(self.seed), 'push', '--quiet', 'origin', 'main')
        self.base = self.remote_head('main')
        self.prs = []
        self.runs = []
        self.calls = []
        self.pr_failures = 0
        self.dispatch_failures = 0
        self.created_prs = 0
        self.dispatch_attempts = 0
        self.dispatches = 0
        self.body_paths = []
        self.bodies = []
        self.clones = 0

    def environment(self):
        return dict(os.environ, GIT_AUTHOR_DATE=self.date, GIT_COMMITTER_DATE=self.date,
                    GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')

    def git(self, *arguments):
        return subprocess.check_output(['git', *arguments], text=True, env=self.environment(),
                                       stderr=subprocess.DEVNULL).strip()

    def identity(self, checkout):
        self.git('-C', str(checkout), 'config', 'user.name', 'Upstream fixture')
        self.git('-C', str(checkout), 'config', 'user.email', 'fixture@example.test')

    def commit(self, checkout, message):
        self.git('-C', str(checkout), 'add', '.')
        self.git('-C', str(checkout), 'commit', '--quiet', '-m', message)

    def fresh_checkout(self):
        self.clones += 1
        path = self.root / ('run-' + str(self.clones))
        self.git('clone', '--quiet', str(self.origin), str(path))
        self.identity(path)
        return path

    def write_manifest(self, checkout, manifest):
        (checkout / self.manifest_path).write_text(json.dumps(manifest, indent=2) + '\n')

    def remote_head(self, branch=None):
        return self.git('--git-dir', str(self.origin), 'rev-parse', branch or self.branch)

    @staticmethod
    def option(arguments, name):
        return arguments[arguments.index(name) + 1]

    def command(self, *arguments):
        self.calls.append(arguments)
        if arguments[0] == 'git':
            self.assertEqual(arguments[1], '-C', 'Every tracker Git operation has an explicit checkout')
            self.assertNotIn('--force', arguments)
            self.assertNotIn('--force-with-lease', arguments)
            return self.git(*arguments[1:])
        self.assertEqual(arguments[0], 'gh')
        if arguments[1:3] == ('api', 'repos/Cisco-Talos/clamav/branches/main'):
            return json.dumps({'commit': {'sha': self.target}})
        if arguments[1:3] == ('api', 'repos/' + self.repository):
            return json.dumps({'default_branch': 'main'})
        if arguments[1:3] == ('pr', 'list'):
            self.assertEqual(self.option(arguments, '--state'), 'open')
            return json.dumps(self.prs)
        if arguments[1:3] == ('auth', 'setup-git'):
            return ''
        if arguments[1:3] == ('pr', 'create'):
            self.assertEqual(self.option(arguments, '--base'), 'main')
            self.assertEqual(self.option(arguments, '--head'), self.branch)
            body_path = Path(self.option(arguments, '--body-file'))
            self.body_paths.append(body_path)
            self.bodies.append(body_path.read_text())
            if self.pr_failures:
                self.pr_failures -= 1
                raise subprocess.CalledProcessError(1, list(arguments), stderr='PR creation denied')
            self.created_prs += 1
            self.prs = [{'number': 7, 'url': 'https://github.com/example/native/pull/7',
                         'baseRefName': 'main', 'headRefOid': self.remote_head()}]
            return self.prs[0]['url']
        if arguments[1:3] == ('run', 'list'):
            self.assertEqual(self.option(arguments, '--workflow'), 'compact-native.yml')
            self.assertEqual(self.option(arguments, '--branch'), self.branch)
            self.assertEqual(self.option(arguments, '--commit'), self.remote_head())
            return json.dumps(self.runs)
        if arguments[1:3] == ('workflow', 'run'):
            self.assertEqual(arguments[3], 'compact-native.yml')
            self.assertEqual(self.option(arguments, '--ref'), self.branch)
            self.dispatch_attempts += 1
            if self.dispatch_failures:
                self.dispatch_failures -= 1
                raise subprocess.CalledProcessError(1, list(arguments), stderr='Dispatch unavailable')
            self.dispatches += 1
            self.runs.append({'headSha': self.remote_head(), 'status': 'queued', 'conclusion': ''})
            return ''
        self.fail('Unexpected command: ' + repr(arguments))

    def track(self, checkout):
        with mock.patch.object(TRACKER, 'run', side_effect=self.command):
            TRACKER.track(checkout / 'compact-integration', self.repository)

    def orphan(self):
        self.pr_failures = 1
        checkout = self.fresh_checkout()
        with self.assertRaises(subprocess.CalledProcessError):
            self.track(checkout)
        self.assertEqual(self.prs, [])
        self.assertEqual(self.dispatch_attempts, 0)
        return checkout, self.remote_head()

    def test_unchanged_upstream_does_not_touch_git_or_create_work(self):
        self.target = self.previous
        checkout = self.fresh_checkout()
        before = self.git('-C', str(checkout), 'rev-parse', 'HEAD')
        self.track(checkout)
        self.assertEqual(self.calls, [('gh', 'api', 'repos/Cisco-Talos/clamav/branches/main')])
        self.assertEqual(self.git('-C', str(checkout), 'rev-parse', 'HEAD'), before)

    def test_pr_permission_failure_recovers_the_exact_already_pushed_commit(self):
        _, proposal = self.orphan()
        self.date = '2020-02-01T00:00:00+00:00'
        self.calls = []
        self.track(self.fresh_checkout())
        self.assertEqual(self.remote_head(), proposal)
        self.assertEqual(self.remote_head('main'), self.base)
        self.assertEqual(self.created_prs, 1)
        self.assertEqual(self.dispatches, 1)
        self.assertFalse(any(args[0] == 'git' and ('commit' in args or 'push' in args) for args in self.calls))
        candidate = json.loads(self.git('--git-dir', str(self.origin), 'show', proposal + ':' + self.manifest_path))
        self.assertEqual(candidate['upstream_commit'], self.target)
        self.assertEqual(candidate['patches'], self.manifest['patches'])
        self.assertEqual(candidate['qualification'], {'status': 'pending', 'coverage_qualified': False,
                                                       'siteground_qualified': False})
        self.assertTrue(all(not path.exists() for path in self.body_paths))
        self.assertIn(self.previous, self.bodies[-1])
        self.assertIn(self.target, self.bodies[-1])
        self.assertIn('\n\n', self.bodies[-1])

    def test_existing_pr_recovers_a_failed_qualification_dispatch(self):
        self.dispatch_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.track(self.fresh_checkout())
        proposal = self.remote_head()
        self.assertEqual(self.created_prs, 1)
        self.assertEqual(self.dispatches, 0)
        self.calls = []
        self.track(self.fresh_checkout())
        self.assertEqual(self.remote_head(), proposal)
        self.assertEqual(self.created_prs, 1)
        self.assertEqual(self.dispatch_attempts, 2)
        self.assertEqual(self.dispatches, 1)

    def test_active_or_successful_qualification_is_not_dispatched_again(self):
        self.track(self.fresh_checkout())
        for status, conclusion in [('queued', ''), ('in_progress', ''), ('waiting', ''), ('completed', 'success')]:
            with self.subTest(status=status, conclusion=conclusion):
                self.runs = [{'headSha': self.remote_head(), 'status': status, 'conclusion': conclusion}]
                self.track(self.fresh_checkout())
                self.assertEqual(self.dispatch_attempts, 1)
                self.assertEqual(self.created_prs, 1)

    def test_failed_or_cancelled_qualification_can_be_retried(self):
        self.track(self.fresh_checkout())
        for conclusion in ['failure', 'cancelled', 'timed_out']:
            with self.subTest(conclusion=conclusion):
                before = self.dispatch_attempts
                self.runs = [{'headSha': self.remote_head(), 'status': 'completed', 'conclusion': conclusion}]
                self.track(self.fresh_checkout())
                self.assertEqual(self.dispatch_attempts, before + 1)
                self.assertEqual(self.created_prs, 1)

    def test_a_different_commit_success_does_not_suppress_qualification(self):
        self.track(self.fresh_checkout())
        self.runs = [{'headSha': self.previous, 'status': 'completed', 'conclusion': 'success'}]
        self.track(self.fresh_checkout())
        self.assertEqual(self.dispatches, 2)

    def assert_modified_orphan_is_rejected(self, mutate):
        checkout, _ = self.orphan()
        self.date = '2020-03-01T00:00:00+00:00'
        mutate(checkout)
        self.commit(checkout, 'Manual branch change')
        self.git('-C', str(checkout), 'push', '--quiet', 'origin', self.branch)
        changed = self.remote_head()
        self.calls = []
        with self.assertRaises((ValueError, RuntimeError)):
            self.track(self.fresh_checkout())
        self.assertEqual(self.remote_head(), changed)
        self.assertEqual(self.created_prs, 0)
        self.assertEqual(self.dispatches, 0)
        self.assertFalse(any(args[0] == 'git' and 'push' in args for args in self.calls))

    def test_orphan_with_another_target_is_preserved_and_rejected(self):
        def mutate(checkout):
            value = json.loads((checkout / self.manifest_path).read_text())
            value['upstream_commit'] = 'f' * 40
            self.write_manifest(checkout, value)
        self.assert_modified_orphan_is_rejected(mutate)

    def test_orphan_with_changed_patch_identity_is_preserved_and_rejected(self):
        def mutate(checkout):
            value = json.loads((checkout / self.manifest_path).read_text())
            value['patches'][0]['sha256'] = 'b' * 64
            self.write_manifest(checkout, value)
        self.assert_modified_orphan_is_rejected(mutate)

    def test_orphan_cannot_restore_a_qualification_claim(self):
        def mutate(checkout):
            value = json.loads((checkout / self.manifest_path).read_text())
            value['qualification']['coverage_qualified'] = True
            self.write_manifest(checkout, value)
        self.assert_modified_orphan_is_rejected(mutate)

    def test_orphan_with_an_unexpected_file_is_preserved_and_rejected(self):
        self.assert_modified_orphan_is_rejected(lambda checkout: (checkout / 'manual-adaptation').write_text('keep this\n'))

    def test_default_branch_advance_does_not_invalidate_an_unmodified_proposal(self):
        _, proposal = self.orphan()
        self.date = '2020-04-01T00:00:00+00:00'
        (self.seed / 'tracker-fix').write_text('new default branch code\n')
        self.commit(self.seed, 'Fix tracker on default branch')
        self.git('-C', str(self.seed), 'push', '--quiet', 'origin', 'main')
        advanced = self.remote_head('main')
        self.assertNotEqual(advanced, self.base)
        self.track(self.fresh_checkout())
        self.assertEqual(self.remote_head(), proposal)
        self.assertEqual(self.remote_head('main'), advanced)
        self.assertEqual(self.created_prs, 1)
        self.assertEqual(self.dispatches, 1)

    def test_existing_pr_keeps_manual_adaptation_and_qualifies_the_new_head(self):
        checkout = self.fresh_checkout()
        self.track(checkout)
        old = self.remote_head()
        self.date = '2020-05-01T00:00:00+00:00'
        (checkout / 'manual-adaptation').write_text('reviewed patch work\n')
        self.commit(checkout, 'Adapt existing PR')
        self.git('-C', str(checkout), 'push', '--quiet', 'origin', self.branch)
        updated = self.remote_head()
        self.assertNotEqual(old, updated)
        self.prs[0]['headRefOid'] = updated
        self.runs = [{'headSha': old, 'status': 'completed', 'conclusion': 'success'}]
        self.calls = []
        self.track(self.fresh_checkout())
        self.assertEqual(self.remote_head(), updated)
        self.assertEqual(self.dispatches, 2)
        self.assertEqual(self.created_prs, 1)
        self.assertFalse(any(args[0] == 'git' and ('commit' in args or 'push' in args) for args in self.calls))


if __name__ == '__main__':
    unittest.main()
