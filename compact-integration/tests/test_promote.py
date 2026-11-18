"""Publication boundaries: trusted runs, immutable releases, and channel authentication."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'release'))
try:
    SPEC = importlib.util.spec_from_file_location('native_promote', ROOT / 'release/promote.py')
    PROMOTE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(PROMOTE)
finally:
    sys.path.pop(0)
REPOSITORY = 'example/clamav'
COMMIT = 'a' * 40
RUN_ID = '123'
WORKFLOW = 'compact-native.yml'
VERSION = '1.6.0-devel-20261118+compact.7'
TAG = 'clamav-' + VERSION


def run_data():
    return {'status': 'completed', 'conclusion': 'success', 'event': 'push',
            'head_branch': 'upstream-optimized', 'head_repository': {'full_name': REPOSITORY},
            'path': '.github/workflows/' + WORKFLOW, 'head_sha': COMMIT,
            'run_number': 7, 'run_attempt': 2}


class QualificationTests(unittest.TestCase):
    def checked(self, run, job=None, jobs=None):
        answers = [json.dumps(run), json.dumps({'default_branch': 'upstream-optimized'})]
        if job is not None:
            answers.extend([json.dumps(jobs or {'total_count': 1, 'jobs': [
                {'name': 'qualification', 'status': 'completed', 'conclusion': 'success'}]})]
                           * run.get('run_attempt', 1))
        with mock.patch.object(PROMOTE, 'gh', side_effect=answers) as gh:
            result = PROMOTE.check_run(REPOSITORY, RUN_ID, WORKFLOW, job)
            return result, gh.call_args_list

    def test_manual_requires_successful_completed_trusted_run(self):
        self.assertEqual(self.checked(run_data())[0], COMMIT)
        for change in [{'event': 'pull_request'}, {'head_branch': 'feature'},
                       {'conclusion': 'failure'}, {'status': 'in_progress', 'conclusion': None},
                       {'head_repository': {'full_name': 'attacker/clamav'}},
                       {'path': '.github/workflows/other.yml'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.checked({**run_data(), **change})

    def test_auto_checks_successful_job_in_exact_current_attempt(self):
        run = {**run_data(), 'status': 'in_progress', 'conclusion': None}
        result, calls = self.checked(run, 'qualification')
        self.assertEqual(result, COMMIT)
        self.assertIn('/attempts/2/jobs?per_page=100', calls[-1].args[1])
        for jobs in [[], [{'name': 'qualification', 'status': 'completed', 'conclusion': 'failure'}],
                     [{'name': 'qualification', 'status': 'in_progress', 'conclusion': None}],
                     [{'name': 'qualification', 'status': 'completed', 'conclusion': 'success'}] * 2]:
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                self.checked(run, 'qualification', {'total_count': len(jobs), 'jobs': jobs})
        with self.assertRaises(ValueError):
            self.checked(run, 'qualification', {'total_count': 101, 'jobs': []})

    def test_only_http_404_means_missing(self):
        for message in ['gh: Forbidden (HTTP 403)', 'timeout', 'gh: Bad Gateway (HTTP 502)']:
            with self.subTest(message=message), mock.patch.object(PROMOTE, 'gh', side_effect=
                    subprocess.CalledProcessError(1, ['gh'], stderr=message)):
                with self.assertRaises(subprocess.CalledProcessError):
                    PROMOTE.api_optional('endpoint')
        with mock.patch.object(PROMOTE, 'gh', side_effect=
                subprocess.CalledProcessError(1, ['gh'], stderr='gh: Not Found (HTTP 404)')):
            self.assertIsNone(PROMOTE.api_optional('endpoint'))

    def test_draft_lookup_uses_numeric_id_when_tag_endpoint_returns_404(self):
        draft = {'id': 42, 'tag_name': TAG, 'draft': True, 'assets': []}
        with mock.patch.object(PROMOTE, 'api_optional', return_value=None) as tag_lookup, \
                mock.patch.object(PROMOTE, 'gh', side_effect=[json.dumps([draft]), json.dumps(draft)]) as gh:
            self.assertEqual(PROMOTE.find_release(REPOSITORY, TAG), draft)
        self.assertIn('%2Bcompact.7', tag_lookup.call_args.args[0])
        self.assertEqual(gh.call_args_list[-1].args, ('api', 'repos/' + REPOSITORY + '/releases/42'))

    def test_published_lookup_and_absent_or_inconsistent_drafts(self):
        release = {'id': 42, 'tag_name': TAG, 'draft': False}
        with mock.patch.object(PROMOTE, 'api_optional', return_value=release), \
                mock.patch.object(PROMOTE, 'gh') as gh:
            self.assertEqual(PROMOTE.find_release(REPOSITORY, TAG), release)
            gh.assert_not_called()
        with mock.patch.object(PROMOTE, 'api_optional', return_value=None), \
                mock.patch.object(PROMOTE, 'gh', return_value='[]'):
            self.assertIsNone(PROMOTE.find_release(REPOSITORY, TAG))
        with mock.patch.object(PROMOTE, 'api_optional', return_value=None), \
                mock.patch.object(PROMOTE, 'gh', side_effect=[json.dumps([release]),
                    json.dumps({**release, 'tag_name': 'different'})]):
            with self.assertRaisesRegex(ValueError, 'identity differs'):
                PROMOTE.find_release(REPOSITORY, TAG)

    def test_draft_lookup_pagination_is_bounded_and_metadata_errors_fail(self):
        unrelated = [{'id': i + 1, 'tag_name': 'other'} for i in range(100)]
        with mock.patch.object(PROMOTE, 'api_optional', return_value=None), \
                mock.patch.object(PROMOTE, 'gh', return_value=json.dumps(unrelated)) as gh:
            with self.assertRaisesRegex(ValueError, 'bounded'):
                PROMOTE.find_release(REPOSITORY, TAG)
            self.assertEqual(gh.call_count, 10)
        with mock.patch.object(PROMOTE, 'api_optional', return_value=None), \
                mock.patch.object(PROMOTE, 'gh', side_effect=subprocess.CalledProcessError(1, ['gh'])):
            with self.assertRaises(subprocess.CalledProcessError):
                PROMOTE.find_release(REPOSITORY, TAG)

    def test_publisher_only_retry_uses_latest_actual_qualification_without_hiding_failure(self):
        run = {**run_data(), 'status': 'in_progress', 'conclusion': None}
        base = [json.dumps(run), json.dumps({'default_branch': 'upstream-optimized'}),
                json.dumps({'total_count': 1, 'jobs': [{'name': 'publish-preview'}]})]
        for conclusion in ['success', 'failure']:
            answers = base + [json.dumps({'total_count': 1, 'jobs': [
                {'name': 'qualification', 'status': 'completed', 'conclusion': conclusion}]})]
            with mock.patch.object(PROMOTE, 'gh', side_effect=answers) as gh:
                if conclusion == 'success':
                    self.assertEqual(PROMOTE.check_run(REPOSITORY, RUN_ID, WORKFLOW, 'qualification'), COMMIT)
                else:
                    with self.assertRaisesRegex(ValueError, 'latest qualification'):
                        PROMOTE.check_run(REPOSITORY, RUN_ID, WORKFLOW, 'qualification')
                self.assertIn('/attempts/1/jobs?', gh.call_args.args[1])


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        changelog = '# ClamAV release\n\n## Upstream changes\n\n- Fixed scanning.\n'
        (self.root / 'CHANGELOG.md').write_text(changelog)
        self.manifest = {'protocol': 1, 'repository': REPOSITORY, 'integration_sha': COMMIT,
                         'upstream_sha': 'b' * 40, 'version': VERSION, 'tag': TAG,
                         'upstream_version': '1.6.0-devel-20261118', 'fork_revision': 7,
                         'sequence': 7, 'channel': 'preview',
                         'changelog_sha256': hashlib.sha256(changelog.encode()).hexdigest()}
        self.write_manifest()
        self.write_json('qualification.json', {'passed': True, 'integration_sha': COMMIT})
        self.write_json('provenance.json', {'source_complete': True, 'github_run_id': RUN_ID})
        self.write_json('sbom.spdx.json', {'spdxVersion': 'SPDX-2.3'})
        (self.root / ('clamav-' + VERSION + '-source.tar.gz')).write_bytes(b'complete source')
        (self.root / 'assets').mkdir()
        (self.root / 'assets' / 'native-binary').write_bytes(b'native payload')

    def write_json(self, name, content):
        (self.root / name).write_text(json.dumps(content) + '\n')

    def write_manifest(self):
        self.write_json('manifest.json', self.manifest)

    def content(self, unsigned=True, key=None):
        return PROMOTE.release_content(self.root, self.manifest, run_data(), RUN_ID, key, unsigned)

    def publish(self, api=(None, None), **kwargs):
        uploaded = {**self.public_release(), 'draft': True}
        with mock.patch.object(PROMOTE, 'trusted_run', return_value=run_data()), \
                mock.patch.object(PROMOTE, 'api_optional', return_value=api[0]) as optional, \
                mock.patch.object(PROMOTE, 'find_release', side_effect=[api[1], uploaded]), \
                mock.patch.object(PROMOTE, 'gh', return_value=json.dumps(uploaded)) as gh:
            PROMOTE.publish(REPOSITORY, RUN_ID, WORKFLOW, self.root,
                            allow_unsigned_preview=True, **kwargs)
            return optional.call_args_list, gh.call_args_list

    def tag(self, commit=COMMIT):
        return {'object': {'type': 'commit', 'sha': commit}}

    def public_release(self):
        notes, files = self.content()
        return {'draft': False, 'prerelease': True, 'tag_name': TAG, 'body': notes,
                'assets': [{'name': path.name, 'id': i + 1, 'size': path.stat().st_size}
                           for i, path in enumerate(files)]}

    def test_unsigned_requires_explicit_canonical_preview_and_absent_keys(self):
        with self.assertRaisesRegex(ValueError, 'Ed25519'):
            self.content(unsigned=False)
        with self.assertRaisesRegex(ValueError, 'Unsigned'):
            self.content(key='configured')
        (self.root / 'manifest.sig').write_bytes(b'x' * 64)
        with self.assertRaisesRegex(ValueError, 'Unsigned'):
            self.content()
        (self.root / 'manifest.sig').unlink()
        self.manifest['channel'] = 'stable'
        self.write_json('qualification.json', {'passed': True, 'integration_sha': COMMIT,
                                               'stable_release_qualified': True})
        with self.assertRaisesRegex(ValueError, 'Unsigned'):
            self.content()

    def test_changelog_and_source_are_bound_before_publication(self):
        notes, files = self.content()
        self.assertIn('Unsigned development prerelease', notes)
        self.assertIn('## Upstream changes', notes)
        self.assertIn('CHANGELOG.md', [path.name for path in files])
        self.assertTrue(any(path.name.endswith('-source.tar.gz') for path in files))
        (self.root / 'CHANGELOG.md').write_text('modified after qualification')
        with self.assertRaisesRegex(ValueError, 'exact qualified changelog'):
            self.publish()

    def test_version_sequence_run_and_provenance_cannot_be_substituted(self):
        original = dict(self.manifest)
        for change in [{'tag': 'clamav-1.6.0+compact.7'}, {'sequence': 8}, {'fork_revision': 8},
                       {'upstream_version': '1.5.0'}, {'integration_sha': 'c' * 40},
                       {'repository': 'attacker/clamav'}]:
            self.manifest = {**original, **change}
            self.write_manifest()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.publish()
        self.manifest = original
        self.write_manifest()
        self.write_json('provenance.json', {'source_complete': True, 'github_run_id': '456'})
        with self.assertRaisesRegex(ValueError, 'another qualification run'):
            self.content()

    def test_failed_qualification_incomplete_source_and_stable_gate_fail(self):
        for report in [{'passed': False, 'integration_sha': COMMIT},
                       {'passed': True, 'integration_sha': 'c' * 40}]:
            self.write_json('qualification.json', report)
            with self.assertRaisesRegex(ValueError, 'Successful qualification'):
                self.content()
        self.write_json('qualification.json', {'passed': True, 'integration_sha': COMMIT})
        self.write_json('provenance.json', {'source_complete': False, 'github_run_id': RUN_ID})
        with self.assertRaisesRegex(ValueError, 'complete corresponding source'):
            self.content()

    def test_new_release_is_draft_until_all_assets_uploaded_and_uses_encoded_api_tag(self):
        optional, calls = self.publish()
        self.assertTrue(all('%2Bcompact.7' in call.args[0] for call in optional))
        commands = [call.args for call in calls]
        self.assertEqual(commands[0][0:3], ('api', '--method', 'POST'))
        self.assertIn('ref=refs/tags/' + TAG, commands[0])
        self.assertEqual(commands[1][0:2], ('release', 'create'))
        self.assertIn('--draft', commands[1])
        self.assertIn('--prerelease', commands[1])
        self.assertEqual(commands[2][0:2], ('release', 'upload'))
        self.assertEqual(commands[3][0:2], ('release', 'edit'))
        self.assertIn('--draft=false', commands[3])
        self.assertFalse((self.root / 'release-notes.txt').exists())

    def test_draft_resume_does_not_recreate_tag_or_release(self):
        _, calls = self.publish(api=(self.tag(), {'draft': True, 'tag_name': TAG}))
        self.assertEqual([call.args[0] for call in calls], ['release', 'release'])
        self.assertEqual(calls[0].args[1], 'upload')
        self.assertEqual(calls[-1].args[1], 'edit')

    def test_published_rerun_is_noop_only_with_identical_metadata(self):
        release = self.public_release()
        with mock.patch.object(PROMOTE, 'asset_bytes', side_effect=
                lambda repository, asset: next(path.read_bytes() for path in self.root.rglob('*')
                                                if path.is_file() and path.name == asset['name'])):
            _, calls = self.publish(api=(self.tag(), release))
        self.assertEqual(calls, [])
        with mock.patch.object(PROMOTE, 'asset_bytes', return_value=b'other manifest'):
            with self.assertRaisesRegex(ValueError, 'immutable'):
                self.publish(api=(self.tag(), release))

    def test_published_asset_inventory_body_and_channel_are_immutable(self):
        for change in [{'assets': []}, {'body': 'edited'}, {'prerelease': False}]:
            release = {**self.public_release(), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.publish(api=(self.tag(), release))

    def test_existing_tag_cannot_move(self):
        with self.assertRaisesRegex(ValueError, 'points elsewhere'):
            self.publish(api=(self.tag('c' * 40), None))

    def test_draft_extra_assets_are_rejected_before_upload(self):
        draft = {'draft': True, 'tag_name': TAG, 'assets': [{'name': 'manifest.sig', 'size': 64}]}
        with mock.patch.object(PROMOTE, 'gh') as gh, self.assertRaisesRegex(ValueError, 'unexpected'):
            self.publish(api=(self.tag(), draft))
            gh.assert_not_called()

    def test_uploaded_inventory_and_asset_digests_must_match(self):
        _, files = self.content()
        draft = {**self.public_release(), 'draft': True}
        for asset in draft['assets']:
            path = next(path for path in files if path.name == asset['name'])
            asset['digest'] = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
        PROMOTE.verify_draft_inventory(draft, files, complete=True)
        draft['assets'][0]['digest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            PROMOTE.verify_draft_inventory(draft, files, complete=True)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            PROMOTE.verify_draft_inventory({**draft, 'assets': []}, files, complete=True)

    def test_partial_upload_cannot_publish_release(self):
        def gh(*args):
            if args[0:2] == ('release', 'upload'):
                raise subprocess.CalledProcessError(1, ['gh'], stderr='upload interrupted')
            return ''
        with mock.patch.object(PROMOTE, 'trusted_run', return_value=run_data()), \
                mock.patch.object(PROMOTE, 'api_optional', return_value=None), \
                mock.patch.object(PROMOTE, 'find_release', return_value=None), \
                mock.patch.object(PROMOTE, 'gh', side_effect=gh) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                PROMOTE.publish(REPOSITORY, RUN_ID, WORKFLOW, self.root, allow_unsigned_preview=True)
            self.assertFalse(any(call.args[0:2] == ('release', 'edit') for call in command.call_args_list))

    def test_legacy_signed_manual_candidate_remains_supported(self):
        self.manifest.update({'version': '0.1.1', 'tag': 'compact-v0.1.1'})
        self.manifest.pop('changelog_sha256')
        (self.root / 'CHANGELOG.md').unlink()
        (self.root / 'manifest.sig').write_bytes(b'x' * 64)
        with mock.patch.object(PROMOTE, 'verify_signature') as verify:
            notes, files = self.content(unsigned=False, key='channel public key')
        verify.assert_called_once_with(self.root, 'channel public key')
        self.assertIn('Experimental 0.1.1', notes)
        with self.assertRaisesRegex(ValueError, 'Unsigned'):
            self.content()

    @unittest.skipUnless(shutil.which('php'), 'PHP sodium available in release CI builder')
    def test_real_ed25519_signature_verification_and_tampering(self):
        secret = subprocess.check_output(['php', '-r',
            '$p=sodium_crypto_sign_keypair();echo base64_encode(sodium_crypto_sign_secretkey($p));']).decode()
        public = subprocess.check_output(['php', '-r',
            'echo base64_encode(sodium_crypto_sign_publickey_from_secretkey(base64_decode($argv[1])));',
            secret]).decode()
        signature = subprocess.check_output(['php', '-r',
            'echo sodium_crypto_sign_detached(file_get_contents($argv[1]),base64_decode($argv[2]));',
            str(self.root / 'manifest.json'), secret])
        (self.root / 'manifest.sig').write_bytes(signature)
        PROMOTE.verify_signature(self.root, public)
        (self.root / 'manifest.json').write_bytes(b'tampered')
        with self.assertRaises(subprocess.CalledProcessError):
            PROMOTE.verify_signature(self.root, public)
        with self.assertRaises(subprocess.CalledProcessError):
            PROMOTE.verify_signature(self.root, base64.b64encode(b'short').decode())


if __name__ == '__main__':
    unittest.main()
