"""Release boundary checks: exact bytes, transport traversal, and signing keys."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_verify', ROOT / 'release/verify_candidate.py')
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
sys.path.insert(0, str(ROOT / 'release'))
try:
    PACKAGE_SPEC = importlib.util.spec_from_file_location('native_package', ROOT / 'release/package.py')
    PACKAGE = importlib.util.module_from_spec(PACKAGE_SPEC)
    PACKAGE_SPEC.loader.exec_module(PACKAGE)
finally:
    sys.path.pop(0)
COMMIT = 'a' * 40


class CandidateTests(unittest.TestCase):
    def test_launcher_pins_tls_roots_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory(prefix='compact release ') as temp:
            root = Path(temp)
            (root / 'lib').mkdir()
            program = root / 'lib/compact-update.real'
            program.write_text('#!/bin/sh\nprintf "%s\\n" "$CURL_CA_BUNDLE" "$LD_LIBRARY_PATH" "$@"\n')
            program.chmod(0o700)
            PACKAGE.write_launcher(root, 'compact-update')
            env = os.environ.copy()
            env.update(CURL_CA_BUNDLE='/untrusted/external-roots', LD_LIBRARY_PATH='/untrusted/libs')
            args = ['space and quotes "', '$(touch should-not-run)', '`uname`']
            lines = subprocess.check_output([str(root / 'bin/compact-update'), *args], env=env, text=True).splitlines()
            self.assertEqual(lines, [str(root / 'lib/tls-ca-bundle.crt'), str(root / 'lib'), *args])

    def test_tls_roots_exclude_local_certificates_and_database_trust(self):
        roots = sorted(Path('/usr/share/ca-certificates/mozilla').glob('*.crt'))
        if not roots:
            self.skipTest('Pinned Debian CA roots are tested in the release builder')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(PACKAGE.subprocess, 'check_output', return_value=(
                    str(roots[0]) + '\n/usr/local/share/ca-certificates/private-proxy.crt\n')):
                bundle = PACKAGE.copy_tls_ca_bundle(root)
            self.assertEqual(bundle, root / 'lib/tls-ca-bundle.crt')
            self.assertEqual(bundle.read_bytes(), roots[0].read_bytes().strip() + b'\n')
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o644)
            self.assertFalse((root / 'certs').exists())

    def test_current_upstream_pin_does_not_modify_checkout(self):
        spec = importlib.util.spec_from_file_location('release_track', ROOT / 'release/track_upstream.py')
        tracker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tracker)
        manifest = json.loads((ROOT / 'manifest.json').read_text())
        with mock.patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/native'}), \
                mock.patch.object(tracker, 'run', return_value=json.dumps(
                    {'commit': {'sha': manifest['upstream_commit']}})) as run:
            tracker.main()
        run.assert_called_once_with('gh', 'api', 'repos/Cisco-Talos/clamav/branches/main')

    def fixture(self, root, extra=None):
        data = {'manifest.json': json.dumps({'protocol': 1, 'expires_at': int(time.time()) + 600,
                    'repository': 'example/native', 'integration_sha': COMMIT, 'channel': 'preview',
                    'version': '0.1.0', 'tag': 'compact-v0.1.0'}).encode(),
                'qualification.json': json.dumps({'passed': True, 'integration_sha': COMMIT}).encode(),
                'provenance.json': b'{"source_complete":true}'}
        index = [{'path': name, 'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                 for name, value in sorted(data.items())]
        data['bundle-index.json'] = json.dumps(index).encode()
        if extra:
            data.update(extra)
        archive = root / 'candidate.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, value in data.items():
                item = tarfile.TarInfo('candidate/' + name)
                item.size = len(value)
                tar.addfile(item, io.BytesIO(value))
        return archive

    def verify(self, archive, destination, digest=None):
        return VERIFY.verify(archive, digest or VERIFY.sha256(archive), destination,
                             'example/native', COMMIT, 'preview', '0.1.0', 'compact-v0.1.0')

    def test_exact_transport_and_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.fixture(root)
            self.assertTrue((self.verify(archive, root / 'ok') / 'manifest.json').is_file())
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                self.verify(archive, root / 'bad', '0' * 64)

    def test_unindexed_and_traversal_content_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.fixture(root, {'unexpected.bin': b'not qualified'})
            with self.assertRaisesRegex(ValueError, 'Unindexed'):
                self.verify(archive, root / 'unexpected')
            archive = self.fixture(root, {'../../outside': b'not allowed'})
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                self.verify(archive, root / 'traversal')
            self.assertFalse((root / 'outside').exists())

    def test_missing_key_cannot_create_signature(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'manifest.json').write_text('{}')
            env = os.environ.copy()
            env.pop('COMPACT_TEST_RELEASE_KEY', None)
            result = subprocess.run([sys.executable, str(ROOT / 'release/sign.py'),
                '--manifest', str(root / 'manifest.json'), '--signature', str(root / 'manifest.sig'),
                '--key-env', 'COMPACT_TEST_RELEASE_KEY', '--public-key-b64', base64.b64encode(b'0' * 32).decode()],
                env=env, capture_output=True)
            self.assertEqual(result.returncode, 78)
            self.assertFalse((root / 'manifest.sig').exists())

    @unittest.skipUnless(shutil.which('php'), 'PHP sodium test runs in the pinned builder')
    def test_exact_manifest_signature_rejects_mutation(self):
        keys = json.loads(subprocess.check_output(['php', '-r',
            '$p=sodium_crypto_sign_keypair();echo json_encode([base64_encode(sodium_crypto_sign_secretkey($p)),base64_encode(sodium_crypto_sign_publickey($p))]);']))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, signature = root / 'manifest.json', root / 'manifest.sig'
            manifest.write_bytes(b'{"protocol":1,"version":"0.1.0"}\n')
            env = os.environ.copy()
            env['COMPACT_TEST_RELEASE_KEY'] = keys[0]
            subprocess.run([sys.executable, str(ROOT / 'release/sign.py'), '--manifest', str(manifest),
                            '--signature', str(signature), '--key-env', 'COMPACT_TEST_RELEASE_KEY',
                            '--public-key-b64', keys[1]], env=env, check=True)
            self.assertEqual(signature.stat().st_size, 64)
            command = ['php', '-r', '$k=base64_decode($argv[1],true);exit(sodium_crypto_sign_verify_detached(file_get_contents($argv[2]),file_get_contents($argv[3]),$k)?0:1);',
                       keys[1], str(signature), str(manifest)]
            self.assertEqual(subprocess.run(command).returncode, 0)
            manifest.write_bytes(manifest.read_bytes() + b' ')
            self.assertNotEqual(subprocess.run(command).returncode, 0)


if __name__ == '__main__':
    unittest.main()
