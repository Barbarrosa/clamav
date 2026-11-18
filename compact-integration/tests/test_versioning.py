"""Release names come from the built engine; recipe versions remain independent."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'release'))
try:
    import versioning as VERSIONING
    SPEC = importlib.util.spec_from_file_location('versioned_package', ROOT / 'release/package.py')
    PACKAGE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(PACKAGE)
finally:
    sys.path.pop(0)
INTEGRATION_SHA = 'a' * 40
RECIPE = json.loads((ROOT / 'manifest.json').read_text())


def engine_fixture(build, version='1.6.0-devel-20261118', core='1.6.0'):
    build.mkdir(parents=True)
    (build / 'clamav-version.h').write_text('#define CLAMAV_VERSION ' + json.dumps(core) + '\n')
    scanner = build / 'compact-adapter/compact-scan'
    scanner.parent.mkdir()
    scanner.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
        'assert sys.argv[1:] == ["doctor"]\n'
        'assert os.environ["COMPACT_PARENT_PID"] == str(os.getppid())\n'
        'assert "LD_PRELOAD" not in os.environ and "LD_AUDIT" not in os.environ\n'
        'print(json.dumps(' + repr({'protocol': 1, 'status': 'ready', 'completed': True,
                                     'engine_version': version}) + '))\n')
    scanner.chmod(0o700)
    return scanner


class VersionIdentityTests(unittest.TestCase):
    def test_preserves_stable_prerelease_and_upstream_build_metadata(self):
        for upstream in ['1.5.3', '1.6.0-devel-20261118', '1.6.0-rc.2',
                         '1.6.0-01alpha', '1.6.0+vendor.01', '1.6.0-rc.2+vendor.1']:
            with self.subTest(upstream=upstream):
                version = upstream + ('.' if '+' in upstream else '+') + 'compact.123'
                identity = VERSIONING.version_identity(upstream, 123)
                self.assertEqual(identity, {'upstream_version': upstream, 'fork_revision': 123,
                                           'version': version, 'tag': 'clamav-' + version})
                self.assertTrue(VERSIONING.valid_semver(version))
                self.assertEqual(VERSIONING.native_tag(version), identity['tag'])

    def test_rejects_ambiguous_or_invalid_upstream_versions(self):
        for upstream in [None, 16, '', 'v1.6.0', '1.6', '01.6.0', '1.06.0', '1.6.00',
                         '1.6.0-01', '1.6.0-rc.01', '1.6.0-', '1.6.0+', '1.6.0+vendor..1',
                         '1.6.0+vendor+more', '1.6.0\n', '1.6.0 devel', '1.6.0/../../bad']:
            with self.subTest(upstream=upstream):
                self.assertFalse(VERSIONING.valid_semver(upstream))
                with self.assertRaises(ValueError):
                    VERSIONING.version_identity(upstream, 1)

    def test_fork_revision_is_a_canonical_positive_sequence(self):
        for revision in [None, True, False, 0, -1, '1', 1.0, 2**63]:
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                VERSIONING.version_identity('1.6.0', revision)
        self.assertEqual(VERSIONING.version_identity('1.6.0', 2**63 - 1)['fork_revision'], 2**63 - 1)
        for version in ['1.6.0', '1.6.0-compact.1', '1.6.0+vendor.1', '1.6.0+compact.0',
                        '1.6.0+compact.01', '1.6.0+compact.1.extra', '1.6.0+compact.' + str(2**63)]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                VERSIONING.native_tag(version)

    def test_generated_core_must_match_the_actual_qualified_version(self):
        self.assertEqual(VERSIONING.release_identity('1.6.0-devel-20261118', 2, '1.6.0')['fork_revision'], 2)
        for core in ['1.5.9', '1.6.0-devel', '01.6.0', '1.6.0\n', 16]:
            with self.subTest(core=core), self.assertRaisesRegex(ValueError, 'generated upstream version header'):
                VERSIONING.release_identity('1.6.0-devel-20261118', 2, core)

    def test_built_identity_uses_matching_libraries_and_actual_parent(self):
        with tempfile.TemporaryDirectory(prefix='qualified engine ') as temp:
            build = Path(temp) / 'build'
            scanner = engine_fixture(build)
            actual_check_output = subprocess.check_output
            calls = []

            def observe(command, **kwargs):
                calls.append((command, kwargs))
                return actual_check_output(command, **kwargs)

            with mock.patch.dict(os.environ, {'LD_LIBRARY_PATH': '/untrusted/libs',
                    'LD_PRELOAD': '/untrusted/preload', 'LD_AUDIT': '/untrusted/audit',
                    'COMPACT_PARENT_PID': '1'}), \
                    mock.patch.object(VERSIONING.subprocess, 'check_output', side_effect=observe):
                result = VERSIONING.built_identity(build, 9)
            self.assertEqual(result['version'], '1.6.0-devel-20261118+compact.9')
            self.assertEqual(calls[0][0], [str(scanner), 'doctor'])
            self.assertEqual(calls[0][1]['timeout'], 30)
            self.assertEqual(calls[0][1]['env']['LD_LIBRARY_PATH'], ':'.join(
                str(build / directory) for directory in VERSIONING.LIBRARY_DIRECTORIES))

    def test_wrong_header_incomplete_doctor_and_failed_process_cannot_name_release(self):
        with tempfile.TemporaryDirectory() as temp:
            build = Path(temp) / 'build'
            engine_fixture(build, core='1.5.9')
            with self.assertRaisesRegex(ValueError, 'generated upstream version header'):
                VERSIONING.built_identity(build, 1)
            (build / 'clamav-version.h').write_text('#define CLAMAV_VERSION "1.6.0"\n')
            for doctor in [{'protocol': 1, 'status': 'ready', 'completed': False,
                            'engine_version': '1.6.0'}, [], {'engine_version': '1.6.0'}]:
                with self.subTest(doctor=doctor), \
                        mock.patch.object(VERSIONING.subprocess, 'check_output', return_value=json.dumps(doctor)), \
                        self.assertRaisesRegex(ValueError, 'complete identity'):
                    VERSIONING.built_identity(build, 1)
            with mock.patch.object(VERSIONING.subprocess, 'check_output',
                    side_effect=subprocess.CalledProcessError(127, ['compact-scan'])), \
                    self.assertRaises(subprocess.CalledProcessError):
                VERSIONING.built_identity(build, 1)

    def test_missing_or_duplicate_generated_version_cannot_name_release(self):
        with tempfile.TemporaryDirectory() as temp:
            build = Path(temp) / 'build'
            engine_fixture(build)
            for header in ['', '#define CLAMAV_VERSION "1.6.0"\n#define CLAMAV_VERSION "1.6.0"\n']:
                (build / 'clamav-version.h').write_text(header)
                with self.subTest(header=header), self.assertRaisesRegex(ValueError, 'unique generated'):
                    VERSIONING.built_identity(build, 1)
            (build / 'clamav-version.h').write_text('#define CLAMAV_VERSION "1.6.0"\n')
            (build / 'compact-adapter/compact-scan').unlink()
            with self.assertRaisesRegex(ValueError, 'matching compiled'):
                VERSIONING.built_identity(build, 1)

    def test_cli_outputs_actual_build_identity_to_stdout_and_json_file(self):
        with tempfile.TemporaryDirectory(prefix='version cli ') as temp:
            root = Path(temp)
            engine_fixture(root / 'build', '1.6.0-rc.2+vendor.7')
            output = root / 'nested/release-version.json'
            result = subprocess.check_output([sys.executable, str(ROOT / 'release/versioning.py'),
                '--build', str(root / 'build'), '--revision', '71', '--output', str(output)], text=True)
            identity = json.loads(result)
            self.assertEqual(json.loads(output.read_text()), identity)
            self.assertEqual(identity['tag'], 'clamav-1.6.0-rc.2+vendor.7.compact.71')


class PackageIdentityTests(unittest.TestCase):
    def fixture(self, root, built_version='1.6.0-rc.2+vendor.7'):
        source, build, output = root / 'source', root / 'build', root / 'output'
        (source / 'compact-adapter').mkdir(parents=True)
        (source / 'compact-adapter/scan.c').write_text('/* materialized adapter fixture */\n')
        (source / 'compact-source.json').write_text(json.dumps({
            'upstream_commit': RECIPE['upstream_commit'],
            'integration_version': RECIPE['integration_version'], 'variant': 'optimized',
            'manifest_sha256': PACKAGE.digest(ROOT / 'manifest.json')}))
        (source / 'certs').mkdir()
        (source / 'certs/clamav.crt').write_text('packaged ClamAV certificate fixture\n')
        (source / 'COPYING.txt').write_text('GPL-2.0-only fixture\n')
        (source / 'Cargo.toml').write_text('# Cargo metadata is mocked at the dependency boundary.\n')
        engine_fixture(build, built_version)
        (build / 'compact-adapter/compact-update').write_text('#!/bin/sh\nexit 0\n')
        for name in ['libclamav', 'libfreshclam', 'libclammspack', 'libclamunrar', 'libclamunrar_iface']:
            (build / (name + '.so.12.0')).write_text('Native library fixture for packaging paths.\n')
        report = root / 'qualification.json'
        report.write_text(json.dumps({'integration_sha': INTEGRATION_SHA, 'passed': True}))
        notes = root / 'notes.md'
        notes.write_bytes(b'# ClamAV 1.6.0\n\nExact generated notes.\n')
        identity = VERSIONING.version_identity('1.6.0-rc.2+vendor.7', 123)
        argv = ['package.py', '--source', str(source), '--build', str(build), '--output', str(output),
                '--qualification', str(report), '--changelog', str(notes),
                '--upstream-sha', RECIPE['upstream_commit'], '--integration-sha', INTEGRATION_SHA,
                '--version', identity['version'], '--repository', 'example/native', '--sequence', '123',
                '--expires-at', str(int(time.time()) + 600)]
        return source, build, output, notes, identity, argv

    def package(self, root, argv):
        actual_check_output = subprocess.check_output

        def tool_output(command, **kwargs):
            if command[:2] == ['cc', '--version']:
                return 'Fixture C compiler\n'
            if command[:2] == ['rustc', '--version']:
                return 'Fixture Rust compiler\n'
            if command[:2] == ['cargo', 'vendor']:
                Path(command[-1]).mkdir()
                return '[source.vendored-sources]\ndirectory = "fixture"\n'
            if command[:2] == ['cargo', 'metadata']:
                return '{"packages":[]}'
            return actual_check_output(command, **kwargs)

        def dependencies(_elf, _build, _payload, destination, **_kwargs):
            Path(destination).mkdir()
            (Path(destination) / 'source.txt').write_text('Complete dependency source fixture.\n')
            return {'platform_sonames': [], 'source_complete': True, 'sources': []}

        def tls_roots(payload):
            (payload / 'lib/tls-ca-bundle.crt').write_text('Public CA fixture.\n')

        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(PACKAGE.subprocess, 'check_output', side_effect=tool_output), \
                mock.patch.object(PACKAGE, 'collect', side_effect=dependencies), \
                mock.patch.object(PACKAGE, 'copy_tls_ca_bundle', side_effect=tls_roots), \
                redirect_stdout(io.StringIO()):
            PACKAGE.main()

    def test_package_binds_actual_upstream_recipe_changelog_and_encoded_asset_urls(self):
        with tempfile.TemporaryDirectory(prefix='package release ') as temp:
            root = Path(temp)
            source, build, output, notes, identity, argv = self.fixture(root)
            with mock.patch.dict(os.environ, {'LD_PRELOAD': '/untrusted/preload',
                    'LD_AUDIT': '/untrusted/audit', 'COMPACT_PARENT_PID': '1'}):
                self.package(root, argv)
            manifest = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(manifest['version'], identity['version'])
            self.assertEqual(manifest['upstream_version'], identity['upstream_version'])
            self.assertEqual(manifest['integration_version'], RECIPE['integration_version'])
            self.assertNotEqual(manifest['integration_version'], manifest['version'])
            self.assertEqual(manifest['fork_revision'], manifest['sequence'])
            self.assertEqual((output / 'CHANGELOG.md').read_bytes(), notes.read_bytes())
            self.assertEqual(manifest['changelog_sha256'], hashlib.sha256(notes.read_bytes()).hexdigest())
            base_url = 'https://github.com/example/native/releases/download/' + quote(identity['tag'], safe='') + '/'
            self.assertIn('%2B', base_url)
            self.assertTrue(all(item['url'].startswith(base_url) for item in manifest['files']))
            source_archive = manifest['source_archives'][0]
            self.assertEqual(source_archive['name'], identity['tag'] + '-source.tar.gz')
            self.assertEqual(source_archive['url'], base_url + quote(source_archive['name'], safe=''))
            provenance = json.loads((output / 'provenance.json').read_text())
            self.assertEqual(provenance['release'], identity)
            self.assertEqual(provenance['integration_version'], RECIPE['integration_version'])
            self.assertEqual(json.loads((output / 'packaged-smoke.json').read_text())['engine_version'], identity['upstream_version'])
            index = json.loads((output / 'bundle-index.json').read_text())
            self.assertIn({'path': 'CHANGELOG.md', 'size': notes.stat().st_size,
                           'sha256': manifest['changelog_sha256']}, index)
            with tarfile.open(root / (identity['tag'] + '-candidate.tar.gz')) as archive:
                self.assertEqual(archive.extractfile('candidate/CHANGELOG.md').read(), notes.read_bytes())

    def test_modified_recipe_identity_is_rejected_before_packaging(self):
        for field, replacement in [('manifest_sha256', '0' * 64),
                                   ('integration_version', '1.6.0-rc.2+vendor.7.compact.123'),
                                   ('upstream_commit', 'b' * 40), ('variant', 'baseline')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source, build, output, notes, identity, argv = self.fixture(root)
                stamp_path = source / 'compact-source.json'
                stamp = json.loads(stamp_path.read_text())
                stamp[field] = replacement
                stamp_path.write_text(json.dumps(stamp))
                with mock.patch.object(sys, 'argv', argv), redirect_stderr(io.StringIO()), \
                        mock.patch.object(PACKAGE, 'built_identity') as inspect_build, \
                        self.assertRaises(SystemExit):
                    PACKAGE.main()
                inspect_build.assert_not_called()
                self.assertFalse(output.exists())

    def test_incorrect_upstream_version_or_fork_sequence_is_rejected(self):
        for version in ['1.6.0+compact.123', '1.6.0-rc.2+vendor.7.compact.124', '0.1.1']:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source, build, output, notes, identity, argv = self.fixture(root)
                argv[argv.index('--version') + 1] = version
                with mock.patch.object(sys, 'argv', argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    PACKAGE.main()
                self.assertFalse(output.exists())

    def test_absent_or_empty_changelog_cannot_prepare_a_candidate(self):
        for missing in [True, False]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source, build, output, notes, identity, argv = self.fixture(root)
                notes.unlink() if missing else notes.write_text('')
                with mock.patch.object(sys, 'argv', argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    PACKAGE.main()
                self.assertFalse(output.exists())

    def test_packaged_engine_cannot_differ_from_the_qualified_build(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, build, output, notes, identity, argv = self.fixture(root, built_version='1.6.0-rc.1')
            with mock.patch.object(PACKAGE, 'built_identity', return_value=identity), \
                    self.assertRaisesRegex(ValueError, 'Packaged engine version differs'):
                self.package(root, argv)
            self.assertFalse((root / (identity['tag'] + '-candidate.tar.gz')).exists())


if __name__ == '__main__':
    unittest.main()
