#!/usr/bin/env python3
"""Run native qualification, recording failures without weakening release gates.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import shlex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'integration', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    a = parser.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(CI_SOURCE=str(a.source), CI_BUILD=str(a.build),
               LIBCLAMAV=str(a.build / 'libclamav/libclamav.so'), CARGO_CMD='test',
               RUSTFLAGS='-g', CARGO_NET_OFFLINE='true')
    env['LD_LIBRARY_PATH'] = ':'.join(str(a.build / p) for p in
        ('libclamav', 'libfreshclam', 'libclamunrar_iface', 'libclamunrar', 'libclammspack'))
    crypto_probe = a.output.parent / 'prepare-crypto-probe'
    bounded_probe = a.output.parent / 'bounded-native-probe'
    cflags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', 'json-c', 'openssl', 'sqlite3'], text=True))
    libraries = shlex.split(subprocess.check_output(['pkg-config', '--libs', 'json-c', 'openssl', 'sqlite3', 'zlib'], text=True))
    tests = [
        ('integration-python', ['python3', '-m', 'unittest', 'discover', '-s', str(a.integration / 'tests'), '-v'], None),
        ('C-and-scanners', ['ctest', '--test-dir', str(a.build), '-R', '^(libclamav|clamscan|sigtool|freshclam)$', '--output-on-failure'], None),
        ('Rust', ['cargo', 'test', '--locked', '--offline', '--release', '--target', 'x86_64-unknown-linux-gnu',
                  '--target-dir', str(a.build), '--lib', '--', '--test-threads=1'], a.source / 'libclamav_rust'),
        ('C-Rust-ABI', ['python3', str(a.source / 'tools/compact-memory/check_layout.py'), '--build', str(a.build),
                       '--include', '/usr/include/json-c', '--include', '/usr/include/libxml2'], None),
        ('prepare', ['sh', str(a.integration / 'tests/test_prepare.sh')], None),
        ('PKI-probe-build', ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-I' + str(a.source / 'libclamav'), '-I' + str(a.build), *cflags,
            str(a.integration / 'tests/prepare_crypto_probe.c'), '-L' + str(a.build / 'libclamav'),
            '-Wl,-rpath,' + str(a.build / 'libclamav'), '-lclamav', *libraries, '-o', str(crypto_probe)], None),
        ('PKI-only-preparation', ['python3', str(a.integration / 'tests/test_prepare_pki.py'),
            '--probe', str(crypto_probe), '--source', str(a.source),
            '--output', str(a.output.parent / 'pki-qualification.json')], None),
        ('production-guards', ['sh', str(a.integration / 'tests/run_guards.sh'),
                               str(a.source), str(a.build), str(a.output.parent / 'guard-reports')], None),
        ('bounded-native-probe-build', ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-DHAVE_CONFIG_H', '-I' + str(a.source / 'libclamav'), '-I' + str(a.build), *cflags,
            str(a.integration / 'tests/bounded_native_probe.c'), str(a.integration / 'native/prepare.c'),
            '-L' + str(a.build / 'libclamav'), '-Wl,-rpath,' + str(a.build / 'libclamav'),
            '-lclamav', *libraries, '-ldl', '-o', str(bounded_probe)], None),
        ('bounded-native-diagnostics', ['python3', str(a.integration / 'tests/test_bounded_native.py'),
            '--probe', str(bounded_probe), '--certs', str(a.source / 'certs'),
            '--output', str(a.output.parent / 'bounded-native-qualification.json')], None),
        ('packaged-adapter', [str(a.build / 'compact-adapter/compact-scan'), 'doctor'], None),
        ('native-resource-lifecycle', ['python3', str(a.integration / 'tests/test_native_dos.py'),
            '--scanner', str(a.build / 'compact-adapter/compact-scan'),
            '--updater', str(a.build / 'compact-adapter/compact-update'), '--source', str(a.source),
            '--report', str(a.output.parent / 'native-resource-qualification.json')], None),
    ]
    report = {'integration_sha': a.commit, 'passed': False, 'stable_release_qualified': False,
              'subset_release_qualified': False, 'siteground_qualified': False,
              'scope': 'pinned source regression; no universal detection or hosting guarantee', 'checks': []}
    for name, args, cwd in tests:
        started = time.monotonic()
        result = subprocess.run(args, cwd=cwd, env=env)
        report['checks'].append({'name': name, 'returncode': result.returncode,
                                 'seconds': time.monotonic() - started})
        a.output.write_text(json.dumps(report, indent=2) + '\n')
        if result.returncode:
            return result.returncode
    report['passed'] = True
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
