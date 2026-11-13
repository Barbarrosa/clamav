#!/usr/bin/env python3
"""Run a nonempty Rust streaming test selection with the qualified native libraries.

The timeout is a CI test policy, not a deployment resource default.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


LIBRARY_DIRECTORIES = ('libclamav', 'libfreshclam', 'libclamunrar_iface',
                       'libclamunrar', 'libclammspack')


def checked_output(arguments, environment, timeout):
    result = subprocess.run(arguments, env=environment, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace')
    print(result.stdout, end='', flush=True)
    result.check_returncode()
    return result.stdout


def run(build, timeout=120):
    build = Path(build).resolve()
    environment = os.environ.copy()
    # Match qualify.py exactly; never append an inherited untrusted library path.
    environment['LD_LIBRARY_PATH'] = ':'.join(str(build / part) for part in LIBRARY_DIRECTORIES)
    dependencies = build / 'x86_64-unknown-linux-gnu/release/deps'
    binaries = sorted(path for path in dependencies.glob('clamav_rust-*')
                      if path.is_file() and not path.is_symlink() and os.access(path, os.X_OK))
    if not binaries:
        raise RuntimeError('No compiled Rust test executable was found; streaming qualification did not run.')
    total = 0
    for binary in binaries:
        print('Listing streaming tests in ' + str(binary), flush=True)
        listing = checked_output([str(binary), 'streaming', '--list', '--format', 'terse'], environment, timeout)
        names = [line[:-6] for line in listing.splitlines() if line.endswith(': test')]
        if not names or any('streaming' not in name for name in names):
            raise RuntimeError('Rust executable did not list a nonempty streaming test selection.')
        print('Running ' + str(len(names)) + ' streaming tests in ' + str(binary), flush=True)
        output = checked_output([str(binary), 'streaming', '--test-threads=1'], environment, timeout)
        summary = re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', output)
        if not summary or int(summary[1]) != len(names) or int(summary[2]) != 0 or int(summary[3]) != 0:
            raise RuntimeError('Rust streaming test completion does not match the nonempty listed selection.')
        total += len(names)
    print('Streaming qualification passed: ' + str(total) + ' tests across ' + str(len(binaries)) + ' executables.', flush=True)
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, default=120)
    arguments = parser.parse_args()
    if arguments.timeout_seconds < 1:
        parser.error('The CI test timeout must be positive.')
    try:
        run(arguments.build, arguments.timeout_seconds)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('Streaming qualification failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
