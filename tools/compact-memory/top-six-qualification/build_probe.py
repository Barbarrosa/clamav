#!/usr/bin/env python3
"""Build the same qualification adapter against a selected engine. GPL-2.0-only."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--libdir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include', type=Path, action='append', default=[])
    parser.add_argument('--library-path', type=Path, action='append', default=[])
    parser.add_argument('--runtime-dir', type=Path, action='append', default=[])
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    source = (args.source or repository).resolve()
    library = (args.libdir or args.build / 'libclamav').resolve()
    runtime = [library, args.build / 'libclamunrar_iface', args.build / 'libclamunrar', *args.runtime_dir]
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c', 'openssl'], text=True))
    command = [os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-function', '-I' + str(source / 'libclamav'), '-I' + str(args.build.resolve())]
    command += ['-I' + str(p.resolve()) for p in args.include]
    command += [str(Path(__file__).with_name('probe.c')), '-L' + str(library)]
    command += ['-L' + str(p.resolve()) for p in args.library_path]
    command += ['-Wl,--disable-new-dtags', '-Wl,-rpath,' + ':'.join(str(p.resolve()) for p in runtime),
                '-lclamav', '-ldl', '-pthread', *flags, '-o', str(args.output.resolve())]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
