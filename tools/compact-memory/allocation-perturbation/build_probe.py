#!/usr/bin/env python3
"""Build the experiment harness against a prebuilt engine. GPL-2.0-only."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--libdir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--include', type=Path, action='append', default=[])
    parser.add_argument('--library-path', type=Path, action='append', default=[])
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[3]
    libdir = (args.libdir or args.build / 'libclamav').resolve()
    directories = [libdir, args.build / 'libclamunrar_iface', args.build / 'libclamunrar']
    flags = shlex.split(subprocess.check_output(
        ['pkg-config', '--cflags', '--libs', 'json-c', 'openssl'], text=True))
    command = [args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-function', '-I' + str(source / 'libclamav'),
               '-I' + str(args.build.resolve())]
    command += ['-I' + str(p.resolve()) for p in args.include]
    command += [str(Path(__file__).with_name('probe.c')), '-L' + str(libdir),
                '-Wl,--disable-new-dtags', '-Wl,-rpath,' + ':'.join(str(p.resolve()) for p in directories)]
    command += ['-L' + str(p.resolve()) for p in args.library_path]
    command += ['-lclamav', '-ldl'] + flags + ['-o', str(args.output)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
