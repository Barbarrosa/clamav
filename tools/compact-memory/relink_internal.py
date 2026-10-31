#!/usr/bin/env python3
"""Relink existing Linux build objects for private-API diagnostics only.

The production shared library is not modified. No sources are recompiled and
no scanner features are disabled. The diagnostic copy exports private symbols.
"""
import argparse
from pathlib import Path
import shlex
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
build, out = a.build.resolve(), a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
commands = subprocess.check_output(['ninja', '-C', str(build), '-t', 'commands',
                                   'libclamav/libclamav.so.14.0.0'], text=True)
args = shlex.split(commands.splitlines()[-1])
assert args[:2] == [':', '&&'] and args[-2:] == ['&&', ':']
args = [x for x in args[2:-2] if not x.startswith(('-Wl,--version-script=', '-Wl,--dependency-file='))]
args[args.index('-o') + 1] = str(out / 'libclamav.so.14.0.0')
subprocess.run(args, cwd=build, check=True)
for name in ('libclamav.so', 'libclamav.so.14'):
    link = out / name
    if link.is_symlink():
        link.unlink()
    link.symlink_to('libclamav.so.14.0.0')
print(out)
