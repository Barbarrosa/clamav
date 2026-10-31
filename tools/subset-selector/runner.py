"""Bounded Linux scanner supervision. Resource limits are not a security sandbox.
SPDX-License-Identifier: GPL-2.0-only
"""
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from types import SimpleNamespace


def run(command, *, timeout=180, cpu_seconds=120, address_space_mib=2048,
        output_bytes=16*1024*1024, temp_directory, library=None):
    if (not math.isfinite(timeout) or timeout <= 0 or cpu_seconds < 1
            or address_space_mib < 128 or output_bytes < 1):
        raise ValueError('invalid scanner resource limits')
    # Trusted build/runtime paths are permitted; diagnostic hooks and loader
    # injection knobs are not inherited by intake. Standalone probes stay diagnostic.
    env = {k: os.environ[k] for k in ('PATH', 'LD_LIBRARY_PATH') if k in os.environ}
    if library is not None:
        parent = Path(library).resolve().parent
        paths = [parent] + [parent.parent/name for name in ('libclamunrar_iface','libclamunrar')
                            if (parent.parent/name).is_dir()]
        existing = [p for p in env.get('LD_LIBRARY_PATH','').split(':') if p and Path(p).is_absolute()]
        env['LD_LIBRARY_PATH'] = ':'.join(map(str, paths+existing))
    env.update(LANG='C.UTF-8', TMPDIR=str(temp_directory))
    launcher = [sys.executable, '-I', str(Path(__file__).with_name('resource_exec.py')),
                str(cpu_seconds), str(address_space_mib*1024*1024), str(512*1024*1024)]
    child = subprocess.Popen(launcher+command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, start_new_session=True, cwd=temp_directory)
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout
    total = 0
    try:
        with selectors.DefaultSelector() as events:
            for name in chunks:
                pipe = getattr(child, name)
                os.set_blocking(pipe.fileno(), False)
                events.register(pipe, selectors.EVENT_READ, name)
            while events.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('scanner wall-time limit exceeded')
                for key, _ in events.select(min(remaining, 0.1)):
                    data = os.read(key.fd, 65536)
                    if not data:
                        events.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > output_bytes:
                        raise ValueError('scanner output limit exceeded')
                    chunks[key.data].extend(data)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('scanner wall-time limit exceeded')
            child.wait(timeout=remaining)
        return SimpleNamespace(returncode=child.returncode,
            stdout=chunks['stdout'].decode('utf-8', errors='strict'),
            stderr=chunks['stderr'].decode('utf-8', errors='replace'))
    finally:
        # Kill descendants as well on timeout, output overflow, or early parent exit.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdout.close()
        child.stderr.close()
