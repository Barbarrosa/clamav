#!/usr/bin/env python3
"""Single-threaded Linux child resource setup before exec. GPL-2.0-only."""
import ctypes
import os
import resource
import sys


def main():
    cpu, memory, file_bytes, *command = sys.argv[1:]
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (int(cpu), int(cpu)))
    resource.setrlimit(resource.RLIMIT_AS, (int(memory), int(memory)))
    resource.setrlimit(resource.RLIMIT_FSIZE, (int(file_bytes), int(file_bytes)))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS, inherited across exec
        raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
    os.umask(0o077)
    os.execv(command[0], command)


if __name__ == '__main__':
    main()
