#!/usr/bin/env python3
"""Atomic shadow-generation pointer and rollback. Production activation is disabled.
The full database service configuration is never changed. GPL-2.0-only.
"""
import fcntl,json,os,time,uuid
from pathlib import Path
from select_db import validate_generation,sha


def switch_shadow(state, generation, lib):
    state=Path(state);state.mkdir(parents=True,exist_ok=True,mode=0o700)
    generation=Path(generation).resolve();m=validate_generation(generation,lib)
    with (state/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=state/'shadow-current';previous=state/'shadow-previous'
        old=os.readlink(current) if current.is_symlink() else None
        if current.exists() and not current.is_symlink():raise ValueError('current is not a generation symlink')
        if old is not None:
            temp=state/('previous-'+uuid.uuid4().hex);temp.symlink_to(old);os.replace(temp,previous)
        temp=state/('next-'+uuid.uuid4().hex);temp.symlink_to(generation);os.replace(temp,current)
        with (state/'history.jsonl').open('a') as f:
            f.write(json.dumps({'time_ns':time.time_ns(),'old':old,'new':str(generation),'manifest_sha256':sha(generation/'manifest.json'),'mode':'shadow-only','release_enabled':False})+'\n');f.flush();os.fsync(f.fileno())
        fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    return generation


def rollback_shadow(state,lib):
    previous=Path(state)/'shadow-previous'
    if not previous.is_symlink():raise ValueError('no rollback generation')
    return switch_shadow(state,previous.resolve(),lib)


def activate_for_release(*args,**kwargs):
    raise ValueError('release activation disabled: parser completeness remains unproven')
