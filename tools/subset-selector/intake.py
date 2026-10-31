#!/usr/bin/env python3
"""Private local evidence intake; full is default, Legal Redress stays held.
Linux only. No network/form integration or automatic restricted-release override.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import stat
import subprocess
import tempfile
import time
import uuid

from select_db import sha
from scan import command, PROFILES
from runner import run as run_scanner
from storage import private_directory, fsync_directory, write_json, exclusive_lock


def preserve(source, quarantine, max_source_bytes=100*1024*1024):
    """Durably snapshot one no-follow FD; never remove or modify the source.

    Oversize sources are rejected before copying. The upstream upload store must
    retain them for the exception route. A copied-but-unstable snapshot is held.
    """
    if max_source_bytes < 1:
        raise ValueError('invalid source byte limit')
    source = Path(source)
    quarantine = private_directory(quarantine, create=True)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('not a regular file')
        if before.st_size > max_source_bytes:
            raise ValueError('source size exceeds intake limit; retain upstream original for review')
        folder = quarantine / uuid.uuid4().hex
        folder.mkdir(mode=0o700)
        fsync_directory(quarantine)
        record = {
            'schema': 2, 'attachment_id': folder.name, 'original_filename': source.name,
            'source_bytes': before.st_size, 'source_mtime_ns': before.st_mtime_ns,
            'source_ctime_ns': before.st_ctime_ns, 'source_mode': stat.S_IMODE(before.st_mode),
            'snapshot_stable': False, 'outcome': 'held', 'reason': 'snapshot-in-progress',
            'release_qualified': False, 'created_at_unix': time.time(),
            'narrative_submission': 'independent-do-not-wait-for-attachment',
            'exception_route': 'authorized-review-with-original-full-database; executables remain evidence',
            'derivatives': 'separate objects with independent scan verdicts',
        }
        write_json(folder/'record.json', record)
        h = hashlib.sha256()
        copied = 0
        try:
            outfd = os.open(folder/'original', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(outfd, 'wb') as out:
                while chunk := os.read(fd, min(1024*1024, max_source_bytes-copied+1)):
                    if copied + len(chunk) > max_source_bytes:
                        raise ValueError('source grew beyond intake limit; retain upstream original')
                    out.write(chunk)
                    h.update(chunk)
                    copied += len(chunk)
                out.flush()
                os.fchmod(out.fileno(), 0o400)
                os.fsync(out.fileno())
            after = os.fstat(fd)
            stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) and copied == before.st_size
            record.update(sha256=h.hexdigest(), bytes=copied, snapshot_stable=stable,
                reason='pending-scan' if stable else 'source-changed-during-snapshot')
        except (OSError, ValueError) as exc:
            record.update(outcome='failed', reason='snapshot-failed: '+str(exc), bytes=copied)
            write_json(folder/'record.json', record)
            raise
        write_json(folder/'record.json', record)
        return folder, record
    finally:
        os.close(fd)


def _integer(value):
    return type(value) is int


def validate_result(stdout, original, expected_hash, profile, lib):
    """Reject missing, duplicated, mismatched, or contradictory result records."""
    def reject_constant(value):
        raise ValueError('non-finite JSON value: '+value)
    def unique_keys(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('duplicate JSON key: '+key)
            out[key] = value
        return out
    rows = [json.loads(line, parse_constant=reject_constant, object_pairs_hook=unique_keys) for line in stdout.splitlines() if line.strip()]
    groups = {}
    for row in rows:
        if not isinstance(row, dict) or row.get('kind') not in {'runtime', 'engine', 'scan', 'batch'}:
            raise ValueError('unexpected scanner output')
        groups.setdefault(row['kind'], []).append(row)
    if any(len(groups.get(k, [])) != 1 for k in ('runtime', 'engine', 'scan', 'batch')):
        raise ValueError('missing or duplicate scanner outcome')
    runtime, engine, row, batch = (groups[k][0] for k in ('runtime', 'engine', 'scan', 'batch'))
    if runtime.get('engine_sha256') != sha(lib) or runtime.get('unrar_modules_verified') != 1:
        raise ValueError('runtime engine or parser modules mismatch')
    if not _integer(engine.get('signatures')) or engine['signatures'] < 1:
        raise ValueError('invalid engine signature count')
    mode = int(profile == 'legal-redress')
    for obj in (row, batch):
        if type(obj.get('allmatch')) is not int or obj['allmatch'] != mode or type(obj.get('round')) is not int or obj['round'] != 0:
            raise ValueError('unexpected scan mode or round')
    if row.get('path') != str(original.resolve()):
        raise ValueError('scan path mismatch')
    if runtime.get('scan_api') not in (None, 'legacy-1.4'):
        raise ValueError('unsupported scanner API')
    legacy_api = runtime.get('scan_api') == 'legacy-1.4'
    for key in ('return_code', 'hold_bits', 'scanned_bytes') + (() if legacy_api else ('verdict',)):
        if not _integer(row.get(key)) or row[key] < 0:
            raise ValueError('invalid scan '+key)
    if (row.get('verdict') is not None if legacy_api else row.get('verdict') not in (0, 1, 2, 3)) or not isinstance(row.get('events'), list):
        raise ValueError('invalid verdict or events')
    if not all(isinstance(event, dict) for event in row['events']):
        raise ValueError('invalid event')
    detected = row['return_code'] == 1 if legacy_api else row['verdict'] in (2, 3)
    expected = ('failed' if row['return_code'] != 0 and not (row['return_code'] == 1 and detected)
                else 'held' if row['hold_bits'] else 'detected' if detected else 'clean')
    if row.get('candidate_outcome') != expected:
        raise ValueError('contradictory scanner candidate outcome')
    expected_outcome = 'held' if mode and expected == 'clean' else expected
    if row.get('outcome') != expected_outcome:
        raise ValueError('contradictory scanner policy outcome')
    if mode and row.get('release_blocker') != 'parser-completeness-unproven':
        raise ValueError('missing restricted release blocker')
    if expected != 'failed' and (row.get('sha256') != expected_hash or row.get('after_sha256') != expected_hash):
        raise ValueError('scan integrity mismatch')
    if expected == 'clean' and (row.get('final_name') is not None or any(
            event.get('event') in ('alert', 'legacy_virus') for event in row['events'])):
        raise ValueError('clean outcome contains detection evidence')
    return row, runtime, engine


def _assess_locked(folder, generation, probe, lib, certs, broad, database_profile,
                   timeout, cpu_seconds, address_space_mib, max_database_age_hours):
    record = json.loads((folder/'record.json').read_text())
    if not isinstance(record, dict):
        raise ValueError('invalid intake record')
    attempt = uuid.uuid4().hex
    # Keep previous findings, then revoke release before any fallible reassessment.
    write_json(folder/('attempt-'+attempt+'-before.json'), record)
    for key in ('scan_evidence','runtime','engine','detection_result',
                'generation_manifest_sha256','database_age_seconds'):
        record.pop(key, None)
    record['database_profile'] = database_profile
    record.update(outcome='held', reason='scan-in-progress', release_qualified=False,
                  assessment_id=attempt, assessment_started_unix=time.time())
    write_json(folder/'record.json', record)
    try:
        if record.get('snapshot_stable') is not True:
            raise ValueError('snapshot is incomplete or unstable')
        original = folder/'original'
        info = original.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o400):
            raise ValueError('unsafe quarantine original')
        if info.st_size != record['bytes'] or sha(original) != record['sha256']:
            raise ValueError('quarantine original changed')
        manifest_path = Path(generation)/'manifest.json'
        manifest_hash = sha(manifest_path)
        manifest = json.loads(manifest_path.read_text())
        if not math.isfinite(max_database_age_hours) or max_database_age_hours <= 0:
            raise ValueError('invalid database age limit')
        daily = [db for db in manifest['signed_databases'] if db['name'] in ('daily.cvd', 'daily.cld')]
        if len(daily) != 1:
            raise ValueError('one signed daily database is required')
        age = time.time() - int(daily[0]['header'].rsplit(':', 1)[-1])
        if age < -300 or age > max_database_age_hours*3600:
            raise ValueError('daily database is stale or future-dated')
        with tempfile.TemporaryDirectory(prefix='.scan-', dir=folder) as d:
            files = Path(d)/'files.txt'
            if '\n' in str(original.resolve()) or '\r' in str(original.resolve()):
                raise ValueError('newline in quarantine path')
            files.write_text(str(original.resolve())+'\n')
            cmd = command(probe=probe, lib=lib, certs=certs, files=files,
                          generation=generation, database_profile=database_profile, broad=broad)
            # One native scanner per private quarantine root, across all intake processes.
            with exclusive_lock(folder.parent/'.scanner.lock'):
                result = run_scanner(cmd, temp_directory=d, timeout=timeout,
                                     cpu_seconds=cpu_seconds, address_space_mib=address_space_mib, library=lib)
        if result.returncode:
            raise ValueError('scanner process failed: '+str(result.returncode))
        row, runtime, engine = validate_result(result.stdout, original, record['sha256'], database_profile, lib)
        record.update(scan_evidence=[row], runtime=runtime, engine=engine,
                      database_profile=database_profile, detection_result=row['candidate_outcome'],
                      generation_manifest_sha256=manifest_hash, database_age_seconds=age)
        candidate = row['candidate_outcome']
        if candidate == 'failed':
            record.update(outcome='failed', reason='scanner-error')
        elif candidate == 'held':
            record.update(outcome='held', reason='unsupported-encrypted-limited-or-incomplete')
        elif candidate == 'detected':
            record.update(outcome='detected', reason='scanner-detection')
        elif database_profile == 'legal-redress':
            record.update(outcome='held', reason='parser-completeness-unproven')
        elif candidate == 'clean':
            record.update(outcome='clean', reason='full-database-no-detection')
        else:
            raise ValueError('unknown candidate outcome')
        if sha(original) != record['sha256'] or sha(manifest_path) != manifest_hash:
            raise ValueError('original or generation changed during assessment')
        record['release_qualified'] = database_profile == 'full' and record['outcome'] == 'clean'
    except BlockingIOError:
        record.update(outcome='held', reason='scanner-busy-retry', release_qualified=False)
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError, OverflowError) as exc:
        record.update(outcome='failed', reason=str(exc), release_qualified=False)
    record['assessment_finished_unix'] = time.time()
    record['linux_process_high_water_kib'] = {
        'parent': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'terminated_children_max': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        'note': 'separate high-water values, not simultaneous or cgroup charge'}
    write_json(folder/('attempt-'+attempt+'-result.json'), record)
    write_json(folder/'record.json', record)
    return record


def assess(folder, generation, probe, lib, certs, broad=False, database_profile='full',
           *, timeout=180, cpu_seconds=120, address_space_mib=2048, max_database_age_hours=48):
    folder = private_directory(folder)
    private_directory(folder.parent)
    with exclusive_lock(folder/'.assessment.lock'):
        return _assess_locked(folder, generation, probe, lib, certs, broad, database_profile,
                              timeout, cpu_seconds, address_space_mib, max_database_age_hours)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('source', 'quarantine', 'generation', 'probe', 'lib', 'certs'):
        p.add_argument('--'+key, type=Path, required=True)
    p.add_argument('--broad', action='store_true')
    p.add_argument('--database-profile', choices=PROFILES, default='full')
    p.add_argument('--max-source-mib', type=int, default=100)
    p.add_argument('--timeout', type=float, default=180)
    p.add_argument('--cpu-seconds', type=int, default=120)
    p.add_argument('--address-space-mib', type=int, default=2048)
    p.add_argument('--max-database-age-hours', type=float, default=48)
    a = p.parse_args()
    try:
        folder, _ = preserve(a.source, a.quarantine, a.max_source_mib*1024*1024)
        result = assess(folder, a.generation, a.probe, a.lib, a.certs, a.broad, a.database_profile,
                        timeout=a.timeout, cpu_seconds=a.cpu_seconds, address_space_mib=a.address_space_mib,
                        max_database_age_hours=a.max_database_age_hours)
    except (OSError, ValueError) as exc:
        print(json.dumps({'outcome': 'failed', 'release_qualified': False, 'reason': str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return {'clean': 0, 'detected': 1, 'failed': 2, 'held': 3}[result['outcome']]


if __name__ == '__main__':
    raise SystemExit(main())
