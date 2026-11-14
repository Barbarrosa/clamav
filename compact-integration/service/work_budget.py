"""Bounded, durable CPU admission for a single service account.

Charges are conservative work envelopes, never estimates refunded after a scan.
Minute buckets include the whole partial boundary minute. Pending work counts in
all windows until completion, or settlement at its persisted deadline.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import time

WINDOWS = {'hour': 3600, 'day': 86400, 'month': 2678400}
RING_SLOTS = 44642
PENDING_SLOTS = 128
_HEADER = struct.Struct('<8sIQQ')
_BUCKET = struct.Struct('<IQQ')
_PENDING = struct.Struct('<16sIIQB7x')
_MAGIC = b'CMCPUB01'
_MARKER = b'CMCPU001'
_VERSION = 1
_RING_START = _HEADER.size
_PENDING_START = _RING_START + RING_SLOTS * _BUCKET.size
_DATA_SIZE = _PENDING_START + PENDING_SLOTS * _PENDING.size
METADATA_BYTES = _DATA_SIZE + 32
_FILENAME = 'service-work-budget.bin'
_LOCKNAME = 'service-budget.lock'
_TEMPFILE = '.service-work-budget.tmp'
_MAX_U32 = (1 << 32) - 1
_MAX_U64 = (1 << 64) - 1


class BudgetDeferred(RuntimeError):
    def __init__(self, reason: str, retry_after: int = 1):
        self.reason = reason
        self.retry_after = max(1, int(retry_after))
        super().__init__(reason)


class Lease:
    """One open-file-description lease; inherited descriptors retain its lock."""
    def __init__(self, fd: int):
        self.fd = fd

    def close(self) -> None:
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            os.close(fd)  # Never LOCK_UN: a child may still own this OFD.


def _private(info: os.stat_result, directory: bool = False) -> None:
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    mode = 0o700 if directory else 0o600
    if (not valid_type or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != mode or (not directory and info.st_nlink != 1)):
        raise BudgetDeferred('budget_state_invalid')


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _directory(state: Path) -> int:
    try:
        before = state.lstat()
        _private(before, True)
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            after = os.fstat(fd)
            _private(after, True)
            if not _same(before, after) or not _same(after, state.lstat()):
                raise BudgetDeferred('budget_state_invalid')
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError as error:
        raise BudgetDeferred('budget_state_invalid') from error


def acquire_lease(state: Path, name: str) -> Lease | None:
    """Secure nonblocking process lease, shared by all service instances."""
    if not isinstance(name, str) or re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}', name) is None:
        raise BudgetDeferred('budget_state_invalid')
    state = Path(state)
    directory = _directory(state)
    fd = -1
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        _private(os.fstat(fd))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            fd = -1
            return None
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _private(current)
        if (not _same(os.fstat(fd), current)
                or not _same(os.fstat(directory), state.lstat())):
            raise BudgetDeferred('budget_state_invalid')
        lease, fd = Lease(fd), -1
        return lease
    except OSError as error:
        raise BudgetDeferred('budget_state_invalid') from error
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory)


class BudgetLedger:
    def __init__(self, state: Path, hourly_seconds: int | None,
                 daily_seconds: int | None, monthly_seconds: int | None,
                 clock=time.time):
        self.state = Path(state)
        self.allocations = dict(zip(WINDOWS, (hourly_seconds, daily_seconds, monthly_seconds)))
        self.clock = clock

    def _known(self) -> None:
        if any(type(value) is not int or value <= 0 or value > _MAX_U64 // 1000
               for value in self.allocations.values()):
            raise BudgetDeferred('cpu_allocation_unknown')

    def _now(self) -> int:
        value = self.clock()
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or isinstance(value, float) and not math.isfinite(value) or value < 1
                or value >= _MAX_U32 - 60):
            raise BudgetDeferred('budget_state_invalid')
        whole = int(value)
        return whole * 1_000_000_000 + int((value - whole) * 1_000_000_000)

    def _read(self, directory: int, lease: Lease, now: int):
        marker = os.pread(lease.fd, len(_MARKER) + 1, 0)
        if marker not in (b'', _MARKER):
            raise BudgetDeferred('budget_state_invalid')
        fd = -1
        try:
            try:
                fd = os.open(_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            except FileNotFoundError:
                if marker:
                    raise BudgetDeferred('budget_state_invalid')
                raw = bytearray(_DATA_SIZE)
                _HEADER.pack_into(raw, 0, _MAGIC, _VERSION, now, 0)
                return raw, None
            info = os.fstat(fd)
            _private(info)
            if info.st_size != METADATA_BYTES:
                raise BudgetDeferred('budget_state_invalid')
            raw = bytearray()
            while len(raw) < METADATA_BYTES:
                chunk = os.read(fd, METADATA_BYTES - len(raw))
                if not chunk:
                    raise BudgetDeferred('budget_state_invalid')
                raw.extend(chunk)
            current = os.stat(_FILENAME, dir_fd=directory, follow_symlinks=False)
            _private(current)
            if not _same(info, current) or not hmac.compare_digest(hashlib.sha256(raw[:-32]).digest(), raw[-32:]):
                raise BudgetDeferred('budget_state_invalid')
            del raw[-32:]
            magic, version, last_now, scan_next = _HEADER.unpack_from(raw)
            if magic != _MAGIC or version != _VERSION or last_now < 1 or last_now > _MAX_U32 * 1_000_000_000:
                raise BudgetDeferred('budget_state_invalid')
            if now < last_now:
                raise BudgetDeferred('clock_rollback', math.ceil((last_now - now) / 1_000_000_000))
            latest_minute = (last_now // 1_000_000_000 // 60) * 60
            for index in range(RING_SLOTS):
                epoch, total, scan = _BUCKET.unpack_from(raw, _RING_START + index * _BUCKET.size)
                if ((epoch == 0 and (total or scan)) or (epoch and (epoch % 60 or epoch > latest_minute
                        or epoch // 60 % RING_SLOTS != index or not total or scan > total))):
                    raise BudgetDeferred('budget_state_invalid')
            tokens = set()
            for index in range(PENDING_SLOTS):
                token, created, deadline, charge, kind = self._pending(raw, index)
                if token == bytes(16):
                    if created or deadline or charge or kind:
                        raise BudgetDeferred('budget_state_invalid')
                elif (token in tokens or not 0 < created <= last_now // 1_000_000_000
                      or deadline < created or charge < 1000 or kind not in (1, 2)):
                    raise BudgetDeferred('budget_state_invalid')
                else:
                    tokens.add(token)
            return raw, info
        except OSError as error:
            raise BudgetDeferred('budget_state_invalid') from error
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _pending(raw, index):
        return _PENDING.unpack_from(raw, _PENDING_START + index * _PENDING.size)

    @staticmethod
    def _clear_pending(raw, index):
        start = _PENDING_START + index * _PENDING.size
        raw[start:start + _PENDING.size] = bytes(_PENDING.size)

    def _add(self, raw, second, charge, kind, now):
        # An already expired crash charge contributes to no current window.
        if second < now // 1_000_000_000 - WINDOWS['month'] - 60:
            return
        epoch = second // 60 * 60
        index = epoch // 60 % RING_SLOTS
        offset = _RING_START + index * _BUCKET.size
        previous, total, scan = _BUCKET.unpack_from(raw, offset)
        if previous != epoch:
            if previous and previous >= now // 1_000_000_000 - WINDOWS['month'] - 60:
                raise BudgetDeferred('budget_capacity')
            total = scan = 0
        total += charge
        scan += charge if kind == 1 else 0
        if max(total, scan) > _MAX_U64:
            raise BudgetDeferred('budget_capacity')
        _BUCKET.pack_into(raw, offset, epoch, total, scan)

    def _settle(self, raw, now):
        for index in range(PENDING_SLOTS):
            token, created, deadline, charge, kind = self._pending(raw, index)
            if token != bytes(16) and deadline * 1_000_000_000 <= now:
                self._add(raw, deadline, charge, kind, now)
                self._clear_pending(raw, index)

    def _usage(self, raw, now):
        totals = {name: [0, 0] for name in WINDOWS}
        pending = 0
        for index in range(RING_SLOTS):
            epoch, total, scan = _BUCKET.unpack_from(raw, _RING_START + index * _BUCKET.size)
            if epoch:
                for name, seconds in WINDOWS.items():
                    # Retain the entire partially overlapping oldest minute.
                    if (epoch + 60 + seconds) * 1_000_000_000 > now:
                        totals[name][0] += total
                        totals[name][1] += scan
        for index in range(PENDING_SLOTS):
            token, _, _, charge, kind = self._pending(raw, index)
            if token != bytes(16):
                pending += 1
                for total in totals.values():
                    total[0] += charge
                    total[1] += charge if kind == 1 else 0
        return totals, pending

    def _save(self, directory, lease, raw, previous):
        if not _same(os.fstat(directory), self.state.lstat()):
            raise BudgetDeferred('budget_state_invalid')
        try:
            current = os.stat(_FILENAME, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            _private(current)
        if (previous is None) != (current is None) or previous is not None and not _same(previous, current):
            raise BudgetDeferred('budget_state_invalid')
        temporary = _TEMPFILE
        fd = -1
        try:
            # A crash can leave at most one staging file. Its unpublished
            # contents never authorized work; the old committed debt wins.
            try:
                stale = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                stale = None
            if stale is not None:
                _private(stale)
                os.unlink(temporary, dir_fd=directory)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            output = raw + hashlib.sha256(raw).digest()
            offset = 0
            while offset < len(output):
                written = os.write(fd, memoryview(output)[offset:])
                if written <= 0:
                    raise OSError('incomplete budget write')
                offset += written
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, _FILENAME, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            os.pwrite(lease.fd, _MARKER, 0)
            os.ftruncate(lease.fd, len(_MARKER))
            os.fsync(lease.fd)
        except OSError as error:
            raise BudgetDeferred('budget_state_invalid') from error
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    def _transaction(self, action, *, readonly_missing=False):
        if readonly_missing:
            # A status read before any work must not initialize durable debt or
            # even create the coordination file. A concurrent first admission
            # can linearize after this empty observation.
            directory = _directory(self.state)
            try:
                absent = []
                for name in (_FILENAME, _LOCKNAME):
                    try:
                        os.stat(name, dir_fd=directory, follow_symlinks=False)
                        absent.append(False)
                    except FileNotFoundError:
                        absent.append(True)
                if all(absent):
                    now = self._now()
                    raw = bytearray(_DATA_SIZE)
                    _HEADER.pack_into(raw, 0, _MAGIC, _VERSION, now, 0)
                    return action(raw, now)
            finally:
                os.close(directory)
        lease = acquire_lease(self.state, _LOCKNAME)
        if lease is None:
            raise BudgetDeferred('budget_busy')
        directory = -1
        try:
            directory = _directory(self.state)
            now = self._now()
            raw, previous = self._read(directory, lease, now)
            before = bytes(raw)
            self._settle(raw, now)
            try:
                result = action(raw, now)
            except BudgetDeferred:
                # Persist a stale settlement even if new work was refused. A
                # pure refusal does not rewrite the large ledger or its clock.
                if raw != before:
                    _, _, _, scan_next = _HEADER.unpack_from(raw)
                    _HEADER.pack_into(raw, 0, _MAGIC, _VERSION, now, scan_next)
                    self._save(directory, lease, raw, previous)
                raise
            if raw != before:
                _, _, _, scan_next = _HEADER.unpack_from(raw)
                _HEADER.pack_into(raw, 0, _MAGIC, _VERSION, now, scan_next)
                self._save(directory, lease, raw, previous)
            return result
        finally:
            if directory >= 0:
                os.close(directory)
            lease.close()

    def reserve(self, kind: str, cpu_seconds: float, wall_seconds: float) -> str:
        self._known()
        if kind not in ('scan', 'maintenance'):
            raise ValueError('invalid work kind')
        if any(isinstance(value, bool) or not isinstance(value, (int, float))
               or isinstance(value, float) and not math.isfinite(value) or value <= 0
               for value in (cpu_seconds, wall_seconds)):
            raise ValueError('work envelopes must be finite and positive')
        if cpu_seconds > _MAX_U64 / 1000 or wall_seconds > _MAX_U32:
            raise BudgetDeferred('budget_capacity')
        charge = max(1000, math.ceil(cpu_seconds * 1000))
        if charge > _MAX_U64:
            raise BudgetDeferred('budget_capacity')
        code = 1 if kind == 'scan' else 2

        def admit(raw, now):
            _, _, _, scan_next = _HEADER.unpack_from(raw)
            if kind == 'scan' and now < scan_next:
                raise BudgetDeferred('scan_paced', math.ceil((scan_next - now) / 1_000_000_000))
            totals, _ = self._usage(raw, now)
            for name, allocation in self.allocations.items():
                total, scan = totals[name]
                if total + charge > allocation * 1000 or kind == 'scan' and scan + charge > allocation * 800:
                    raise BudgetDeferred('cpu_budget_exhausted', 60)
            free = next((index for index in range(PENDING_SLOTS)
                         if self._pending(raw, index)[0] == bytes(16)), None)
            deadline = (now + math.ceil(wall_seconds * 1_000_000_000) + 999_999_999) // 1_000_000_000
            if free is None or deadline > _MAX_U32:
                raise BudgetDeferred('budget_capacity')
            next_at = scan_next
            if kind == 'scan':
                interval = max((charge * seconds * 1_000_000_000 + allocation * 800 - 1)
                               // (allocation * 800)
                               for (name, seconds), allocation in zip(WINDOWS.items(), self.allocations.values()))
                next_at = now + interval
                if next_at > _MAX_U64:
                    raise BudgetDeferred('budget_capacity')
            token = secrets.token_bytes(16)
            while token == bytes(16) or any(self._pending(raw, index)[0] == token for index in range(PENDING_SLOTS)):
                token = secrets.token_bytes(16)
            _PENDING.pack_into(raw, _PENDING_START + free * _PENDING.size,
                               token, now // 1_000_000_000, deadline, charge, code)
            _HEADER.pack_into(raw, 0, _MAGIC, _VERSION, now, next_at)
            return token.hex()
        return self._transaction(admit)

    def finish(self, token: str) -> None:
        if not isinstance(token, str) or re.fullmatch('[0-9a-f]{32}', token) is None:
            raise ValueError('invalid budget token')
        binary = bytes.fromhex(token)

        def complete(raw, now):
            for index in range(PENDING_SLOTS):
                present, _, _, charge, kind = self._pending(raw, index)
                if present != bytes(16) and present == binary:
                    self._add(raw, now // 1_000_000_000, charge, kind, now)
                    self._clear_pending(raw, index)
                    return
        self._transaction(complete)

    def snapshot(self) -> dict:
        def report(raw, now):
            totals, pending = self._usage(raw, now)
            windows = {}
            known = all(type(value) is int and value > 0 and value <= _MAX_U64 // 1000
                        for value in self.allocations.values())
            for name, (total, scan) in totals.items():
                allocation = self.allocations[name] if known else None
                windows[name] = {'total_seconds': total / 1000, 'scan_seconds': scan / 1000,
                    'total_remaining_seconds': None if allocation is None else max(0, allocation - total / 1000),
                    'scan_remaining_seconds': None if allocation is None else max(0, min(allocation - total / 1000,
                                                                                       allocation * 0.8 - scan / 1000))}
            return {'allocations_seconds': {name: value if type(value) is int and 0 < value <= _MAX_U64 // 1000 else None
                                            for name, value in self.allocations.items()}, 'windows': windows,
                    'pending_reservations': pending, 'scan_next_at': _HEADER.unpack_from(raw)[3] / 1_000_000_000,
                    'metadata_bytes': METADATA_BYTES, 'bucket_seconds': 60,
                    'month_seconds': WINDOWS['month'], 'charges_are_conservative': True}
        return self._transaction(report, readonly_missing=True)
