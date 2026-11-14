#!/usr/bin/env python3
"""Durable bounded CPU envelopes and process-wide admission leases."""
import importlib.util
import hashlib
import multiprocessing
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('compact_work_budget', ROOT / 'service/work_budget.py')
budget = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = budget
spec.loader.exec_module(budget)


def lease_child(state, name, connection):
    lease = budget.acquire_lease(Path(state), name)
    connection.send(lease is not None)
    if lease is not None:
        connection.recv()
        lease.close()
    connection.close()


class WorkBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='compact-budget-')
        self.state = Path(self.temporary.name)
        self.state.chmod(0o700)
        self.now = 1800000000.0
        self.ledger = self.make()

    def tearDown(self):
        self.temporary.cleanup()

    def make(self, hourly=3600, daily=86400, monthly=2678400):
        return budget.BudgetLedger(self.state, hourly, daily, monthly, clock=lambda: self.now)

    def deferred(self, reason, call):
        with self.assertRaises(budget.BudgetDeferred) as caught:
            call()
        self.assertEqual(caught.exception.reason, reason)
        self.assertGreaterEqual(caught.exception.retry_after, 1)
        return caught.exception

    def test_tiny_requests_have_floor_and_pacing_without_burst_credit(self):
        token = self.ledger.reserve('scan', 0.00001, 10)
        self.assertEqual(self.ledger.snapshot()['windows']['hour']['total_seconds'], 1)
        self.ledger.finish(token)
        self.deferred('scan_paced', lambda: self.ledger.reserve('scan', 0.00001, 10))
        self.now += 1.25
        self.ledger.finish(self.ledger.reserve('scan', 0.00001, 10))
        self.now += 10000
        self.ledger.finish(self.ledger.reserve('scan', 0.00001, 10))
        self.deferred('scan_paced', lambda: self.ledger.reserve('scan', 0.00001, 10))

    def test_scan_eighty_percent_and_maintenance_can_use_reserved_remainder(self):
        ledger = self.make(10, 1000, 100000)
        token = ledger.reserve('scan', 8, 10)
        self.deferred('scan_paced', lambda: ledger.reserve('scan', 1, 10))
        maintenance = ledger.reserve('maintenance', 2, 10)
        self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 0.001, 10))
        ledger.finish(token)
        ledger.finish(maintenance)
        report = ledger.snapshot()['windows']['hour']
        self.assertEqual(report['scan_seconds'], 8)
        self.assertEqual(report['total_seconds'], 10)
        self.assertEqual(report['scan_remaining_seconds'], 0)

    def test_maintenance_can_use_allocation_without_scans(self):
        ledger = self.make(10, 20, 30)
        ledger.finish(ledger.reserve('maintenance', 10, 2))
        self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 1, 2))

    def test_independent_hour_day_and_rolling_31_day_exhaustion(self):
        for window, arguments in [('hour', (2, 100, 1000)),
                                  ('day', (100, 2, 1000)), ('month', (100, 1000, 2))]:
            with self.subTest(window=window), tempfile.TemporaryDirectory(dir=self.state) as path:
                os.chmod(path, 0o700)
                ledger = budget.BudgetLedger(Path(path), *arguments, clock=lambda: self.now)
                ledger.finish(ledger.reserve('maintenance', 2, 1))
                self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 1, 1))
                self.now += budget.WINDOWS[window] - 1
                self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 1, 1))
                self.now += 62
                self.assertIsInstance(ledger.reserve('maintenance', 1, 1), str)
        self.assertEqual(budget.WINDOWS['month'], 31 * 86400)

    def test_partial_boundary_minute_is_retained_conservatively(self):
        self.now = self.now // 60 * 60 + 1
        ledger = self.make(1, 100, 10000)
        ledger.finish(ledger.reserve('maintenance', 1, 1))
        self.now += 3600
        self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 1, 1))
        self.now = self.now // 60 * 60 + 60
        self.assertIsInstance(ledger.reserve('maintenance', 1, 1), str)

    def test_invalid_and_unrepresentable_work_never_authorizes(self):
        for cpu, wall in [(0, 1), (1, 0), (True, 1), ('1', 1), (float('inf'), 1), (1, float('nan'))]:
            with self.assertRaises(ValueError):
                self.ledger.reserve('maintenance', cpu, wall)
        for cpu, wall in [(10 ** 1000, 1), (1, 10 ** 1000), (budget._MAX_U64 / 1000, 1)]:
            self.deferred('budget_capacity', lambda: self.ledger.reserve('maintenance', cpu, wall))
        self.assertFalse((self.state / budget._FILENAME).exists())

    def test_unknown_allocations_block_both_work_classes(self):
        for missing in (None, 0, -1, 1.5, True, '10'):
            for kind in ('scan', 'maintenance'):
                self.deferred('cpu_allocation_unknown', lambda: self.make(hourly=missing).reserve(kind, 1, 2))
        self.assertFalse((self.state / budget._FILENAME).exists())

    def test_restart_preserves_pending_and_full_charge_without_refunds(self):
        token = self.ledger.reserve('maintenance', 5, 60)
        restarted = self.make()
        self.assertEqual(restarted.snapshot()['pending_reservations'], 1)
        self.assertEqual(restarted.snapshot()['windows']['month']['total_seconds'], 5)
        restarted.finish(token)
        restarted.finish(token)
        self.assertEqual(self.make().snapshot()['windows']['month']['total_seconds'], 5)
        self.assertEqual(self.make().snapshot()['pending_reservations'], 0)

    def test_unknown_and_zero_tokens_cannot_create_or_refund_charges(self):
        self.ledger.finish('0' * 32)
        self.ledger.finish('f' * 32)
        self.assertEqual(self.ledger.snapshot()['windows']['month']['total_seconds'], 0)
        self.ledger.reserve('maintenance', 5, 10)
        self.ledger.finish('0' * 32)
        self.assertEqual(self.ledger.snapshot()['windows']['month']['total_seconds'], 5)

    def test_crashed_pending_settles_at_deadline_and_late_finish_never_refunds(self):
        token = self.ledger.reserve('maintenance', 5, 120)
        self.now += 121
        report = self.make().snapshot()
        self.assertEqual(report['pending_reservations'], 0)
        self.assertEqual(report['windows']['hour']['total_seconds'], 5)
        self.make().finish(token)
        self.assertEqual(self.make().snapshot()['windows']['hour']['total_seconds'], 5)
        self.now += 3600 + 60
        self.assertEqual(self.make().snapshot()['windows']['hour']['total_seconds'], 0)
        self.assertEqual(self.make().snapshot()['windows']['month']['total_seconds'], 5)

    def test_pending_counts_all_windows_even_when_created_long_ago(self):
        self.ledger.reserve('maintenance', 5, 10000)
        self.now += 4000
        self.assertEqual(self.make().snapshot()['windows']['hour']['total_seconds'], 5)

    def test_changed_config_preserves_history_and_pacing_debt(self):
        token = self.ledger.reserve('scan', 1, 10)
        self.ledger.finish(token)
        next_at = self.ledger.snapshot()['scan_next_at']
        raised = self.make(1000000, 10000000, 100000000)
        self.deferred('scan_paced', lambda: raised.reserve('scan', 1, 10))
        self.assertEqual(raised.snapshot()['scan_next_at'], next_at)
        lowered = self.make(1, 1, 1)
        self.deferred('cpu_budget_exhausted', lambda: lowered.reserve('maintenance', 1, 10))
        self.assertEqual(lowered.snapshot()['windows']['month']['total_seconds'], 1)

    def test_clock_rollback_holds_without_modifying_debt(self):
        token = self.ledger.reserve('maintenance', 2, 10)
        before = (self.state / budget._FILENAME).read_bytes()
        self.now -= 1
        self.deferred('clock_rollback', lambda: self.make().snapshot())
        self.deferred('clock_rollback', lambda: self.make().finish(token))
        self.assertEqual((self.state / budget._FILENAME).read_bytes(), before)
        self.now += 1
        self.assertEqual(self.ledger.snapshot()['windows']['month']['total_seconds'], 2)

    def test_size_checksum_and_deleted_file_never_reset_debt(self):
        self.ledger.finish(self.ledger.reserve('maintenance', 3, 10))
        path = self.state / budget._FILENAME
        original = path.read_bytes()
        for bad in (b'', original[:-1], original + b'x', original[:100] + b'x' + original[101:]):
            with self.subTest(size=len(bad)):
                path.write_bytes(bad)
                self.deferred('budget_state_invalid', lambda: self.make().reserve('maintenance', 1, 10))
                self.assertEqual(path.read_bytes(), bad)
        path.unlink()
        self.deferred('budget_state_invalid', lambda: self.make().reserve('maintenance', 1, 10))
        self.assertFalse(path.exists())
        path.write_bytes(original)
        path.chmod(0o600)
        self.assertEqual(self.make().snapshot()['windows']['month']['total_seconds'], 3)

    def test_semantically_corrupt_valid_checksum_holds(self):
        self.ledger.finish(self.ledger.reserve('maintenance', 1, 2))
        path = self.state / budget._FILENAME
        raw = bytearray(path.read_bytes()[:-32])
        budget._BUCKET.pack_into(raw, budget._RING_START, 60, 2, 3)
        path.write_bytes(raw + hashlib.sha256(raw).digest())
        self.deferred('budget_state_invalid', self.ledger.snapshot)

    def test_status_and_denials_never_rewrite_unchanged_state(self):
        self.assertEqual(self.ledger.snapshot()['pending_reservations'], 0)
        self.assertEqual(list(self.state.iterdir()), [])
        self.ledger.finish('f' * 32)
        self.assertFalse((self.state / budget._FILENAME).exists())
        self.assertEqual((self.state / budget._LOCKNAME).read_bytes(), b'')
        self.ledger.reserve('scan', 1, 100)
        path = self.state / budget._FILENAME
        before = path.stat()
        contents = path.read_bytes()
        lock = self.state / budget._LOCKNAME
        lock_before = lock.stat()
        marker = lock.read_bytes()
        for _ in range(3):
            self.ledger.snapshot()
            self.ledger.finish('f' * 32)
            self.deferred('scan_paced', lambda: self.ledger.reserve('scan', 1, 100))
        self.now += 0.25
        self.ledger.snapshot()
        self.assertEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(path.read_bytes(), contents)
        self.assertEqual(lock.read_bytes(), marker)
        self.assertEqual(lock.stat().st_ino, lock_before.st_ino)
        self.assertEqual(lock.stat().st_mtime_ns, lock_before.st_mtime_ns)

    def test_exhausted_denial_does_not_write_but_stale_settlement_does(self):
        ledger = self.make(1, 100, 10000)
        ledger.reserve('maintenance', 1, 2)
        path = self.state / budget._FILENAME
        before = path.stat()
        self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 1, 2))
        self.assertEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
        self.now += 3
        self.deferred('cpu_budget_exhausted', lambda: ledger.reserve('maintenance', 1, 2))
        self.assertNotEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(self.make(1, 100, 10000).snapshot()['pending_reservations'], 0)
        self.assertEqual(self.make(1, 100, 10000).snapshot()['windows']['hour']['total_seconds'], 1)

    def test_fixed_size_bounded_capacity_and_staging_recovery(self):
        for _ in range(budget.PENDING_SLOTS):
            self.ledger.reserve('maintenance', 1, 600)
        self.deferred('budget_capacity', lambda: self.ledger.reserve('maintenance', 1, 600))
        self.assertEqual(self.ledger.snapshot()['pending_reservations'], budget.PENDING_SLOTS)
        path = self.state / budget._FILENAME
        self.assertEqual(path.stat().st_size, budget.METADATA_BYTES)
        self.assertLess(budget.METADATA_BYTES, 1024 * 1024)
        staging = self.state / budget._TEMPFILE
        staging.write_bytes(b'incomplete old staging')
        staging.chmod(0o600)
        self.now += 601
        self.ledger.snapshot()
        self.assertFalse(staging.exists())
        self.assertEqual(sorted(p.name for p in self.state.iterdir()),
                         sorted([budget._FILENAME, budget._LOCKNAME]))

    def test_ring_wrap_retains_only_live_debt_without_growth(self):
        token = self.ledger.reserve('maintenance', 1, 2)
        self.ledger.finish(token)
        self.now += (budget.RING_SLOTS + 5) * 60
        self.ledger.finish(self.ledger.reserve('maintenance', 2, 2))
        self.assertEqual(self.ledger.snapshot()['windows']['month']['total_seconds'], 2)
        self.assertEqual((self.state / budget._FILENAME).stat().st_size, budget.METADATA_BYTES)

    def test_private_file_symlink_hardlink_and_owner_checks(self):
        self.ledger.finish(self.ledger.reserve('maintenance', 1, 2))
        path = self.state / budget._FILENAME
        path.chmod(0o644)
        self.deferred('budget_state_invalid', self.ledger.snapshot)
        path.chmod(0o600)
        link = self.state / 'hardlink'
        os.link(path, link)
        self.deferred('budget_state_invalid', self.ledger.snapshot)
        link.unlink()
        original = path.read_bytes()
        path.unlink()
        target = self.state / 'target'
        target.write_bytes(original)
        target.chmod(0o600)
        path.symlink_to(target)
        self.deferred('budget_state_invalid', self.ledger.snapshot)
        with mock.patch.object(budget.os, 'geteuid', return_value=os.geteuid() + 1):
            self.deferred('budget_state_invalid', lambda: budget.acquire_lease(self.state, 'other.lock'))

    def test_nonblocking_metadata_lock(self):
        self.ledger.reserve('maintenance', 1, 2)
        lease = budget.acquire_lease(self.state, budget._LOCKNAME)
        try:
            self.deferred('budget_busy', self.ledger.snapshot)
        finally:
            lease.close()
        self.ledger.snapshot()

    def test_independent_process_observes_same_lease(self):
        ctx = multiprocessing.get_context('fork')
        parent, child = ctx.Pipe()
        process = ctx.Process(target=lease_child, args=(str(self.state), 'work.lock', child))
        process.start()
        try:
            self.assertTrue(parent.recv())
            self.assertIsNone(budget.acquire_lease(self.state, 'work.lock'))
            parent.send('close')
            process.join(5)
            self.assertEqual(process.exitcode, 0)
            lease = budget.acquire_lease(self.state, 'work.lock')
            self.assertIsNotNone(lease)
            lease.close()
        finally:
            if process.is_alive():
                process.kill()
                process.join()
            parent.close()
            child.close()

    def test_parent_close_does_not_unlock_inherited_open_file_description(self):
        lease = budget.acquire_lease(self.state, 'inherited.lock')
        started_read, started_write = os.pipe()
        release_read, release_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(started_read)
                os.close(release_write)
                os.write(started_write, b'1')
                os.read(release_read, 1)
                lease.close()
            finally:
                os._exit(0)
        os.close(started_write)
        os.close(release_read)
        try:
            self.assertEqual(os.read(started_read, 1), b'1')
            lease.close()
            self.assertIsNone(budget.acquire_lease(self.state, 'inherited.lock'))
            os.write(release_write, b'1')
            os.waitpid(pid, 0)
            pid = -1
            replacement = budget.acquire_lease(self.state, 'inherited.lock')
            self.assertIsNotNone(replacement)
            replacement.close()
        finally:
            if pid > 0:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            os.close(started_read)
            os.close(release_write)
            lease.close()

    def test_lease_rejects_unsafe_paths_modes_links(self):
        for name in ('../outside', '/absolute', '', 'x/' ):
            self.deferred('budget_state_invalid', lambda: budget.acquire_lease(self.state, name))
        target = self.state / 'target.lock'
        target.touch(mode=0o600)
        (self.state / 'symlink.lock').symlink_to(target)
        self.deferred('budget_state_invalid', lambda: budget.acquire_lease(self.state, 'symlink.lock'))
        os.link(target, self.state / 'hardlink.lock')
        self.deferred('budget_state_invalid', lambda: budget.acquire_lease(self.state, 'hardlink.lock'))
        self.state.chmod(0o755)
        self.deferred('budget_state_invalid', lambda: budget.acquire_lease(self.state, 'new.lock'))
        self.state.chmod(0o700)


if __name__ == '__main__':
    unittest.main()
