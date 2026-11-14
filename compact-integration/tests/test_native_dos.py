#!/usr/bin/env python3
"""Exercise actual native lifecycle limits with tiny upstream TEST-signed CVDs.

No network, production trust changes, or alternate signature parser. The isolated
LD_PRELOAD diagnostic only delays cleanup/input reads and observes module loading.
Production callers explicitly strip these hooks from their environments.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import zipfile

import fixtures


def wait_event(path, event, process, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and event in path.read_text().splitlines():
            return
        assert process.poll() is None, (event, process.returncode)
        time.sleep(0.01)
    raise AssertionError(f"Native probe never reached {event}")


def locked(path):
    with path.open("rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def full_pipe():
    readfd, writefd = os.pipe()
    flags = fcntl.fcntl(writefd, fcntl.F_GETFL)
    fcntl.fcntl(writefd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    try:
        while True:
            os.write(writefd, b"x" * 4096)
    except BlockingIOError:
        pass
    fcntl.fcntl(writefd, fcntl.F_SETFL, flags)
    return readfd, writefd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--updater", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    observations = {}
    with tempfile.TemporaryDirectory(prefix="compact-native-dos-") as temporary:
        root = Path(temporary)
        state = root / "state"
        state.mkdir(mode=0o700)
        generation = state / "generation"
        databases = generation / "databases"
        databases.mkdir(parents=True)
        trust = args.source / "unit_tests/input/signing/verify"
        original = args.source / "unit_tests/input/freshclam_testfiles"
        for stem, version in (("main", 1), ("daily", 2), ("bytecode", 3)):
            shutil.copyfile(original / f"test-{version}.cvd", databases / f"{stem}.cvd")
            shutil.copyfile(original / f"test-{version}.cvd.sign", databases / f"{stem}-{version}.cvd.sign")
        hook = root / "lifecycle-hooks.so"
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-shared", "-fPIC", str(tests / "native_lifecycle_hooks.c"), "-ldl", "-o", str(hook)], check=True)
        policy = {"as-bytes": str(512 * 1024**2), "cpu-seconds": "30", "wall-seconds": "15", "file-bytes": str(64 * 1024**2)}

        def environment(**extra):
            result = {k: v for k, v in os.environ.items() if k not in ("LD_PRELOAD", "COMPACT_PARENT_PID")}
            result.update(COMPACT_PARENT_PID=str(os.getpid()))
            result.update(extra)
            return result

        def command(action, *, wall=None, **options):
            values = {"state": str(state), **policy, **options}
            if wall is not None:
                values["wall-seconds"] = str(wall)
            return [args.scanner, action, *[v for k, value in values.items() for v in ("--" + k, str(value))]]

        def run(arguments, **extra):
            result = subprocess.run(arguments, env=environment(**extra), capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, (arguments, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)

        identity = run(command("doctor"))
        prepared = run(command("prepare", generation=generation, certs=trust, **{"line-bytes": "131072"}))
        assert prepared["status"] == "prepared" and all(s["signature_verified"] for s in prepared["sources"])
        # Stock tests authenticate and native-load every TEST-signed source. These
        # are test trust roots only; production certificate policy is unchanged.
        with (state / "job.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            internal = environment()
            internal.update({"COMPACT_UPDATE_" + k: str(v) for k, v in {
                "as_bytes": 512 * 1024**2, "cpu_seconds": 30, "wall_seconds": 15, "file_bytes": 64 * 1024**2,
                "line_bytes": 131072, "connect_seconds": 1, "low_speed_seconds": 1, "attempts": 1,
                "age_seconds": 10**9, "reserve_bytes": 1, "max_state_bytes": 1024**3, "max_state_inodes": 10000,
            }.items()})
            for stem in ("main", "daily", "bytecode"):
                result = subprocess.run([args.updater, "test-db", "--state", str(state), "--certs", str(trust),
                                         "--database", str(databases / f"{stem}.cvd"), "--lock-fd", str(lock.fileno())],
                                        env=internal, pass_fds=(lock.fileno(),), capture_output=True, text=True, timeout=20)
                assert result.returncode == 0, (stem, result.returncode, result.stderr)
        members = {str(p.relative_to(generation)): {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size}
                   for p in sorted(generation.rglob("*")) if p.is_file()}
        gid = hashlib.sha256(json.dumps(members, sort_keys=True).encode()).hexdigest()
        daily_time = next(s["created_at"] for s in prepared["sources"] if s["name"] == "daily.cvd")
        manifest = {"protocol": 1, "generation_id": gid, "created_at": int(time.time()), "database_created_at": daily_time,
                    "engine_version": identity["engine_version"], "engine_sha256": identity["engine_sha256"],
                    "scan_options_sha256": identity["scan_options_sha256"], "files": members,
                    "profile": "pdf-jpeg-png-pe-exclusions", "validation": {"mode": "stock-per-database", "status": "passed"},
                    "qualification": {"coverage_qualified": True, "guard_version": identity["guard_version"],
                                      "ordering_version": identity["ordering_version"]}}
        (generation / "manifest.json").write_text(json.dumps(manifest))
        common = {"generation": generation, "certs": trust, "profile": "pdf-jpeg-png-pe-exclusions", "max-age-seconds": 10**9}
        run(command("self-test", **common))
        observations["real_test_signed_prepare_stock_load_and_selected_compile"] = True

        # Stream a highly compressible member just beyond the native100MiB
        # member limit. The Python parent retains only a fixed1MiB chunk and
        # compressed bytes; the native caller's filesystem cap permits reaching
        # the parser limit instead of failing first on a smaller RLIMIT_FSIZE.
        archive = root / "expanded-member.zip"
        chunk = b"A" * (1024**2)
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
            with zipped.open("expanded.txt", "w", force_zip64=True) as member:
                for _ in range(101):
                    member.write(chunk)
        del chunk
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        started = time.monotonic()
        expanded = subprocess.run(command("scan", **common, input=archive, **{"file-bytes": 256 * 1024**2}),
                                  env=environment(), capture_output=True, text=True, timeout=20)
        elapsed = time.monotonic() - started
        expanded_row = json.loads(expanded.stdout)
        assert expanded.returncode in (1, 2, 3) and expanded_row["status"] != "clean", expanded_row
        assert expanded_row["sha256"] == archive_hash and expanded_row["size"] == archive.stat().st_size, expanded_row
        assert "scan-limit-encryption-or-parser-alert" in expanded_row["reason_codes"], expanded_row
        assert elapsed < 17
        observations["compressed_archive_member_limit"] = {"uncompressed_member_bytes": 101 * 1024**2,
            "compressed_original_bytes": archive.stat().st_size, "sha256": archive_hash,
            "status": expanded_row["status"], "reason_codes": expanded_row["reason_codes"],
            "process_reaped": True, "wall_seconds": elapsed}

        # A completely full undrained pipe must not trap the fatal handler.
        readfd, writefd = full_pipe()
        started = time.monotonic()
        child = subprocess.Popen(command("doctor", wall=1), env=environment(), stdout=writefd, stderr=subprocess.DEVNULL)
        os.close(writefd)
        try:
            assert child.wait(timeout=3) == 2
            observations["full_stdout_pipe_wall_exit_seconds"] = time.monotonic() - started
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(readfd)

        # Parent rejection occurs before handlers are installed; its failure
        # record must also be best-effort rather than blocking forever.
        readfd, writefd = full_pipe()
        started = time.monotonic()
        rejected = subprocess.Popen(command("doctor"), env=environment(COMPACT_PARENT_PID=str(os.getpid() + 100000)),
                                    stdout=writefd, stderr=subprocess.DEVNULL)
        os.close(writefd)
        try:
            assert rejected.wait(timeout=3) == 2
            observations["rejected_parent_full_stdout_exit_seconds"] = time.monotonic() - started
        finally:
            if rejected.poll() is None:
                rejected.kill()
                rejected.wait()
            os.close(readfd)

        # Hold both native engine destruction and libc atexit behind explicit
        # barriers. A second process must stay excluded at both points, and must
        # reject before cl_init rather than merely before database loading.
        free_gate, exit_gate = root / "free-gate", root / "exit-gate"
        audit, busy_audit = root / "cleanup-audit", root / "busy-audit"
        donor = subprocess.Popen(command("self-test", **common), env=environment(
            LD_PRELOAD=str(hook), TEST_NATIVE_HOLD="1", TEST_NATIVE_AUDIT=str(audit),
            TEST_NATIVE_FREE_GATE=str(free_gate), TEST_NATIVE_EXIT_GATE=str(exit_gate)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for phase, gate in (("free-enter", free_gate), ("atexit-enter", exit_gate)):
                wait_event(audit, phase, donor)
                assert locked(state / "job.lock"), phase
                contender = subprocess.run(command("doctor"), env=environment(LD_PRELOAD=str(hook), TEST_NATIVE_AUDIT=str(busy_audit)),
                                           capture_output=True, text=True, timeout=3)
                row = json.loads(contender.stdout)
                assert contender.returncode == 2 and "scanner-or-update-busy" in row["reason_codes"], row
                assert not busy_audit.exists() or "module-bootstrap" not in busy_audit.read_text().splitlines()
                gate.touch()
            stdout, stderr = donor.communicate(timeout=5)
            assert donor.returncode == 0, (stdout, stderr)
            assert not locked(state / "job.lock")
            observations["lock_held_through_engine_free_and_atexit"] = True
            observations["busy_rejected_before_parser_initialization"] = True
        finally:
            if donor.poll() is None:
                donor.kill()
                donor.wait()

        # The full request wall budget starts on receipt, independently of the
        # preceding idle interval. Real input hashes and real scan remain enabled.
        slow, clean, guarded = root / "slow-input.pdf", root / "clean-input.pdf", root / "guarded-input.pdf"
        slow.write_bytes(fixtures.pdf(b"ordinary harmless text"))
        clean.write_bytes(slow.read_bytes())
        guarded.write_bytes(fixtures.pdf(fixtures.make_pe()))
        worker_audit = root / "worker-audit"
        worker = subprocess.Popen(command("worker", wall=3, **common, **{"worker-max-requests": 3}),
                                  env=environment(LD_PRELOAD=str(hook), TEST_NATIVE_AUDIT=str(worker_audit), TEST_NATIVE_SLOW="1"),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            wait_event(worker_audit, "stdin-wait", worker)
            time.sleep(2)
            results = []
            for number, (path, expected_status) in enumerate(((slow, "clean"), (guarded, "held"), (clean, "clean"))):
                worker.stdin.write(json.dumps({"input": str(path), "request_id": str(number)}) + "\n")
                worker.stdin.flush()
                row = json.loads(worker.stdout.readline())
                assert row["status"] == expected_status and row["completed"] and row["request_id"] == str(number), row
                if expected_status == "held":
                    assert "excluded-pe-consumer-reached" in row["reason_codes"] and not row["applicability_proven"]
                assert row["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
                results.append(row["status"])
            worker.stdin.close()
            worker.stdin = None
            _, stderr = worker.communicate(timeout=5)
            assert worker.returncode == 0, stderr
            observations["worker_after_idle_and_second_original"] = results
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait()

        idle = subprocess.Popen(command("worker", wall=1, **common, **{"worker-max-requests": 2}),
                                env=environment(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert idle.wait(timeout=3) == 2
            row = json.loads(idle.stdout.read())
            assert row["status"] == "failed" and "native-resource-limit" in row["reason_codes"]
            observations["worker_idle_deadline_preserved"] = True
        finally:
            if idle.poll() is None:
                idle.kill()
                idle.wait()
            idle.stdin.close()

        cpu_worker = subprocess.Popen(command("worker", wall=5, **common, **{"worker-max-requests": 10, "cpu-seconds": 2}),
                                      env=environment(LD_PRELOAD=str(hook), TEST_NATIVE_CPU="1"),
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            sequence = []
            for number in range(10):
                cpu_worker.stdin.write(json.dumps({"input": str(slow), "request_id": str(number)}) + "\n")
                cpu_worker.stdin.flush()
                row = json.loads(cpu_worker.stdout.readline())
                sequence.append(row["status"])
                if row["status"] == "failed":
                    assert any(reason in row["reason_codes"] for reason in ("native-resource-limit", "native-cpu-budget-exhausted")) and not row["completed"]
                    break
                assert row["status"] == "clean" and row["request_id"] == str(number)
            assert sequence[0] == "clean" and sequence[-1] == "failed" and len(sequence) < 10, sequence
            assert cpu_worker.wait(timeout=3) == 2
            observations["worker_cpu_budget_spans_originals"] = sequence
        finally:
            if cpu_worker.poll() is None:
                cpu_worker.kill()
                cpu_worker.wait()
            cpu_worker.stdin.close()

        wrong = subprocess.run(command("doctor"), env=environment(COMPACT_PARENT_PID=str(os.getpid() + 100000)),
                               capture_output=True, text=True, timeout=3)
        assert wrong.returncode == 2 and json.loads(wrong.stdout)["status"] == "failed"
        observations["incorrect_trusted_parent_rejected"] = True
        report = {"protocol": 1, "status": "passed", "engine_sha256": identity["engine_sha256"],
                  "scanner_sha256": hashlib.sha256(Path(args.scanner).read_bytes()).hexdigest(),
                  "updater_sha256": hashlib.sha256(Path(args.updater).read_bytes()).hexdigest(),
                  "test_only_upstream_trust": True, "production_trust_modified": False,
                  "delay_and_observation_hooks_diagnostic_only": True, "observations": observations}
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
