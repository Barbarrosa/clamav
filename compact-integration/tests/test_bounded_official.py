#!/usr/bin/env python3
"""Exercise production bounded validation on a copied authenticated generation.

Original database bytes remain unchanged. The production loader authenticates
each original transport during every pass. Supply an explicit test resource
policy; this runner has no shipping host-budget or freshness defaults.
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import tempfile
import time


def processes(pid):
    pending, result = [pid], []
    while pending:
        current = pending.pop()
        try:
            status = pathlib.Path(f"/proc/{current}/status").read_text().splitlines()
            values = {}
            for line in status:
                if line.startswith(("VmRSS:", "VmHWM:", "VmPeak:")):
                    key, value, _ = line.split()
                    values[key.rstrip(":")] = int(value)
            result.append(values)
            pending.extend(map(int, pathlib.Path(f"/proc/{current}/task/{current}/children").read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--generation", type=pathlib.Path, required=True)
    parser.add_argument("--certs", required=True)
    parser.add_argument("--as-bytes", type=int, required=True)
    parser.add_argument("--cpu-seconds", type=int, required=True)
    parser.add_argument("--wall-seconds", type=int, required=True)
    parser.add_argument("--file-bytes", type=int, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert all(getattr(args, k) > 0 for k in ("as_bytes", "cpu_seconds", "wall_seconds", "file_bytes"))
    with tempfile.TemporaryDirectory(prefix="compact-bounded-official-") as temporary:
        state = pathlib.Path(temporary)
        state.chmod(0o700)
        generation = state / "generation"
        shutil.copytree(args.generation, generation)
        for name in ("bounded-batches.jsonl", "bounded-validation.json"):
            assert not (generation / "profile" / name).exists(), "supply a prepared pre-validation generation"
        command = [args.scanner, "validate-bounded", "--generation", str(generation), "--state", str(state), "--certs", args.certs]
        for key in ("as_bytes", "cpu_seconds", "wall_seconds", "file_bytes"):
            command.extend(["--" + key.replace("_", "-"), str(getattr(args, key))])
        start = time.monotonic()
        with (state / "stdout").open("w") as stdout, (state / "stderr").open("w") as stderr:
            child = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            max_rss, max_vm, max_sum, max_count, coordinator_rss = 0, 0, 0, 0, 0
            while child.poll() is None:
                observed = processes(child.pid)
                if observed:
                    coordinator_rss = max(coordinator_rss, observed[0].get("VmHWM", 0))
                max_count = max(max_count, len(observed))
                max_rss = max([max_rss] + [p.get("VmHWM", 0) for p in observed])
                max_vm = max([max_vm] + [p.get("VmPeak", 0) for p in observed])
                max_sum = max(max_sum, sum(p.get("VmRSS", 0) for p in observed))
                if time.monotonic() - start > args.wall_seconds + 15:
                    child.kill()
                    child.wait()
                    raise AssertionError("native whole-operation wall limit failed")
                time.sleep(0.01)
        result = json.loads((state / "stdout").read_text())
        assert child.returncode == 0 and result["status"] == "passed", (child.returncode, result, (state / "stderr").read_text()[-3000:])
        assert result["eligible_occurrences"] == result["validated_occurrences"]
        attempts = [json.loads(s) for s in (generation / "profile/bounded-batches.jsonl").read_text().splitlines()]
        assert sum(a["count"] for a in attempts if a["status"] == "passed") == result["eligible_occurrences"]
        assert max_count <= 2, "more than the coordinator and one native batch child were resident"
        native_peak = max(a["peak_rss_kib"] for a in attempts)
        report = {"protocol": 1, "status": "passed", "wall_seconds": time.monotonic() - start,
                  "policy": {k: getattr(args, k) for k in ("as_bytes", "cpu_seconds", "wall_seconds", "file_bytes")},
                  "sampled_visible_process_peak_rss_kib": max_rss, "sampled_visible_process_peak_address_space_kib": max_vm,
                  "sampled_visible_process_peak_sum_rss_kib": max_sum, "max_visible_processes": max_count,
                  "proc_descendant_visibility_observed": max_count > 1,
                  "native_batch_peak_rss_kib_from_wait4": native_peak,
                  "coordinator_sampled_peak_rss_kib": coordinator_rss,
                  "conservative_coordinator_plus_batch_peak_rss_kib": coordinator_rss + native_peak,
                  "result": result, "attempts": attempts,
                  "scope": "production loader/compiler and real signed originals; sampled memory, explicit test policy, no actual hosting-account certificate"}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k not in ("attempts", "result")}))


if __name__ == "__main__":
    main()
