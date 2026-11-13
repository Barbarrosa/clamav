#!/usr/bin/env python3
"""Native-parser/coordinator diagnostics; production authentication is separate.

The diagnostic probe labels its synthetic raw official-context inputs and an
injected CL_EMEM split condition. The signed-snapshot suite independently tests
real authentication and real address-space-induced batching.
"""
import argparse
import json
import pathlib
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--certs", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    results = []
    for case in ("split", "omitted-malformed", "retained-malformed", "transcript",
                 "singleton-resource", "baseline-resource", "overflow", "bm-overflow", "generation"):
        with tempfile.TemporaryDirectory(prefix="compact-bounded-native-") as temporary:
            generation = pathlib.Path(temporary)
            databases, raw, profile = (generation / n for n in ("databases", "raw", "profile"))
            for path in (databases, raw, profile):
                path.mkdir()
            for name in ("main.cvd", "daily.cvd", "bytecode.cvd"):
                (databases / name).write_text("diagnostic placeholders; not signed transports\n")
            (profile / "ledger.sqlite").write_text("diagnostic inventory binding\n")
            (profile / "validation.json").write_text('{"status":"prepared"}\n')
            (profile / "skip.tsv").write_text("ldb\tAtomic\nndb\tDuplicate\n")
            retained = "Retained:0:*:41424344\n"
            omitted = "Duplicate:1:*:45464748\nDuplicate:1:*:494a4b4c\n"
            if case == "omitted-malformed":
                omitted = "Duplicate:1:*:GG\n"
            if case == "retained-malformed":
                retained = "Retained:0:*:GG\n"
            (raw / "fixture.ndb").write_text(retained + omitted)
            if case == "split":
                (raw / "fixture.ldb").write_text("Atomic;Target:1;0&1;41424344;45464748\n")
            result = subprocess.run([args.probe, str(generation), str(raw), args.certs, case],
                                    capture_output=True, text=True, timeout=50)
            row = json.loads(result.stdout)
            attempts = [json.loads(s) for s in (profile / "bounded-batches.jsonl").read_text().splitlines()]
            if case == "split":
                assert result.returncode == 0 and row["status"] == "passed", (row, result.stderr)
                assert row["eligible_occurrences"] == row["validated_occurrences"] == 3
                assert row["aggregate_counter_upperbounds"][7] == 1  # whole LDB
                assert row["aggregate_counter_upperbounds"][19] == 4  # retained once + 3 occurrences
                assert sum(r["count"] for r in attempts if r["status"] == "passed") == 3
                assert any(r["status"] == "resource-failed" for r in attempts)
                assert all(r["counters"][19] == 2 for r in attempts if r["count"] and r["status"] == "passed")
            else:
                assert result.returncode != 0 and row["status"] == "failed", (case, row, result.stderr)
                if case in ("retained-malformed", "baseline-resource"):
                    assert len(attempts) == 1 and row["reason"] == "bounded-retained-baseline-rejected"
                elif case == "singleton-resource":
                    assert row["reason"] == "bounded-indivisible-record-exceeds-budget"
                elif case in ("overflow", "bm-overflow"):
                    assert row["reason"] == "bounded-baseline-native-counter-unsupported"
                elif case == "generation":
                    assert row["reason"] == "bounded-coverage-or-generation-mismatch"
                else:
                    assert row["reason"] == "bounded-native-record-or-transcript-rejected"
            results.append({"case": case, "return_code": result.returncode,
                            "result": row, "attempts": attempts})
    report = {"protocol": 1, "status": "passed", "synthetic_raw_signature_diagnostic": True,
              "split_CL_EMEM_injected": True, "real_native_parser_and_compiler": True,
              "signature_authentication_in_this_diagnostic": False,
              "production_binary_modified": False,
              "scope": "standalone diagnostic probe only; no production bypass exists",
              "cases": results}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}))


if __name__ == "__main__":
    main()
