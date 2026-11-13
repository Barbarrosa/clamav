#!/usr/bin/env python3
"""Exercise the production preparation aliases with legacy RSA disabled.

Uses upstream TEST-signed CVDs and the isolated upstream TEST trust root. Never
use that trust root for real official database updates.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    fixtures = args.source / "unit_tests/input/freshclam_testfiles"
    trust = args.source / "unit_tests/input/signing/verify"
    results = []
    with tempfile.TemporaryDirectory(prefix="compact-test-pki-") as temp:
        for tamper in (False, True):
            generation = pathlib.Path(temp) / str(tamper)
            databases = generation / "databases"
            databases.mkdir(parents=True)
            for stem, version in (("main", 1), ("daily", 2), ("bytecode", 3)):
                shutil.copyfile(fixtures / f"test-{version}.cvd", databases / f"{stem}.cvd")
                shutil.copyfile(fixtures / f"test-{version}.cvd.sign", databases / f"{stem}-{version}.cvd.sign")
            if tamper:
                signature = databases / "main-1.cvd.sign"
                raw = bytearray(signature.read_bytes())
                raw[len(raw) // 2] ^= 1
                signature.write_bytes(raw)
            result = subprocess.run([args.probe, str(generation), str(trust)],
                                    capture_output=True, text=True, timeout=30)
            row = json.loads(result.stdout)
            assert (result.returncode == 0) == (not tamper), (result.returncode, row, result.stderr)
            if not tamper:
                assert all(s["signature_verified"] and s["detached_signature"] for s in row["sources"])
            else:
                assert not (generation / "profile").exists()
            results.append({"tampered": tamper, "return_code": result.returncode,
                            "status": row["status"], "sources": row["sources"]})
    report = {"protocol": 1, "status": "passed", "pki_only_legacy_disabled": True,
              "test_only_trust_sha256": hashlib.sha256((trust / "clamav-test.crt").read_bytes()).hexdigest(),
              "matching_sidecar_pinned": True, "tampered_sidecar_rejected": True,
              "production_trust_modified": False, "cases": results}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}))


if __name__ == "__main__":
    main()
