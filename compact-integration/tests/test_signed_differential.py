#!/usr/bin/env python3
"""Compare actual full/selected engines on an authenticated prepared snapshot.

The probe includes the production scanner options/callbacks. These observations
support the source audit; a finite corpus is not an all-input proof.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import subprocess

import fixtures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--certs", required=True)
    parser.add_argument("--upstream-inputs", type=pathlib.Path, required=True)
    parser.add_argument("--engine", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    paths = sorted(args.upstream_inputs.iterdir())
    assert paths and all(p.is_file() for p in paths)
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    extra = {
        "eicar.txt": eicar, "eicar.pdf": fixtures.pdf(eicar),
        "clean.png": fixtures.png(), "clean.jpg": fixtures.jpeg(),
        "appended-pe.jpg": fixtures.jpeg() + fixtures.make_pe(),
        "appended-pe.png": fixtures.png() + fixtures.make_pe(),
        "clean.pdf": fixtures.pdf(b"ordinary harmless text"),
        "clean.txt": b"ordinary harmless text",
        "embedded-pe.pdf": fixtures.pdf(fixtures.make_pe()),
        "nested-pe.zip": fixtures.zip_bytes(fixtures.make_pe()),
        "renamed-pe.pdf": fixtures.make_pe(),
    }
    for name, data in extra.items():
        path = args.output / name
        path.write_bytes(data)
        paths.append(path)
    listing = args.output / "files.txt"
    listing.write_text("".join(str(p.resolve()) + "\n" for p in paths))
    before = hashlib.sha256(args.engine.read_bytes()).hexdigest()
    rows = []
    for mode in (0, 1):
        path = args.output / ("full.jsonl" if mode == 0 else "reduced.jsonl")
        with path.open("w") as out, (args.output / f"{mode}.stderr").open("w") as err:
            subprocess.run([args.probe, args.generation, args.certs, str(mode), str(listing)],
                           stdout=out, stderr=err, check=True, timeout=240)
        rows.append([json.loads(line) for line in path.read_text().splitlines()])
    assert len(rows[0]) == len(rows[1]) == len(paths)
    accepted, held = [], []
    for full, reduced in zip(*rows):
        assert all(full[k] == reduced[k] for k in ("path", "sha256", "size"))
        if reduced["flags"]:
            assert reduced["status"] != 0
            held.append({"input": pathlib.Path(full["path"]).name,
                         "full_verdict": full["verdict"], "reduced_status": reduced["status"]})
            continue
        fields = ("status", "verdict", "root_type", "scanned_bytes", "incomplete", "bad_callback", "reasons")
        assert all(full[k] == reduced[k] for k in fields), (full, reduced)
        assert collections.Counter(x["name"] for x in full["findings"]) == collections.Counter(x["name"] for x in reduced["findings"])
        assert full["findings"] == reduced["findings"], ("finding order", full, reduced)
        accepted.append({"input": pathlib.Path(full["path"]).name,
                         "detected": bool(full["findings"]), "sha256": full["sha256"]})
    assert before == hashlib.sha256(args.engine.read_bytes()).hexdigest(), "engine changed during test"
    report = {"protocol": 1, "status": "passed", "engine_sha256": before,
              "cases": len(paths), "guard_free_exact_comparisons": len(accepted),
              "guarded_nonclean_cases": len(held), "accepted": accepted, "held": held,
              "scope": "exact observed full/reduced comparisons with production options; finite corpus, not all-input proof",
              "timing_qualification": False}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("accepted", "held")}))


if __name__ == "__main__":
    main()
