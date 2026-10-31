#!/usr/bin/env python3
"""Check old/new exact-layout exports after moving AC byte bounds.

Extension IDs are numbered by allocator address, so compare their presence,
not their numeric value. All other exported pattern fields must match. This
does NOT establish alert-order equivalence: links/nodes and scanner transcripts
must be checked separately with check_alert_order.py and probe_scan_corpus.c.
"""
import argparse
import hashlib
import json
from pathlib import Path


def compare(before, after):
    report = {"files": {}}
    failures = []
    expected = {p.name for p in before.glob("*.bin")}
    if expected != {p.name for p in after.glob("*.bin")}:
        raise ValueError("Export file sets differ")
    required = {"patterns.bin", "tokens.bin", "names.bin", "logical.bin",
                "templates.bin", "programs.bin"}
    if not required <= expected:
        raise ValueError("Missing required exports")
    for name in sorted(expected):
        left, right = (before / name).read_bytes(), (after / name).read_bytes()
        row = {
            "before_bytes": len(left), "after_bytes": len(right),
            "before_sha256": hashlib.sha256(left).hexdigest(),
            "after_sha256": hashlib.sha256(right).hexdigest(),
            "equal": left == right,
        }
        if name == "patterns.bin":
            # export_exact_layouts.c: 13 u32s, 10 u16s, 2 u8s.
            if len(left) != len(right) or len(left) % 74:
                raise ValueError("Pattern count/record size differs")
            changed, bounds, presence, ids = 0, 0, 0, 0
            for offset in range(0, len(left), 74):
                a, b = left[offset:offset + 74], right[offset:offset + 74]
                changed += a[:8] + a[12:] != b[:8] + b[12:]
                bounds += a[52:64] != b[52:64]
                presence += (a[8:12] == b"\xff" * 4) != (b[8:12] == b"\xff" * 4)
                ids += a[8:12] != b[8:12]
            row.update({
                "patterns": len(left) // 74,
                "unequal_records_excluding_allocator_numbered_extension_id": changed,
                "unequal_bound_records": bounds,
                "unequal_extension_presence": presence,
                "different_extension_ids": ids,
            })
            if changed or presence:
                failures.append(name)
        elif name in required and left != right:
            failures.append(name)
        report["files"][name] = row
    report["required_comparison_failures"] = failures
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.before, args.after)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return bool(report["required_comparison_failures"])


if __name__ == "__main__":
    raise SystemExit(main())
