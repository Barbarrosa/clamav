# Correlation experiment evidence

Read [the report](../correlated-optimization-opportunities.md) for the proof
obligations, failures and accounting boundaries. No new scanner representation
is enabled by these diagnostics.

| File | Scope |
| --- | --- |
| `transition-factoring.jsonl` | Four exact microblock layouts and six cyclic-rank layouts for each of 12 active roots; exhaustive real state/byte checks; 30 alternating timing pairs on the PE root |
| `monotone-names.json` | All-name round trips, fixed layout accounting, same 10,000 seeded uniform requests for each block size, and retained C-address checks |
| `zero-default.jsonl` | 24 fresh-process observations: three runs per encoding and write fraction; all-slot checks |
| `evidence-runs.json` | 20,000-operation ordered-stack differential model, rollback counterexample, and identical-evidence flood |
| `correlation-summary.json` | Deterministic aggregation, layout comparisons and bootstrap timing intervals |
| `provenance.json` | Base engine/source revision, tool source and binary hashes, database hashes, platform details |
| `evidence-sha256.json` | SHA-256 of these evidence files, excluding the hash file itself |

The tests use main 63, daily 28164, bytecode 339, with normal verification enabled.
See `../demand-results/database-provenance.json` and the earlier reports. This is
a controlled snapshot comparison, not a claim that the database is current.
The earlier census is copied neither partially nor reinterpreted as RSS:
`../frontier-results/encoding-census.jsonl` is the aggregate input. The name export
is a sequence of little-endian uint32 byte lengths followed by the corresponding
name bytes, with no terminators. It is produced by `engine_census.c`, sorted and
deduplicated there. Raw signatures, name exports and binaries are not included.

The transition probe uses the unchanged guarded flat-node engine as an oracle.
The old representation and its outputs remain allocated; only replacement
layout bytes are reported. Checks omit unused state ID zero. Group masks,
offsets, destinations, group descriptors and the state-row map are included;
malloc rounding and builder workspace are not. The microblock program verifies
reconstructed entries, not a timed scanner implementation.

The timings used `-O3 -mpopcnt`, CPU affinity 2, ten alternating pairs per input,
with no concurrent local heavy job. Other activity on the shared virtual host
is uncontrolled. Each stream is 1 MiB; input 0 is seeded xorshift bytes, input 1
is all zero, and input 2 repeats 0 through 255. Paired geometric means and
5000-resample percentile bootstrap intervals use seed 261027. The slower cyclic
results on repetitive inputs are a disqualifying finding for the default, not
noise to discard.

Name accounting is a Python model with actual ctypes address stability checks.
Its Python originals and temporary buffers remain outside the proposed native
layout accounting. Uniform requests are a sensitivity test, not a WordPress
distribution. The zero-default test measures RSS for fresh anonymous mappings;
it does not measure malloc reuse, cgroup page tables or scanner execution time.
The evidence-stack model does not exercise Rust/FFI error paths or allocation.

## Reproduction

Use a configured ClamAV build matching this source with flat nodes enabled and
its normal development dependencies. Paths below describe the experiment layout;
adjust dependency paths to the local installation. Run from the source root.
`certs` is the source certificate directory. The `.cvd` directory must contain
the verified snapshot to reproduce its counts. Full reproduction also needs
the previous census/export program; obtaining a newer database changes results.

```sh
cc -O3 -mpopcnt -DHAVE_CONFIG_H -I../build-compact -Ilibclamav \
  -Ilibclamunrar_iface \
  -I../research/build-deps/prefix/usr/include/json-c \
  -I../research/build-deps/prefix/usr/include/libxml2 \
  tools/compact-memory/probe_transition_factoring.c \
  -L../build-compact/libclamav \
  -Wl,-rpath,/workspace/scratch/2605ffe80d9d/build-compact/libclamav \
  -lclamav -o ../research/probe-transition-factoring
taskset -c 2 ../research/probe-transition-factoring \
  ../research/official-db/container certs > ../research/transition-factoring.jsonl

python3 tools/compact-memory/probe_monotone_names.py \
  --names ../research/names.bin --output ../research/monotone-names.json

cc -O3 tools/compact-memory/probe_zero_default.c -o ../research/probe-zero-default
python3 - <<'PY'
import subprocess
from pathlib import Path
with Path('../research/zero-default.jsonl').open('w') as f:
    for repeat in range(3):
        for percent in (0, 1, 10, 100):
            for encoded in (0, 1):
                subprocess.run(['../research/probe-zero-default', str(encoded), str(percent)],
                               stdout=f, check=True)
PY

python3 tools/compact-memory/probe_evidence_runs.py \
  --output ../research/evidence-runs.json
python3 tools/compact-memory/analyze_correlated_layouts.py \
  --research ../research --output ../research/correlation-summary.json
```

The aggregator expects the census as `../research/encoding-census.jsonl`. Its
copy already accompanies the earlier evidence and can be reused for the same
snapshot. Hashes identify observed inputs; they do not claim reproducible
process addresses or timing. The programs are trusted-input research diagnostics,
with assertions/abort on mismatch, not hardened signature-file readers or
production serialization formats.
