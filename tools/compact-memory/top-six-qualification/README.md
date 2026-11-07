# Whole-engine qualification for the top six investigations

This directory collects reproducible correctness and performance evidence. It
does not authorize promotion from a storage model, a padding response, a small
component benchmark or an incomplete measurement bundle.

The performance runner compares a candidate with the retained branch and the
pinned original ClamAV baseline. Each role has its own executable, library and
source identity. It makes separate-inode private copies of the complete selected
database and public corpus before changing file-page cache state. It never uses
global `drop_caches` or evicts the original database/corpus files.

## Build the identical performance adapter

Build each engine with matching toolchains and relevant configuration. Then:

```sh
python3 tools/compact-memory/top-six-qualification/build_probe.py \
  --build /private/retained-build --source /private/retained-source \
  --libdir /private/retained-library --output /tmp/perf-retained
python3 tools/compact-memory/top-six-qualification/build_probe.py \
  --build /private/candidate-build --source /private/candidate-source \
  --output /tmp/perf-candidate
python3 tools/compact-memory/top-six-qualification/build_probe.py \
  --build /private/upstream-build --source /private/upstream-source \
  --output /tmp/perf-upstream
```

The adapter reuses `performance_probe.c` and `scan_probe.c` for measurements and
ordered callbacks. It adds observed resource limits/CPU affinity and actual
engine, unrar-module and update-library identities. `--include` and
`--library-path` can be repeated for a private sysroot. `pkg-config` must locate
json-c and OpenSSL. Python 3, a C compiler and pthread support are needed.

The pinned upstream reference is commit
`dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`. The retained structural baseline is
distinct: an improvement over it is not automatically a performance qualification
against original ClamAV.

## First run a bounded smoke test

```sh
python3 tools/compact-memory/top-six-qualification/runner.py \
  --variant retained /tmp/perf-retained /private/retained-library/libclamav.so.14.0.0 /private/retained-source \
  --variant candidate /tmp/perf-candidate /private/candidate-build/libclamav/libclamav.so.14.0.0 /private/candidate-source \
  --runtime-dir retained /private/retained-build/libclamunrar_iface \
  --runtime-dir retained /private/retained-build/libclamunrar \
  --runtime-dir candidate /private/candidate-build/libclamunrar_iface \
  --runtime-dir candidate /private/candidate-build/libclamunrar \
  --database /private/signed-database --certs certs \
  --output /private/qualification-smoke --stage smoke \
  --cases scan --rounds 1 --scan-repeats 1 --cpu 0
```

Choose an allowed CPU. This tests nine fixed public benign, positive and adverse
files, including expected malformed-input responses, with a fresh engine and
cold/warm file-page passes. These are observations, not qualification. The default
per-process limits are 6 GiB address space, 240/245 CPU seconds and 300 seconds
wall time. A timeout kills the process group and leaves a failed record.

The output must be new or empty; changed experiments cannot resume old results.
Do not modify sources, executables, libraries or fixtures while a matrix runs.
The driver rechecks private input and artifact hashes after each process.

## Full measurements

Add the upstream role and its runtime directories. `--stage full` uses all 163
archived public fixtures. `--workloads combined accepted positive adverse` can
measure each group separately, but increases runtime. The exact archive and
fixture hashes are recorded. For fuller coverage, use:

```sh
--stage full --cases scan reload update concurrency --rounds 3 \
  --scan-repeats 1 --database-cache both --concurrency 4 \
  --concurrency-cpus 0 1 2 3
```

Ordinary cases remain pinned to `--cpu`; the shared-engine concurrency case uses
the declared allowed CPU set. It is a test at that worker count, not a claim of
the maximum supported deployment concurrency. All cases execute serially; only
the explicit concurrency case starts worker threads.

For update validation, bind a matching `--freshclam ROLE LIBRARY` for every role.
`--update-member daily.cvd` selects the copied signed member. The public
`fc_test_database_ex` call is timed in process while the original and replacement
engines remain alive. No network update or deployment publication is performed.

`--reload-database /private/different-signed-generation` copies and binds a
changed replacement generation. An identical byte manifest is rejected as a
changed-generation test. Without this argument, reload means an equal-generation
overlap. The replacement is compiled and freed without scanning it; its signature
count remains part of paired validation.

Use `--build-cache ROLE CMakeCache.txt` to record the build flags and cache hash.
Source commits, source-file hashes (including untracked source files), executable,
library, runtime-module, certificate, database and corpus identities are retained
in `plan.json`. Compiler/hardware metadata and the exact randomized process plan
are also bound. Changing a role's source after producing its library requires a
new build/provenance check; a file hash is not a reproducible-build attestation.

## Measurements and gates

The runner reports the contract's 18 named dimensions separately:

- Scan CPU and wall time, and empirical per-file p95/p99 latency.
- Startup, reload and in-process update-validation CPU/wall time.
- Compiled and post-workload resident RAM; construction, reload and update-overlap
  process resident high-water marks.
- Scan context, scan scratch and builder scratch, which remain **unknown** unless
  supplied by a separate source-bound accounting argument. They are never set to
  zero from an RSS subtraction.

Latency quantiles use nearest rank on externally measured `cl_scandesc_ex` wall
intervals. Every observed value is retained. The existing measurement contract
requires at least 20 samples for p95 and 100 for p99; smaller smoke distributions
have numerical quantiles but cannot pass that qualification gate. These sample
counts do not establish a confidence interval or all-input latency guarantee.

Concurrent CPU uses one process envelope around the worker group. Overlapping
per-file process-CPU counters are **not summed**. Per-file wall latencies remain
observed independently. File-page hydration is not proof that every decoded name
or field in a future representation has been touched; that coverage remains
explicitly separate.

High-water values are cumulative within each fresh process, through the stated
phase; they are not obtained by subtracting unrelated RSS values. Cache controls
apply to the copied database/corpus file pages, not every shared library or OS
cache. Signed loading remains enabled and no selected-rule skip list is used.

Every paired observed cost is compared with a ratio ceiling of 1.0. A favorable
average does not hide a slower paired observation. Missing roles, rounds,
percentile samples or required metrics remain unknown. The script can therefore
exit successfully after collecting a complete but unqualified matrix:
`summary.complete` describes process/data completion, while
`summary.qualification` describes the observed criteria. Always inspect both.

The runner deliberately does not automatically promote an implementation. Full
correctness-property coverage, source-bound complexity/resource proofs, complete
hydration, changed-generation ownership and deployment concurrency require
independent adjudication in addition to these finite measurements.

## Attach independent checks

The targeted suite is driven by `correctness.py`:

```sh
python3 tools/compact-memory/top-six-qualification/correctness.py \
  --build /private/build --baseline-library /private/base/libclamav.so.14.0.0 \
  --candidate-library /private/candidate/libclamav.so.14.0.0 \
  --certs certs --output /private/correctness --rules 10000 --hash-distractors 10000
```

See its `--help` for private sysroot and runtime-module paths. Its output must
have `qualifying_comparison=true` before treating it as a distinct-artifact
comparison. A same-library smoke test cannot qualify a candidate.

The performance runner can attach `--correctness-report .../summary.json`; it
rejects a candidate/baseline library binding mismatch. It can attach
`--resource-audit FILE`; the directory-retirement audit's observed source hashes
must match the candidate source. Such statements are recorded as source-relative
evidence, never converted into invented absolute zero-byte measurements.

```sh
python3 -m unittest discover -s tools/compact-memory/top-six-qualification \
  -p 'test_*.py' -q
```

The tests exercise missing/wrong identities, changed inputs, exact callback
multiplicity/order, quantile boundaries, overlapping CPU accounting and paired
regressions. They do not replace full-engine qualification.
