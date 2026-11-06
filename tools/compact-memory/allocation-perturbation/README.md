# Allocation perturbation experiment

This offline experiment deliberately adds bytes to selected allocation requests
to measure which paths amplify per-request overhead. It preserves a full signed
database and compares exact scan results with zero-dose and ordinary-build
controls. It does not establish how much existing memory is unnecessary or safe
to remove.

The engine's `ENABLE_MEMORY_PERTURB` build option defaults to **OFF**. Experimental
builds annotate selected C allocation paths, including pool requests; they do not
interpose every allocator in Rust, bundled parsers or external libraries.

## Build the harness

Keep ordinary and experimental libraries separately. Build the engine with the
same configuration and toolchain for each control, changing the experimental
option only. Then build this harness against each library:

Use the normal [build dependencies and options](../../../README.md#build-and-compare),
setting `-DENABLE_MEMORY_PERTURB=ON` only in the experimental build. The ordinary
build uses `-DENABLE_MEMORY_PERTURB=OFF`.

```sh
python3 tools/compact-memory/allocation-perturbation/build_probe.py \
  --build /path/to/experimental-build --output /tmp/perturb-probe
python3 tools/compact-memory/allocation-perturbation/build_probe.py \
  --build /path/to/ordinary-build --output /tmp/ordinary-probe
```

Python 3, a C compiler, json-c and OpenSSL development files are required.
`--libdir`, repeated `--include` and `--library-path` options support private
sysroots and preserved libraries. Both matching unrar modules must be available;
the harness checks that they loaded. The harness includes existing performance
helpers and scanner callbacks; its only new engine dependencies are optional
test-only functions resolved with `dlsym`.

## Prepare public fixtures

```sh
python3 tools/compact-memory/allocation-perturbation/prepare_corpus.py \
  --output /tmp/perturb-fixtures --per-group 3
```

This selects the first three entries from each accepted, positive and adverse
group in the archived public synthetic corpus. It checks member paths, regular
file status, sizes and SHA-256 before extraction. Its output contains an absolute
`files.txt` list and a manifest without historical machine paths. Increase the
selection for broader parser coverage; a small fixed corpus is only a screen.

## Run a bounded serial screen

```sh
python3 tools/compact-memory/allocation-perturbation/run_matrix.py \
  --probe /tmp/perturb-probe \
  --library /path/to/experimental-build/libclamav/libclamav.so.14.0.0 \
  --stock-probe /tmp/ordinary-probe \
  --stock-library /path/to/ordinary-build/libclamav/libclamav.so.14.0.0 \
  --runtime-dir /path/to/experimental-build/libclamunrar_iface \
  --runtime-dir /path/to/experimental-build/libclamunrar \
  --database /private/signed-database --certs certs \
  --files /tmp/perturb-fixtures/files.txt --output /tmp/perturb-screen \
  --doses 0 8 32 --repetitions 1 --zero-controls 3 --cpu 0
```

Select an allowed CPU. The default 12 groups cover names, patterns, candidates,
tokens, nodes, transitions, hashes, logical rules, scan state, build scratch and
remaining annotated pool/heap requests. Nonzero cases are deterministically
shuffled; three shared zero-dose controls are spread across the screen. With
one ordinary-build control, this command launches **28 fresh serial processes**.
Use an idle host and avoid compiling or running other benchmarks concurrently.

The default per-process limits are 4 GiB address space, 120 CPU seconds plus a
five-second hard-limit margin, 150 seconds wall time, and 512 MiB of cumulative
requested padding. These are experimental limits, not operating guarantees.
Cap exhaustion can fail allocations; such runs cannot establish dose response.

For closer follow-up, select groups, increase `--repetitions`, and omit
`--zero-controls` to get a separate zero-dose case for every group/repetition.
`--reload` retains two engines and measures freeing the old one; it has a larger
memory budget requirement. `--scan-passes` repeats fixture batches while keeping
metadata enabled and the clean-result cache disabled. No file-page eviction or
hydration guarantee is made by this harness.

## Evidence and interpretation

Each run records load/compile/scan CPU and wall time, ordered callback histories,
return codes, final labels, verdicts, parser traversal, input hashes and memory
snapshots. Expected malformed-input errors remain in the comparison. Missing
records, changed inputs, timeouts, library identity mismatches and missing runtime
modules fail validation. The comparison includes exact reporting order; a changed
order is reported as a mismatch even if detection multisets agree.

The runner saves the randomized plan, source/artifact/input hashes, raw JSONL,
stderr, perturbation logs, process outcomes and `summary.json`. Shared-control
RSS deltas use the median of the interleaved zero-dose observations; paired-mode
deltas use the same group/repetition. A single screening run has no confidence
interval or no-regression guarantee. Repeat promising cases before ranking them.

Interpret the quantities separately:

- **RSS/PSS/HWM:** observed resident process memory, apportioned shared memory and
  cumulative resident high-water mark. HWM includes earlier construction phases.
- **Pool carved/mapped extents:** region bump usage and reservation size. Carved
  usage includes freed fragments and metadata; neither quantity is live payload
  or necessarily resident memory.
- **Perturbation counters:** cumulative allocation requests and added bytes.
  They are not live allocation counts and cannot be added to RSS or treated as
  reclaimable memory. Free/reallocation and pool reuse affect the final response.
- **Dose response:** how additional bytes affected observed process memory in
  these workloads. This can prioritize high-frequency records, allocation size
  classes or reload lifetimes for a separate removal experiment. It does not
  demonstrate that all added-byte sensitivity already exists as waste.

The runner rejects missing/rejected instrumentation and separates capped doses.
It cannot authenticate a modified reporter or guarantee annotation coverage.
The ordinary control measures instrumentation-related changes separately from
the requested padding. Timing results are diagnostic; perturbation intentionally
changes layout, allocator classes and cache behavior.

Independently audit a completed matrix before using its conclusions:

```sh
python3 tools/compact-memory/allocation-perturbation/audit_results.py \
  --results /tmp/perturb-screen --report /tmp/perturb-screen/audit.json
```

This rechecks raw artifact hashes, exact ordered fixture identities, lifecycle
records, observed limits, dose counters, control semantics and summary arithmetic.
It supplements the runner's validation with an independent manifest check.

Inspect the pool's allocation classes separately:

```sh
python3 tools/compact-memory/allocation-perturbation/pool_class_analysis.py \
  --source libclamav/mpool.c \
  --capture-summary docs/system-model-results/summary.json \
  --report /tmp/pool-classes.json
```

The capture summary must be the prior published LP64 full-engine capture. Its
fixed-record counts are historical evidence, distinct from cumulative requests
in the new experiment. See the [findings](../../../docs/allocation-perturbation.md)
and [published evidence](../../../docs/allocation-perturbation-results/README.md).

```sh
python3 -m unittest discover -s tools/compact-memory/allocation-perturbation \
  -p 'test_*.py' -q
```

The tests check instrumentation allocation behavior and independent evidence
integrity conditions. They do not replace full-engine qualification.
