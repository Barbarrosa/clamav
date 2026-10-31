# Compact resident engine: validation record

Update: [full-database measurements and implementation gates](demand-engine-implementation.md)
now supplement the earlier synthetic results below.

This is a development fork based on upstream
`dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`. These results support further
evaluation, not production certification. The original signature formats,
parsers, bytecode interpreter, YARA support, limits, and verification paths remain
enabled. No production signature database was available for this experiment.

## Correctness evidence

| Check | Result |
|---|---|
| Untouched baseline C suite | 1,782 checks, zero failures/errors |
| Fork with flat compact transition IDs | 1,785 checks, zero failures/errors |
| Fork with native pointer transitions | 1,785 checks, zero failures/errors |
| Baseline and flat compact-ID scanner integration | Each: 145 passed, one skipped, five passing subtests |
| Native-pointer scanner integration | 145 passed, one skipped, five passing subtests |
| Rust unit suite | 65 tests passed |
| Affected C/Rust record sizes and offsets | Agree in both transition configurations |
| Pool-disabled matcher and regex suites with ASan and UBSan | 13 matcher and 212 regex checks passed with halt-on-error; leak detection disabled for the reason below |
| Source consistency | `git diff --check` and Python byte-compilation passed |

The three added tests cover row boundaries and compatibility fallbacks,
independent contexts, compact-versus-legacy counts and offsets across overlapping
windows, equal-pattern and suffix outputs, case folding, wildcard verification,
subsignature 63, rejected node-index overflow, and partial-state cleanup.
These complement the existing matcher and scanner regressions; they are not an
exhaustive equivalence proof.

The contiguous arena is compiled once and remains resident. Each input byte
still selects one completed transition; address calculation replaces an indirect
pointer fetch. Candidate enumeration and full-pattern verification retain their
original algorithms and order. There is no new hash-collision failure mode,
rule-cache eviction, replay pass, or scan-time database I/O. Node-ID/allocation
arithmetic is checked, and failure to allocate the arena returns an error while
leaving the original nodes owned for cleanup. Existing scan limits remain intact.

Test logs, record-layout output, environment failures, and raw measurements are
included in [compact-results](compact-results/). The strict sanitizer result
applies to the C/C++ matcher path; the Rust library has its own passing unit suite
and was not instrumented with Rust sanitizers.

### Checks that could not pass in this environment

- The complete strict UBSan C suite stops at an unaligned `uint32_t` load in
  `libclamav/matcher-hash.c:270`. A separately built, untouched baseline reproduces
  the same finding. The hash matcher was not modified here. This is why the new
  strict sanitizer CI job targets the changed matcher and regex suites while release jobs
  retain the full tests.
- LeakSanitizer cannot inspect the container's process namespace: it reports
  failure opening `/proc/<pid>/task` and exits. The passing local matcher run
  therefore used `detect_leaks=0`; it is not evidence of leak-freedom. CI requests
  leak detection on an ordinary Ubuntu runner.
- `clamd` cannot create its Unix socket (`Operation not permitted`), so daemon
  integration, concurrent reloads, and connection behavior are unvalidated here.
  Both baseline and fork encounter the restriction. Certificate loading was
  configured correctly before confirming this error.
- FreshClam cannot set supplementary groups (`initgroups()` fails), and the official
  database download endpoint returned HTTP 403 in this environment. Updater and
  real-database testing remain open; verification was not disabled to bypass them.
- GitHub Actions has been supplied but has not run remotely. Windows, macOS,
  32-bit, LLVM bytecode JIT, and sustained adversarial/reload testing remain open.

## Measurement method

The complete primary experiments use 20,000 deterministic ordinary logical rules
with four eight-byte subsignatures each. Each workload runs in 30 fresh process
pairs, randomizing baseline/fork order within each pair. Each process loads and
compiles the engine and performs one scan. Workloads are 4 KiB clean random data,
4 MiB clean random data, and a harmless marker satisfying one generated rule plus
4 KiB random data. All parsers, heuristics, and all-match mode are enabled; clean
cache hits are disabled in both builds. All scan verdicts and signature counts
must match their expected values or the driver rejects the experiment.

An earlier run with five scans per process was stopped during the large-file
phase. It is not used in the reported results. The completed one-scan runs use
all 30 pairs, without removing outliers. Longer steady-state loops and production
corpora are still necessary to characterize a deployment.

The host is x86-64 Linux, Intel Xeon Platinum 8370C, with an 8 GiB cgroup memory
limit and eight CPUs of quota. Builds use GCC 13.3, Release optimization, Rust
1.90.0, the default bytecode interpreter, memory pools, and UnRAR. Both builds
use the same dependencies and flags. Tests and builds are not run concurrently
with the complete primary measurements.

Raw JSON records include each observation, build options, library and benchmark
hashes, database/input hashes, and compiler/host metadata. Ratios are geometric
means of paired fork/baseline measurements; intervals are 95% bootstrap intervals
of paired log ratios (5,000 resamples). They describe these runs, not a formal
all-workload non-inferiority guarantee. RSS is process memory, not cgroup memory
including file cache and kernel charges.

## Measured results

The runtime implementation measured in the final flat/native runs is commit
`1c3fecaf7beed5e1fcc80692d09667b2e46504f1`. The later default-policy
commit enables the already-measured flat-ID configuration; it does not change
the matcher runtime. Measurements below use complete runs and their recorded
explicit build options. All times are elapsed wall time on a shared host, without
CPU pinning; wide confidence intervals must not be read as proof of equality.

### Default flat-ID build: memory

| Workload | Baseline compiled RSS, MiB | Flat compiled RSS, MiB | Baseline peak RSS, MiB | Flat peak RSS, MiB |
|---|---:|---:|---:|---:|
| 4 KiB clean | 134.52 | 92.42 | 144.58 | 93.95 |
| 4 MiB clean | 134.72 | 92.48 | 148.64 | 97.86 |
| Detected marker | 134.53 | 92.53 | 144.76 | 94.10 |

These medians correspond to approximately **31% lower compiled resident memory**
and **34–35% lower peak RSS** in the paired ratios. The scan-state payload
calculation is 15,360,000 versus 960,000 bytes for these 20,000 four-part rules.
Its 93.75% reduction is not a whole-process RSS prediction: other structures
remain, allocator size classes matter, and untouched `calloc` pages can share
the operating system’s zero page.

### Default flat-ID build: scan time

| Workload | Baseline median, ms | Flat median, ms | Paired time ratio [95% interval] |
|---|---:|---:|---:|
| 4 KiB clean | 97.77 | 44.07 | 0.470 [0.401, 0.552] |
| 4 MiB clean | 2597.43 | 2013.66 | 0.790 [0.715, 0.869] |
| Detected marker | 100.81 | 50.98 | 0.558 [0.485, 0.649] |

The large-file time ratio is 0.790: about **21% less scan time** in this
experiment. The small-clean and detected-marker ratios are 0.470 and 0.558.
These workloads do not establish performance for archives, extension-heavy
rules, adversarial candidate floods, or production traffic.

### Loading and compilation are included

| Workload | Load-time ratio [95% interval] | Compile-time ratio [95% interval] |
|---|---:|---:|
| 4 KiB clean | 0.729 [0.638, 0.830] | 0.996 [0.897, 1.102] |
| 4 MiB clean | 0.797 [0.702, 0.891] | 0.870 [0.752, 0.976] |
| Detected marker | 0.820 [0.676, 0.994] | 0.978 [0.843, 1.135] |

Some compile-time intervals cross 1.0. The arena conversion is not claimed to
improve every compile or to have zero construction cost.

### Competing transition policies

Each row below is a separate paired experiment against the pinned baseline,
using the 4 MiB clean workload. Cross-row comparisons are not a simultaneous
three-way randomized trial. Smaller ratios mean less memory or time.

| Policy | Compiled RSS ratio | Peak RSS ratio | Scan-time ratio [95% interval] |
|---|---:|---:|---:|
| Native pointers (final runtime) | 0.957 | 0.905 | 0.985 [0.910, 1.066] |
| Indirect IDs (earlier prototype) | 0.666 | 0.639 | 1.217 [1.081, 1.371] |
| Flat IDs (final runtime; default) | 0.687 | 0.658 | 0.790 [0.715, 0.869] |

The indirect-ID prototype exposed a significant large-file slowdown and
motivated the contiguous arena. Its measurements predate the arena field
and final runtime commit; they are retained as development evidence, not as
a retest of the final indirect-ID build. That build remains in the CI matrix.
Flat IDs spend roughly 3 MiB more resident memory than the indirect prototype
in these runs and remove the extra scan-time pointer lookup. Native pointers
remain an alternative for hardware or workloads that prefer them; their
large-file time interval crosses 1.0, so this experiment does not prove exact
performance equivalence for that option.

Raw data: [flat](compact-results/flat.json), [native](compact-results/native.json),
[indirect prototype](compact-results/indirect-prototype.json). Each contains
180 process observations (30 pairs × three workloads), including load and
compile timing, verdicts, signature counts, memory readings, and input/build
hashes. No timed-out or failed scan was counted as a memory/performance win.

## Release acceptance still required

The optional pattern extension adds a pointer fetch when a less common pattern
feature is verified. An extension-heavy, high-hit workload can behave differently
from the generated literal rules used here. Native transitions retain that
pattern split and therefore do not restore every upstream memory-access pattern.
No claim of unchanged adversarial tail latency follows from these measurements.

Use the production database and a representative corpus to compare exact alert
names, callback order, offsets, counts, errors, timeouts, and return codes.
Exercise malformed files, repeated candidate hits, dense logical matches,
recursive archives, bytecode/YARA/macros/byte-compare signatures, and all-match
mode under unchanged limits. Test allocation failures and sustained updates.

Measure throughput and tail latency by file class and size, and whole-cgroup
memory across configured concurrency and overlapping old/new engines during
reload. A skipped parser, earlier timeout, changed verdict, reduced concurrency,
or failed reload must fail acceptance. Select the optional transition policy
only after it meets the application's existing performance and resilience
requirements. Do not infer those properties from a lower RSS number alone.
