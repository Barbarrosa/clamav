# Fresh three-way ClamAV performance analysis — 2026-10-29

All figures below come from one new controlled experiment, with both engines rebuilt using the same toolchain. No historical benchmark cell is reused. Original means the pinned, unmodified ClamAV development baseline `dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`, not the latest ClamAV release. New full and Legal Redress use retained engine source `9dfde0139708a1eb1a728f86baecb1d8ec1b66df`; their only difference is the conservative signature-load callback. The archive update adds measurement tools, evidence and documentation; it does not change engine algorithms or shipping defaults.

Legal Redress loads **16.56%** of the engine-counted signatures and reduces mean compiled RSS by **86.33%** versus original, or **83.43%** versus new full. The removed count is **3,027,188**. The official compressed CVD files are still retained and verified in full: **112,798,155 bytes**, or **100%** of source bytes. Signature percentage is a count ratio, not a byte ratio or a malware-detection coverage percentage. The engine count may include expanded logical/subsignature units; it is distinct from the selector's excluded callback-name count.

## Database, memory and lifecycle

| Metric | Original ClamAV | New · full DB | New · Legal Redress |
|---|---:|---:|---:|
| Engine-counted signatures loaded | 3,628,192 | 3,628,192 | 601,004 |
| Signatures loaded (% of full) | 100.00% | 100.00% | 16.56% |
| Signed database bytes retained | 107.573 MiB · 100% | 107.573 MiB · 100% | 107.573 MiB · 100% |
| Compiled engine RSS (MiB, mean) | 959.6 | 791.2 | 131.1 |
| Construction peak RSS (MiB, max) | 959.9 | 825.2 | 162.2 |
| Peak through accepted scans (MiB, max) | 974.4 | 825.2 | 162.2 |
| Two-engine reload peak RSS (MiB, max) | 1,916.1 | 1,613.2 | 304.6 |
| Reload wall time (s, mean) | 8.302 | 7.922 | 3.522 |
| Reload CPU time (s, mean) | 8.262 | 7.912 | 3.516 |
| Two engines + update test peak RSS (MiB) | 2,564.9 | 2,120.1 | 800.1 |

RSS is resident process RAM; PSS apportions shared pages; USS counts private pages. All memory quantities use binary MiB. Peaks are maxima of Linux process high-water RSS, which is cumulative from process start. Scan peak therefore includes engine construction. Reload retains both old and replacement engines. Update tests add an actual unreduced `fc_test_database_ex()` load/bytecode-preparation operation for one CVD while both engines remain live. Each main/daily/bytecode test has its own fresh process. This API validates a database; it does not perform the full engine AC compile step. No network download is included in these CPU/timing intervals.

The observed reduced reload peak is **304.6 MiB**. A 303 MiB hard process ceiling is therefore too low for this rerun. Co-located full update validation reaches **800.1 MiB**; full-database preparation and validation should remain in a separately budgeted worker. The measurements are not a universal upper bound for arbitrary content, concurrency or allocator behavior.

## OS file-page cache: empty → hydrated

Metadata collection, all-match, all parsers and the same heuristic settings are enabled for every variant. The ClamAV clean-result cache is disabled equally. Database startup and input scans each have independent page-cache preparation. Empty means 0% of tested-file pages resident; hydrated means 100%, verified by `mincore` before every phase. It does not describe CPU hardware caches or the storage device's internal cache.

| Metric | Original ClamAV | New · full DB | New · Legal Redress |
|---|---:|---:|---:|
| DB page-cache RAM before load (MiB) | 0.00 → 107.58 | 0.00 → 107.58 | 0.00 → 107.58 |
| Input page-cache RAM before scan (MiB) | 0.00 → 14.18 | 0.00 → 14.18 | 0.00 → 14.18 |
| Startup wall time (s, mean) | 8.621 → 7.935 | 7.860 → 14.733 | 3.682 → 3.491 |
| Startup wall time (s, median) | 8.119 → 7.880 | 7.853 → 7.841 | 3.490 → 3.486 |
| Startup CPU time (s, mean) | 8.437 → 7.927 | 7.674 → 14.340 | 3.645 → 3.488 |
| Startup CPU time (s, median) | 7.980 → 7.873 | 7.658 → 7.835 | 3.446 → 3.483 |
| Startup CPU utilization (%) | 97.9 → 99.9 | 97.6 → 99.0 | 99.0 → 99.9 |
| Post-startup RSS (MiB) | 959.6 → 959.6 | 791.2 → 791.1 | 131.1 → 131.2 |
| Post-startup PSS (MiB) | 958.1 → 958.0 | 789.7 → 789.6 | 129.5 → 129.6 |
| 28-file scan wall time (s, mean) | 1.810 → 1.764 | 1.981 → 1.703 | 1.682 → 2.109 |
| 28-file scan wall time (s, median) | 1.788 → 1.762 | 1.665 → 1.609 | 1.629 → 1.609 |
| 28-file scan CPU time (s, mean) | 1.769 → 1.762 | 1.897 → 1.698 | 1.650 → 2.077 |
| 28-file scan CPU time (s, median) | 1.758 → 1.761 | 1.618 → 1.608 | 1.609 → 1.608 |
| Scan CPU utilization (%) | 97.8 → 99.9 | 96.7 → 99.8 | 98.2 → 99.5 |
| Post-scan RSS (MiB) | 967.1 → 967.1 | 809.2 → 809.2 | 149.2 → 149.2 |
| Post-scan PSS (MiB) | 965.5 → 965.5 | 807.6 → 807.6 | 147.6 → 147.6 |
| Post-scan USS (MiB) | 964.6 → 964.6 | 806.8 → 806.8 | 146.8 → 146.7 |
| Input block reads (MiB per batch) | 14.18 → 0.00 | 14.18 → 0.00 | 14.18 → 0.00 |
| Per-file median latency (ms) | 10.78 → 10.57 | 10.74 → 10.41 | 10.59 → 10.45 |
| Per-file p95 latency (ms) | 385.54 → 360.02 | 428.35 → 342.64 | 348.64 → 341.17 |
| Per-file p99 latency (ms) | 754.74 → 758.20 | 709.12 → 638.81 | 636.84 → 773.01 |
| Hydrated scan throughput (MiB/s) | 8.03 | 8.32 | 6.71 |

Values are means unless labeled median, apart from pooled per-file latency percentiles. CPU utilization is CPU seconds divided by wall seconds, with one core equal to 100%. User and system CPU times, page faults, block reads/writes, anonymous/file PSS, confidence intervals and ranges are retained for every phase in `subset-selector-results/three-way-performance/summary.json`. The file-page working set is measured separately from process memory; it is not added to RSS/PSS, which could double count mappings. Shared cgroup samples are context only and are not reported as isolated scanner RAM. Database loads use the retained `CL_DB_STDOPT` configuration. Limits are identical: 100 MiB per file, 400 MiB scanned content, recursion depth 17 and 10,000 files.

## ClamAV clean-result cache: empty → hydrated

This diagnostic turns metadata collection off and enables ClamAV's 65,536-entry result cache, equally in all variants. OS input pages are hydrated in both states to isolate result-cache effects. Empty/hydrated refers to cache state **at the start** of the scan batch; post-scan RAM is sampled after that batch. Initial empty-cache engine RSS provides the before-scan baseline.

| Metric | Original ClamAV | New · full DB | New · Legal Redress |
|---|---:|---:|---:|
| Initial empty-cache engine RSS (MiB) | 965.6 | 797.4 | 137.0 |
| 28-file scan wall time (s) | 1.758 → 0.050 | 1.618 → 0.051 | 1.601 → 0.051 |
| 28-file scan CPU time (s) | 1.757 → 0.050 | 1.617 → 0.050 | 1.599 → 0.051 |
| Scan CPU utilization (%) | 99.9 → 99.7 | 99.9 → 99.6 | 99.9 → 99.7 |
| Post-scan RSS (MiB) | 973.0 → 973.0 | 815.1 → 815.1 | 154.6 → 154.6 |
| Post-scan PSS (MiB) | 971.4 → 971.4 | 813.6 → 813.6 | 153.0 → 153.0 |
| Post-scan USS (MiB) | 970.6 → 970.6 | 812.8 → 812.8 | 152.2 → 152.2 |
| Input block reads (MiB per batch) | 0.00 → 0.00 | 0.00 → 0.00 | 0.00 → 0.00 |
| Verified root cache-hit rate | 0% → 100% | 0% → 100% | 0% → 100% |
| Warmed-workload CPU reduction | 97.13% | 96.88% | 96.81% |
| Configured cache entry capacity | 65,536 | 65,536 | 65,536 |

The unchanged ClamAV `cache.c` explicitly bypasses clean-result cache lookup and insertion when `SCAN_COLLECT_METADATA` is set. Therefore this diagnostic is not the evidence-preserving shipping configuration, and it does not justify bypassing any hold or release gate. A cache hit is validated using the root file-type callback and absence of the root pre-scan callback under clean outcomes; first-batch root hits must be zero, and every root in every warmed batch must hit. Hydration refers to these 28 workload files, not full cache-capacity occupancy. Before/after SHA-256 hashing remains in timed work. CPU utilization stays near one core because the much shorter scan is still CPU-active; total CPU seconds measure the saved work.

## Statistics and interpretation

The valid workload contains 28 unique valid PDF/JPEG/PNG files, totaling 14,845,995 bytes. Five balanced, randomized rounds run all three variants in both startup cache states: 10 fresh primary engines per variant, 10 initially empty-input-cache batches and 30 hydrated-input-cache batches per variant. The result-cache diagnostic uses five fresh engines and 5 empty + 15 hydrated batches per variant. Lifecycle uses three repetitions of each variant × each CVD, giving nine reload observations per variant. All timings are serial with one scan at a time and CPU affinity fixed to CPU 0. The same machine, GCC 13.3, Rust 1.90.0, Release flags and interpreter bytecode mode are used. Runtime loading of both unrar modules is mandatory and checked in all 78 processes.

The timing boundary is an integrity-preserving local scan pipeline: open, fstat, before-hash, engine scan, after-hash, final fstat, callbacks and result emission. Core engine-only timing is additionally present in each raw file record. Database load plus compilation is timed separately; OS cache preparation, `cl_init`, process creation and PSS snapshots are outside timed scan intervals. No remote upload, queue, storage persistence, narrative submission or application service latency is included.

The statistical unit is a fresh process. Repeated hydrated batches are averaged within each process before the 4,000-resample percentile bootstrap. Paired comparisons use round and initial database-cache state as the pair. Thus repeated files are not incorrectly counted as independent startup trials. P95/P99 are empirical percentiles of the fixed mixed-size corpus, not estimates for every real upload population.

| Hydrated scan comparison | Mean wall-time change | 95% mean-change CI | Median wall-time change | 95% median-change CI |
|---|---:|---:|---:|---:|
| New full vs original | -3.47% | -8.95% to +6.69% | -8.67% | -9.17% to -7.54% |
| Legal Redress vs original | +19.58% | -9.30% to +76.83% | -8.69% | -9.36% to -7.90% |
| Legal Redress vs new full | +23.88% | -14.36% to +92.97% | -0.02% | -1.48% to +0.53% |

Negative change means less elapsed time. No outlier was discarded. A confidence interval spanning zero does not establish a speed difference. Final-round processes 025 (Legal Redress) and 026 (full) contain unusually slow batches: the three hydrated Legal Redress batches were 5.661, 10.543 and 3.704 seconds, with 5.448, 10.017 and 3.520 CPU seconds. This is also a CPU-time increase, so it cannot be explained simply as the process waiting for its turn. Identical bytes, scan options, callback histories and scanned-byte counts were verified. The experiment does not identify the cause. These observations remain in the means, tails and intervals; medians show the typical process alongside that variability. No additional runs were selected to replace them.

| Variant | Hydrated batch mean (s) | SD (s) | 95% mean CI (s) | Min–max process mean (s) |
|---|---:|---:|---:|---:|
| upstream | 1.763743 | 0.014540 | 1.755885–1.772988 | 1.746934–1.795539 |
| full | 1.702540 | 0.278234 | 1.609031–1.881153 | 1.604701–2.493572 |
| legal-redress | 2.109117 | 1.590557 | 1.601885–3.116884 | 1.593262–6.635843 |

## Full update validation breakdown

| Variant / database | Wall time (s, mean) | CPU time (s, mean) | Overlap peak RSS (MiB, max) |
|---|---:|---:|---:|
| upstream / main.cvd | 2.749416 | 2.746911 | 2279.652 |
| upstream / daily.cvd | 3.178970 | 3.177006 | 2564.902 |
| upstream / bytecode.cvd | 0.046544 | 0.046519 | 1921.211 |
| full / main.cvd | 2.869674 | 2.865768 | 1905.359 |
| full / daily.cvd | 2.894640 | 2.892441 | 2120.113 |
| full / bytecode.cvd | 0.058798 | 0.058720 | 1613.176 |
| legal-redress / main.cvd | 3.037938 | 3.034186 | 598.824 |
| legal-redress / daily.cvd | 2.910407 | 2.907750 | 800.125 |
| legal-redress / bytecode.cvd | 0.046039 | 0.045998 | 304.539 |

## Correctness and evidence validation

All 270 page-residency checks passed. All runtime-module checks, result-cache hit checks and 27 updater validation tests passed. All 1,120 accepted scan records per variant had candidate-clean outcomes, zero policy holds and unchanged bytes. Full and reduced each matched original semantics in 1,390 comparisons: 1,120 accepted scans plus 178 positive-fixture scans and 92 adverse scans. These compare complete detection multisets (including weak/PUA legacy events), verdict, layer traversal, scanned bytes, original hashes and hold behavior. They do not prove complete parser coverage.

| Corpus, first pass | Metric | Original | New full | Legal Redress |
|---|---|---:|---:|---:|
| 89 upstream positive fixtures | Detected verdicts | 89 | 89 | 89 |
| 89 upstream positive fixtures | Policy holds | 89 | 89 | 89 |
| 89 upstream positive fixtures | Failed scans | 0 | 0 | 0 |
| 89 upstream positive fixtures | Changed input bytes | 0 | 0 | 0 |
| 89 upstream positive fixtures | Peak RSS over both passes (MiB) | 1123.895 | 824.969 | 161.758 |
| 46 adverse/mixed fixtures | Detected verdicts | 12 | 12 | 12 |
| 46 adverse/mixed fixtures | Policy holds | 19 | 19 | 19 |
| 46 adverse/mixed fixtures | Failed scans | 0 | 0 | 0 |
| 46 adverse/mixed fixtures | Changed input bytes | 0 | 0 | 0 |
| 46 adverse/mixed fixtures | Peak RSS over both passes (MiB) | 1110.004 | 824.695 | 161.891 |

All three builds/configurations have the same detection and hold counts. Positive fixtures are harmless ClamAV test payloads; adverse fixtures are generated locally. None are user submissions. Holds take precedence over a detected policy outcome but retain the detection verdict and events.

The rebuilt upstream and fork each passed the C and Rust suites and the scanner suite (145 passed, 1 platform-tool skip, 5 subtests). The skipped scanner case requires the macOS `xattr` command, unavailable on this Linux host. The selector/configuration unit suite passed all 50 tests. Signed-input tests accepted the valid CVD and equivalent CLD transport and rejected a tampered CVD. Five synthetic severity families with 10,000 relevant signatures each passed accepting-all-match detection equivalence; the prior stricter selected-name/order gate remains unqualified, as expected and recorded. Handler, trust, limits, missing-file and invalid-full-load gates passed.

Initial scanner test discovery used unittest and discovered no scanner tests; installing pytest and reconfiguring fixed discovery, and the entire scanner suite then passed. An initial broad Python unittest discovery also tried to import an argument-taking signed-input script; the intended 50-test unit suite and that signed-input test were subsequently invoked correctly and passed. Logs retain these setup failures and their resolutions.

A completed preflight matrix revealed that optional RAR runtime modules were not on the standalone probe's search path. That matrix is excluded from every final table and statistic. Both matching runtime modules are now explicitly supplied and required; the entire 78-process matrix was rerun. The excluded preflight logs and their provenance remain separately archived to make that correction auditable.

## Configuration and preserved policy

Use `--database-profile=legal-redress` on `tools/subset-selector/scan.py` or `intake.py`. Use `--database-profile=full`, or omit the flag, for the existing full-database default. Full mode retains first-hit behavior by default; add `--allmatch` for the all-match configuration measured here. These are adapter flags, not upstream clamscan or clamd flags.

Reduced mode forces accepting all-match scanning. The signature set retains generic, hash, bytecode, handler, trust, allowlist and uncertain rules and excludes only proven plain PE-only callback groups. Executable/unsupported/unknown/encrypted/limited/error inputs remain held or failed. Parser completeness remains unproven: a no-detection `candidate_outcome` is still `outcome=held` in the reduced evidence workflow. Automatic reduced release remains disabled. Original bytes and metadata must be preserved independently, derivative verdicts cannot clear originals, and narrative submission remains independent with an authorized full-scan/manual exception path.

## Reproduction and artifact map

See [the experiment instructions](../tools/subset-selector/performance/README.md). `subset-selector-results/three-way-performance/` contains the summary with all statistics, raw final per-process JSONL and stderr, hashes, exact synthetic corpus and manifests, bound generation audit files, build flags and toolchain provenance, generated Rust binding diffs, correctness evidence, and exact table data/images. The original signed database blobs and build outputs are not repackaged; fetch the pinned official snapshot and verify all three recorded SHA-256 values. Regenerate the bound profile with your freshly built normal probe before running the matrix.

The same renderer produces the Markdown and PNG cell strings. The source archive preserves earlier reports as historical evidence; this report supersedes their performance comparisons for the freshly measured conditions.
