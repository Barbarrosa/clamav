#!/usr/bin/env python3
"""Build the complete benchmark report from validated measurements."""
import argparse
import json
from pathlib import Path
from render_tables import build_tables, markdown, VARIANTS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--summary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();s=json.loads(a.summary.read_text());t=build_tables(s)
    v=s['variants'];r=v['legal-redress'];f=v['full'];u=v['upstream']
    text=f'''# Fresh three-way ClamAV performance analysis — 2026-10-29

All figures below come from one new controlled experiment, with both engines rebuilt using the same toolchain. No historical benchmark cell is reused. Original means the pinned, unmodified ClamAV development baseline `dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`, not the latest ClamAV release. New full and Legal Redress use retained engine source `9dfde0139708a1eb1a728f86baecb1d8ec1b66df`; their only difference is the conservative signature-load callback. The archive update adds measurement tools, evidence and documentation; it does not change engine algorithms or shipping defaults.

Legal Redress loads **{r['percent_full_signature_count']:.2f}%** of the engine-counted signatures and reduces mean compiled RSS by **{r['compiled_rss_reduction_vs_upstream_percent']:.2f}%** versus original, or **{100*(1-r['compiled_rss_kib']['mean']/f['compiled_rss_kib']['mean']):.2f}%** versus new full. The removed count is **{r['omitted_signature_count']:,}**. The official compressed CVD files are still retained and verified in full: **{r['signed_source_bytes']:,} bytes**, or **100%** of source bytes. Signature percentage is a count ratio, not a byte ratio or a malware-detection coverage percentage. The engine count may include expanded logical/subsignature units; it is distinct from the selector's excluded callback-name count.

## Database, memory and lifecycle

{markdown(t['overview'])}

RSS is resident process RAM; PSS apportions shared pages; USS counts private pages. All memory quantities use binary MiB. Peaks are maxima of Linux process high-water RSS, which is cumulative from process start. Scan peak therefore includes engine construction. Reload retains both old and replacement engines. Update tests add an actual unreduced `fc_test_database_ex()` load/bytecode-preparation operation for one CVD while both engines remain live. Each main/daily/bytecode test has its own fresh process. This API validates a database; it does not perform the full engine AC compile step. No network download is included in these CPU/timing intervals.

The observed reduced reload peak is **{r['reload']['hwm_kib']['max']/1024:.1f} MiB**. A 303 MiB hard process ceiling is therefore too low for this rerun. Co-located full update validation reaches **{r['update_overlap_peak_kib']/1024:.1f} MiB**; full-database preparation and validation should remain in a separately budgeted worker. The measurements are not a universal upper bound for arbitrary content, concurrency or allocator behavior.

## OS file-page cache: empty → hydrated

Metadata collection, all-match, all parsers and the same heuristic settings are enabled for every variant. The ClamAV clean-result cache is disabled equally. Database startup and input scans each have independent page-cache preparation. Empty means 0% of tested-file pages resident; hydrated means 100%, verified by `mincore` before every phase. It does not describe CPU hardware caches or the storage device's internal cache.

{markdown(t['os_cache'])}

Values are means unless labeled median, apart from pooled per-file latency percentiles. CPU utilization is CPU seconds divided by wall seconds, with one core equal to 100%. User and system CPU times, page faults, block reads/writes, anonymous/file PSS, confidence intervals and ranges are retained for every phase in `subset-selector-results/three-way-performance/summary.json`. The file-page working set is measured separately from process memory; it is not added to RSS/PSS, which could double count mappings. Shared cgroup samples are context only and are not reported as isolated scanner RAM. Database loads use the retained `CL_DB_STDOPT` configuration. Limits are identical: 100 MiB per file, 400 MiB scanned content, recursion depth 17 and 10,000 files.

## ClamAV clean-result cache: empty → hydrated

This diagnostic turns metadata collection off and enables ClamAV's 65,536-entry result cache, equally in all variants. OS input pages are hydrated in both states to isolate result-cache effects. Empty/hydrated refers to cache state **at the start** of the scan batch; post-scan RAM is sampled after that batch. Initial empty-cache engine RSS provides the before-scan baseline.

{markdown(t['result_cache'])}

The unchanged ClamAV `cache.c` explicitly bypasses clean-result cache lookup and insertion when `SCAN_COLLECT_METADATA` is set. Therefore this diagnostic is not the evidence-preserving shipping configuration, and it does not justify bypassing any hold or release gate. A cache hit is validated using the root file-type callback and absence of the root pre-scan callback under clean outcomes; first-batch root hits must be zero, and every root in every warmed batch must hit. Hydration refers to these 28 workload files, not full cache-capacity occupancy. Before/after SHA-256 hashing remains in timed work. CPU utilization stays near one core because the much shorter scan is still CPU-active; total CPU seconds measure the saved work.

## Statistics and interpretation

The valid workload contains 28 unique valid PDF/JPEG/PNG files, totaling {s['environment']['fixture_bytes']:,} bytes. Five balanced, randomized rounds run all three variants in both startup cache states: 10 fresh primary engines per variant, 10 initially empty-input-cache batches and 30 hydrated-input-cache batches per variant. The result-cache diagnostic uses five fresh engines and 5 empty + 15 hydrated batches per variant. Lifecycle uses three repetitions of each variant × each CVD, giving nine reload observations per variant. All timings are serial with one scan at a time and CPU affinity fixed to CPU 0. The same machine, GCC 13.3, Rust 1.90.0, Release flags and interpreter bytecode mode are used. Runtime loading of both unrar modules is mandatory and checked in all {s['completed_processes']} processes.

The timing boundary is an integrity-preserving local scan pipeline: open, fstat, before-hash, engine scan, after-hash, final fstat, callbacks and result emission. Core engine-only timing is additionally present in each raw file record. Database load plus compilation is timed separately; OS cache preparation, `cl_init`, process creation and PSS snapshots are outside timed scan intervals. No remote upload, queue, storage persistence, narrative submission or application service latency is included.

The statistical unit is a fresh process. Repeated hydrated batches are averaged within each process before the 4,000-resample percentile bootstrap. Paired comparisons use round and initial database-cache state as the pair. Thus repeated files are not incorrectly counted as independent startup trials. P95/P99 are empirical percentiles of the fixed mixed-size corpus, not estimates for every real upload population.

| Hydrated scan comparison | Mean wall-time change | 95% mean-change CI | Median wall-time change | 95% median-change CI |
|---|---:|---:|---:|---:|
'''
    for key,label in [('upstream-to-full','New full vs original'),('upstream-to-legal-redress','Legal Redress vs original'),('full-to-legal-redress','Legal Redress vs new full')]:
        c=s['comparisons'][key]['warm_scan_wall_percent'];text+=f"| {label} | {c['percent_change']:+.2f}% | {c['95ci'][0]:+.2f}% to {c['95ci'][1]:+.2f}% | {c['median_percent_change']:+.2f}% | {c['median_95ci'][0]:+.2f}% to {c['median_95ci'][1]:+.2f}% |\n"
    text+='\nNegative change means less elapsed time. No outlier was discarded. A confidence interval spanning zero does not establish a speed difference. Final-round processes 025 (Legal Redress) and 026 (full) contain unusually slow batches: the three hydrated Legal Redress batches were 5.661, 10.543 and 3.704 seconds, with 5.448, 10.017 and 3.520 CPU seconds. This is also a CPU-time increase, so it cannot be explained simply as the process waiting for its turn. Identical bytes, scan options, callback histories and scanned-byte counts were verified. The experiment does not identify the cause. These observations remain in the means, tails and intervals; medians show the typical process alongside that variability. No additional runs were selected to replace them.\n\n'
    text+='| Variant | Hydrated batch mean (s) | SD (s) | 95% mean CI (s) | Min–max process mean (s) |\n|---|---:|---:|---:|---:|\n'
    for key in VARIANTS:
        d=v[key]['scan']['file_cache_hydrated']['wall_seconds'];text+=f"| {key} | {d['mean']:.6f} | {d['sd']:.6f} | {d['mean_95ci'][0]:.6f}–{d['mean_95ci'][1]:.6f} | {d['min']:.6f}–{d['max']:.6f} |\n"
    text+='\n## Full update validation breakdown\n\n| Variant / database | Wall time (s, mean) | CPU time (s, mean) | Overlap peak RSS (MiB, max) |\n|---|---:|---:|---:|\n'
    for key in VARIANTS:
        for db,d in v[key]['updates'].items():text+=f"| {key} / {db} | {d['wall_seconds']['mean']:.6f} | {d['cpu_seconds']['mean']:.6f} | {d['hwm_kib']['max']/1024:.3f} |\n"
    text+='\n## Correctness and evidence validation\n\n'
    text+=f"All {s['validation']['page_cache_checks']} page-residency checks passed. All runtime-module checks, result-cache hit checks and 27 updater validation tests passed. All 1,120 accepted scan records per variant had candidate-clean outcomes, zero policy holds and unchanged bytes. Full and reduced each matched original semantics in 1,390 comparisons: 1,120 accepted scans plus 178 positive-fixture scans and 92 adverse scans. These compare complete detection multisets (including weak/PUA legacy events), verdict, layer traversal, scanned bytes, original hashes and hold behavior. They do not prove complete parser coverage.\n\n"
    text+='| Corpus, first pass | Metric | Original | New full | Legal Redress |\n|---|---|---:|---:|---:|\n'
    for stage,label in [('positive','89 upstream positive fixtures'),('adverse','46 adverse/mixed fixtures')]:
        for field,desc in [('detected_verdicts','Detected verdicts'),('held','Policy holds'),('failures','Failed scans'),('integrity_changes','Changed input bytes'),('peak_rss_kib','Peak RSS over both passes (MiB)')]:
            vals=[f"{v[k][stage][field]/1024:.3f}" if field=='peak_rss_kib' else str(v[k][stage][field]) for k in VARIANTS]
            text+=f"| {label} | {desc} | {' | '.join(vals)} |\n"
    text+='''
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
'''
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text)
    print(a.output)


if __name__=='__main__':main()
