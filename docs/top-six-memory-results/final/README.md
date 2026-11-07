# Final screening evidence

**The directory-retirement candidate failed the observed performance gate.** It
used about 29 MiB less resident RAM, but startup CPU was 33.61% higher than
original ClamAV. First-pass scan CPU and latency also exceeded the retained
branch. One round does not establish a persistent slowdown or its cause. The
candidate remains research-only; normal builds retain the directories.

| One-round observation | Original ClamAV | Retained branch | Directory candidate |
|---|---:|---:|---:|
| Compiled resident RAM, MiB | 959.25 | 791.64 | 762.95 |
| Resident RAM after workload, MiB | 972.23 | 818.48 | 789.42 |
| Construction resident high water, MiB | 959.01 | 825.27 | 825.64 |
| Startup CPU, seconds | 7.765 | 7.826 | 10.375 |
| First file pass CPU, seconds | 70.843 | 59.565 | 62.021 |
| Warm file pass CPU, seconds | 77.214 | 57.637 | 55.487 |
| First-pass p95 file latency, ms | 946.576 | 639.484 | 736.435 |
| First-pass p99 file latency, ms | 11685.398 | 10235.047 | 10356.715 |
| Warm-pass p95 file latency, ms | 955.936 | 689.906 | 606.145 |
| Warm-pass p99 file latency, ms | 11919.171 | 9938.788 | 9818.931 |

The candidate saves 28.70 MiB compiled and 29.06 MiB after the workload against
retained. Its startup CPU is 32.57% higher than retained; first-pass scan CPU is
4.12% higher, p95 latency 15.16% higher and p99 1.19% higher. Construction high
water is 0.046% higher. Warm scan CPU is lower in this observation, which does
not excuse the failed dimensions. RSS and high water are independently sampled
Linux counters and can differ slightly.

The [corrected summary](corrected-scan/summary.json),
[compact derived result](corrected-scan/screen-result.json),
[bound plan](corrected-scan/plan.json) and [command](corrected-scan/command.json)
record one serial round of three engines: upstream `dd3aa190`, retained
`ca2e956`, and the explicit retention-OFF directory candidate. Each loads all
3,628,192 signatures and scans 163 public files in first and warm passes.
All **978 observations have identical ordered semantics** across roles.
Database-file pages were hydrated before loading; "first" describes the corpus
file pass. Post-workload RSS does not prove every name/field was touched.
The plan binds actual libraries, modules, flags, inputs and limits.

The [fresh targeted correctness report](correctness/summary.json) passes all
**23 cases and 92 observations**. Its retained/candidate hashes start `5c209d7d`
and `6856cc62`, matching the corrected screen's actual plan. These are finite
fixture results, not proof for every database or input. The
[research-artifact preservation record](corrected-scan/research-library-preservation.json)
identifies the retained research binary after the main build is switched back
to the normal retention-ON setting.

Three-round, update, reload, concurrency, complete field/name hydration and
absolute scratch/context requirements remain incomplete. Missing evidence is
not counted as a pass. No minimum-memory or universal timing bound is established.

The [invalid CPU screen](invalid-cpu-screen/aborted.json) remains separate. All
326 candidate observations completed, then the runner rejected a tiny negative
CPU value caused by cancellation in the old collector. The original control
was interrupted. This is a measurement error, not an engine failure or a valid
performance comparison. The corrected screen uses per-counter deltas without
clamping negative measurements. Its unit tests cover the arithmetic issue.

The [resource audit](source-audit/resource-audit.json) rechecks source bodies,
ownership/layout and the exact default/compile-hook changes. It distinguishes
source equivalence for explicit retention-OFF from an independent binary rebuild
attestation. The [fresh query-code audit](source-audit/query-code-audit.json)
binds the corrected screen's retained/candidate pair: all 16 selected source
bodies match; conservative machine-code checks match **5 of 16** functions.
Differences in other functions must not be silently erased or called identical.
The [historical RIP-target check](source-audit/historical-rip-target-check.json)
verifies selected equal string targets for the **earlier `5a8931a4` candidate**,
not the corrected screen's `6856cc62` artifact. It cannot establish equality for
the current pair. Neither bounded audit proves runtime timing or whole-engine
equivalence. Source reproduction scripts are included with their original
workspace paths.

The archives contain only top-level JSONL observations, stderr and process
records, plus the two runner logs. The [supplemental SHA-256 manifest](final-evidence-sha256.json)
binds every copied file and archive member. The earlier evidence manifest remains
unchanged. No database, signature-name table, process-heap-address capture,
fixture directory or executable is included. ELF target addresses appear only
inside the bounded historical code audit.
