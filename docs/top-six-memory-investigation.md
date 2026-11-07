# What the top six memory investigations found

**None of these additional savings met every requirement for normal builds.**
Releasing construction-only pointer tables used about **29 MiB less resident
RAM**, but the final screen missed performance limits: startup CPU was **33.6%
higher than original ClamAV**, and first-pass scan costs also exceeded the
retained branch. These are observed misses, not merely missing measurements.
One round does not establish a persistent slowdown or its cause.

The earlier likelihood-and-size ranking was a planning estimate. These concrete
experiments replace those estimates where measurements are now available.

| Ranked area | What was investigated | Current outcome |
|---|---|---|
| 1. Pattern records | Release the large pattern-pointer directory after compilation; retain it wherever logical macros need runtime lookups. | Lower RAM as part of the directory candidate, but its performance screen failed. Actual records, tokens and names stay in place. The older record-shrinking patch still fails duplicate-order compatibility. |
| 2. Logical-rule metadata | Pack the logical-rule address directory after compilation, preserving rules and their existing addresses. | Exact table payload falls **1.13 MiB** and targeted correctness passes. The small whole-engine screen includes **2.98% more reload CPU**; the implementation remains archived. [Logical-directory evidence](logical-directory-investigation.md). |
| 3. Signature names | Copy hash names into one stable raw arena after compilation, then release their old allocations. | Rejected: resident RAM increased **73.9 MiB** because the small freed pool allocations remained resident. [Name-arena evidence](name-arena-investigation.md). |
| 4. Candidate lists | Release the candidate-pointer cleanup directory after compilation, while keeping the ordered candidate records and links. | Lower RAM as the other part of the directory candidate, whose performance screen failed. This is not candidate-record compression. |
| 5. Signature tokens | Replace eligible 16-bit sequences with exact byte sequences after compilation. | Rejected: nominal payload fell **32.1 MiB**, but resident RAM increased **24.0 MiB** with pool replacements or **68.4 MiB** with heap replacements. [Token evidence](token-compaction-qualification.md). |
| 6. Pool allocation sizes | Add tighter size classes around common transition rows and logical records. | Rejected: **4 of 23 strict correctness checks failed**, covering duplicate reporting and three PUA positions. The change was removed from active source; the [experimental patch](../experiments/tight-pool-classes.patch) is retained. |

The names and tokens experiments demonstrate a shared obstacle: **freeing many
small objects does not automatically return their pages to the operating
system**. Copying them into a smaller representation can therefore increase
actual RAM. A stored-byte reduction is insufficient evidence for integration.

## Why directory retirement is different

The directory candidate waits until all fallible engine compilation services
have succeeded. It releases large pointer-array fragments, whose interior pages
can be reclaimed without relocating live objects. It preserves the original
loading allocations and the address-derived order established while building
the matcher.

The containing engine pool continues to own the pattern, extension, token, name
and candidate allocations. No rule or candidate occurrence is removed. Macro
lookups keep their original pattern table; missing metadata also keeps the
table rather than assuming it is unused. Non-pool builds retain their original
individual-cleanup ownership. Private census/export tools require an explicit
directory-retention build and fail with a rebuild instruction when indexes are
missing.

Actual page-reclamation measurements are from 64-bit Linux. They do not establish
the same saving or performance on another platform.

The final distinct-artifact directory comparison passed **23 targeted
correctness checks and 92 scan observations**, including the dedicated
duplicate-order fixture. The larger screen also matched exact ordered results
for **978 observations**: 163 files in first and warm passes through each of
three engines. Neither result proves correctness for every input.

## What the final screen measured

Each engine loaded the same **3,628,192 signatures**. Original ClamAV is the
pinned upstream commit; the retained branch is the version before this round.
The directory candidate is an explicit research build with retention disabled.
The following are **one process per engine**, not averages or confidence bounds.

| Observation | Original ClamAV | Retained branch | Directory candidate |
|---|---:|---:|---:|
| Compiled resident RAM, MiB | 959.25 | 791.64 | 762.95 |
| Resident RAM after workload, MiB | 972.23 | 818.48 | 789.42 |
| Construction resident high water, MiB | 959.01 | 825.27 | 825.64 |
| Startup CPU, seconds | 7.765 | 7.826 | 10.375 |
| First file pass CPU, seconds | 70.843 | 59.565 | 62.021 |
| Warm file pass CPU, seconds | 77.214 | 57.637 | 55.487 |
| First-pass p95 file latency, ms | 946.576 | 639.484 | 736.435 |
| First-pass p99 file latency, ms | 11685.398 | 10235.047 | 10356.715 |

The candidate saves **28.70 MiB compiled** and **29.06 MiB after the workload**
against the retained branch. Warm scan CPU is lower in this observation. But
startup CPU is **32.57% higher than retained** and **33.61% higher than original**.
Against retained, first-pass CPU is **4.12% higher**, p95 latency **15.16% higher**,
and p99 **1.19% higher**. Construction high water is also slightly higher
(**0.046%**). The strict observed performance gate therefore **failed**.

Database-file pages were hydrated before loading; "first" describes the corpus
file pass. Post-workload RAM does not prove every name or field was touched.
Resident RAM and high water are independently sampled Linux counters and can
differ slightly. A single round does not establish causation, statistical
confidence or all-input bounds. Three-round, update, reload, concurrency and
absolute scratch/context requirements remain incomplete. Faster scan CPU than
original ClamAV does not excuse the startup miss.

The earlier nine-file screen, including its slower warm-scan observation, is
retained separately. Another full-corpus attempt was stopped because its CPU
collector produced a tiny negative value from numerical cancellation. That
attempt is explicitly invalid for performance conclusions; the corrected screen
above uses the fixed collector. See the [final reports and limits](top-six-memory-results/final/README.md).

## What still blocks promotion

Success requires preserving selected signatures, exact reporting behavior,
severity, callback/stop/trust/error handling, name-pointer lifetimes and engine
ownership. It also requires qualified measurements against the retained branch
and the pinned original ClamAV baseline: scan CPU and latency, startup, updates,
construction, cold and hydrated memory, reload overlap and concurrency.

The directory change adds a bounded compilation-time metadata pass and targeted
page reclamation. It introduces **no new scan-time format, decoder, persistent
decoded cache, allocation or identity lookup**. Existing scan allocations and
scratch still exist; their absolute sizes are not declared zero. The algorithmic
growth of the query paths is unchanged. Code alignment, page residency and
allocator state can nevertheless change real timing, so these source properties
do not substitute for performance measurements.

Normal builds retain the existing directories by default:
**`ENABLE_AC_DIRECTORY_RETENTION=ON`**. `OFF` explicitly enables the retirement
experiment. No additional saving from this round has met every promotion
requirement. No rejected name, token, logical-sharing or tighter-bin prototype is
enabled merely because its modeled storage is smaller.

Read the [qualification procedure and evidence requirements](../tools/compact-memory/top-six-qualification/README.md),
the [source and machine-code audit tool](../tools/compact-memory/top-six-qualification/query_code_audit.py),
the [archived reports and artifact bindings](top-six-memory-results/README.md),
and the earlier [padding investigation](allocation-perturbation.md).
