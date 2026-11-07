# Logical-rule directory packing: measured, still optional

The candidate saves memory without moving or merging logical rules, but it is
**not approved for the default configuration**. Targeted correctness and a small
full-database smoke test passed. The complete performance qualification has not
been run, and one small sample measured 2.98% more reload CPU time.

The earlier logical-sharing experiment remains rejected. This is a different
experiment: it replaces only a table of addresses after every matcher has been
ordered and compilation has succeeded. It leaves the actual rules, names,
logical expressions, IDs and their addresses unchanged.

## What the table change does

On a 64-bit system, an ordinary table stores one 8-byte address per logical
rule. The candidate stores one common 8-byte base address and one 4-byte distance
from that base for each rule. A lookup reconstructs the exact original address.
It applies only to tables with at least 16,384 entries. If the addresses span
too large a range, allocation fails, or the platform is ineligible, the original
table stays in place.

In the measured database, the largest table has 297,075 entries. Its payload
changes from **2,376,600 to 1,188,308 bytes**, saving **1,188,292 bytes (1.13 MiB)**.
Linux reported **581 resident pages** covering the ordinary table and **291
pages** covering the packed table in the normalized reload smoke test.

Merely making an exact-size 8-byte copy did not help: the isolated allocator
experiment observed no normal-case RSS saving. Unused allocation capacity was
mostly untouched. This distinguishes payload/capacity arithmetic from actual
resident-memory savings.

## What was tested

The shared strict correctness suite passed all **23 cases and 92 scan
observations**, with 10,000 duplicate rule pairs and 10,000 hash distractors. It
compared exact callback order and multiplicity, final labels, verdicts, errors,
limits, callback ignore/stop/trust decisions, malformed databases, macros and
unchanged input bytes.

That suite's small logical case does not activate this optional format. Five
additional cases did: 20,000 logical rules with groups of 65 records sharing each
name, a 16,401-rule macro database, and callback ignore/stop/trust behavior. All
**48 observations** matched, and a test-only inspector confirmed that the
candidate actually used the packed format.

Four serial full-database reload processes and four scan processes ran in
ordinary/packed/packed/ordinary order, with two processes per variant. All
3,628,192 signatures loaded. The reload test kept two engines alive, then freed
the old engine and the replacement. The scan test used nine files, first scans
and three hydrated rounds: **144 observations**, all with identical semantics.
The result cache was disabled. Limits were 3 GiB address space, 150 CPU seconds,
180 wall seconds per process, and one pinned CPU. Database files were private
copies with a hydrated file cache.

| Median observation | Ordinary directory | Packed directory |
|---|---:|---:|
| Compiled RSS | 780,642 KiB | 777,056 KiB |
| Compiled PSS | 779,947 KiB | 776,361 KiB |
| Construction high water | 844,906 KiB | 844,264 KiB |
| Hydrated scan RSS | 803,328 KiB | 800,636 KiB |
| Two-engine overlap RSS | 1,557,582 KiB | 1,549,912 KiB |
| Reload high water | 1,621,998 KiB | 1,618,456 KiB |
| Reload CPU | 7.235 s | 7.451 s |
| CPU for 27 hydrated file scans | 4.304 s | 4.038 s |

The scan CPU numbers do **not** establish a speedup: the ordinary variant's two
run totals ranged from 4.047 to 4.560 seconds. The larger whole-process memory
differences also must not be equated with the exact 1.13 MiB table saving.
Allocator reuse, code residency and small-run variability affect those numbers.

The two builds had different compiled-in certificate-directory strings. The
accepted memory runs set `CVD_CERTS_DIR` to the same path before engine creation,
as well as setting the engine option afterward, to remove that allocation-class
confound. Earlier unnormalized runs are excluded from the reported medians.
The remaining configuration differences concern app-only ncurses support.

## Correctness and complexity boundaries

Encoding uses the minimum non-NULL address as the base. Every accepted
non-NULL offset is below `UINT32_MAX`; that reserved value represents NULL, and
zero remains a valid offset. Adding the stored offset to the base recovers the
original address without overflow. Allocation failure does not change the old
table or its ownership. Dedicated tests cover boundary values, NULLs, duplicate
pointers, order and allocation failure, including ASan/UBSan runs.

The conversion runs after successful bytecode preparation, following retirement
of eligible pattern and candidate cleanup directories. It does not change any
pre-link allocation or address-based tie breaker. Logical reads in matching,
macro checks, YARA, cleanup and diagnostics use the same accessor. Diagnostic
extent accounting uses the actual encoded image size.

Lookup remains worst-case **O(1)**: a fixed format test, bounded loads and one
addition, without query allocation, caching, searching or decoding loops. Query
and per-context heap allocation do not increase. Compilation adds two O(N)
passes and a temporary `4*N + 8` byte image while the old table is still live;
therefore these observations are not an all-database proof that construction or
reload peak can never rise. The matcher format/ownership byte occupies existing
LP64 padding. C and Rust keep the same 472-byte matcher size and all 47 existing
field offsets. The field is omitted on 32-bit builds; 32-bit was source-reviewed,
not rebuilt.

`ENABLE_LSIG_DIRECTORY_IDS` stays **OFF**. A complete 18-metric performance run,
more latency/concurrency/update evidence, and a source-bound builder-scratch
assessment are still required before promotion. The bounded reload CPU result
also needs resolution. No minimum-memory or universal performance guarantee is
claimed.

A repeat of the shared strict suite against the final rebuilt directory-only
library also passed all 23 cases and 92 scan observations. Its baseline library
hash starts `5a8931a4`; the unchanged packed candidate starts `9b910cf9`. This
repeat does not activate the packed format in the small logical case, so the
separate active-format tests remain necessary.

The runtime implementation is archived in
[`experiments/logical-directory-ids.patch`](../experiments/logical-directory-ids.patch).
It is not incorporated into the retained scanner.

## Evidence and reproduction

- [Combined summary](logical-directory-results/summary.json)
- [Strict shared correctness report](logical-directory-results/strict-correctness.json)
- [Repeat against the final directory-only library](logical-directory-results/fresh-directory-correctness.json)
- [Active-format correctness report](logical-directory-results/active-packed-correctness.json)
- [Reload observations and bindings](logical-directory-results/reload/summary.json)
- [Scan observations and bindings](logical-directory-results/scan/summary.json)
- [C/Rust ABI comparison](logical-directory-results/abi.json)
- [Exact-copy allocator experiment](logical-directory-results/isolated-exact-copy-residency.json)
- [Artifact hashes](logical-directory-results/evidence-sha256.json)

The archived reproduction scripts and inspector source record the exact workspace
paths used, not portable installation defaults. Their plans bind actual library,
probe, fixture and certificate hashes. The ABI report records the earlier header
hash before an include-guard-only follow-up; its structural declarations are
unchanged. Raw scan/reload JSONL files are included. Large synthetic callback
transcripts remain in the execution workspace, with their hashes and semantic
hashes retained in the correctness reports.
