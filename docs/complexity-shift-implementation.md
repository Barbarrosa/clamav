# Complexity-shift implementation and experiments

27 October 2026, America/Phoenix. This revision builds on the previously repaired
ClamAV fork. It does **not** meet the 202.042 MiB quarter-memory target.

The retained scanner prototype replaces individually owned hash buckets/name
strings with contiguous digest arrays and a stable name arena. It reuses
ClamAV's size-hash algorithm with integer bucket indices. Measured compiled RSS
falls approximately 49 MiB, or 6%, against the recovered fork. Compilation peak
rises approximately 104 MiB. Consequently `ENABLE_FLAT_HASH_STORE` remains
**OFF by default**. Independent token decoding is a separate research executable,
not a newly enabled scanner path.

## What changed and why

The first prototype used a sorted size directory. It preserved exact results,
but random successful size lookups slowed from 44 to 415 ns in the first probe.
It was rejected. The retained design keeps the original size hash's capacity,
key placement, exact comparison, collision sequence and probe bound. Values now
identify ranges in contiguous arrays instead of pointing at bucket objects.
The digest comparator and per-bucket sort retain their original ordering,
including duplicate selection. Unaligned word reads now use `memcpy`.

Name references are direct 3-, 4- or native-width byte offsets into a raw arena.
There is no global interner, probabilistic filter or name cache. Offset zero
means NULL, distinct from an empty string. Returned scan-time name pointers
remain stable until the engine is freed. Width selection depends on arena
length; it does not impose a new signature-count limit.

The allocator investigation materially changed the implementation. ClamAV's
pool fragment-free operation does not unmap pages. Simply copying into compact
arrays could increase RSS. Hash construction therefore uses a disposable pool;
normalization and allocation happen directly there. Once all compiled arrays
are successfully allocated, the original sort runs, data is copied, and the
entire builder pool is destroyed. A later lead removed millions of redundant
individual fragment frees before that destruction. Failed destination
allocation leaves the builder and duplicate order unchanged for retry.

The normal string loader now owns name normalization/allocation; callers lend
the parser string. Existing unofficial suffixes, legacy suffix stripping,
malformed-name rejection and load callbacks are preserved. The production
binary-hash caller uses NULL names for certificate trust hashes. The private
C/Rust layouts were updated together and checked field by field.

This is a shift of scan-time ownership into compilation, **not proof of less
implementation complexity overall**. It adds transactional conversion, a
builder/compiled distinction and validation obligations. Keeping both legacy
and experimental configurations also adds a test matrix. Those costs, and the
construction peak, prevent promoting it as an unconditional simplification.

## Measured scanner results

Baseline means the unmodified source recovered from artifact version 5, already
containing the previous AC and logical-state improvements. It does not mean
stock upstream ClamAV. Both full-feature Release builds use Rust 1.90, GCC 13.3,
`ENABLE_AC_NODE_IDS=ON`, `ENABLE_AC_FLAT_NODES=ON`,
`ENABLE_COMPACT_LSIG_STATE=ON`, `ENABLE_AC_DISPOSABLE_BUILD=OFF`, and memory pools.
The scan cache is disabled equally in both probes. The database has 3,628,192
signatures; its exact input hashes and build provenance accompany the results.

| Observation | Recovered baseline | Rejected sorted prototype | Retained indexed prototype |
|---|---:|---:|---:|
| Compiled RSS, hash probe | 825.50 MiB | 771.30 MiB | 776.13 MiB |
| Construction high-water RSS, same probe | 825.32 MiB | 924.53 MiB | 929.67 MiB |
| Database loading | 9.00 s | 15.01 s | 8.41 s |
| Compilation | 2.30 s | 3.99 s | 2.80 s |
| Random successful size lookup, median of 8 repeats | 44.1 ns | 415.4 ns | 37.0 ns |
| Sequential size lookup | 24.2 ns | 45.4 ns | 17.0 ns |
| Repeated first 32 records | 6.0 ns | 11.2 ns | 5.8 ns |
| Mutated, mostly absent sizes | 211.2 ns | 112.5 ns | 80.4 ns |

RSS and `getrusage` high-water counters use different kernel accounting paths;
the baseline's small inverted difference is measurement granularity, not a
claim that peak is below current usage. These are individual process runs on a
shared host. Eight within-process repeats are not eight independent builds or
a confidence interval. They support rejecting the severe binary-search
regression; they do not establish a general speedup for the retained design.

The independent public-API corpus comprises WordPress 6.8.3 source files plus
ClamAV test inputs: 3,319 files totaling 85,031,530 bytes. Downloaded PHP was never
executed. The pinned version is a repeatable test corpus, not a deployment
recommendation or a measured SiteGround workload average.

| Public-API observation | Baseline | Indexed prototype |
|---|---:|---:|
| Compiled RSS | 824.62 MiB | 775.65 MiB |
| RSS after both scan passes | 850.10 MiB | 801.07 MiB |
| First-hit pass | 81.52 s | 82.31 s |
| All-match pass | 124.13 s | 111.48 s |
| Detected files in each mode | 87 | 87 |
| Scan errors | 0 | 0 |
| First-hit callbacks | 87 | 87 |
| All-match callbacks | 89 | 89 |

All return codes, selected names and ordered callbacks produce identical
transcript hashes. One pass per mode/build is insufficient to promise speed
parity, let alone a speedup. No production daemon throughput, reload availability,
WordPress/PHP coexistence or concurrent hosting peak is qualified here.

The concrete hash layout saves **16.514 MiB of accounted payload/metadata**:
12.776 MiB from name references and about 3.737 MiB from bucket metadata. Name
text and digest values remain exact and uncompressed. The larger RSS saving
also reflects released pool storage and allocator effects; it must not be
attributed entirely to those payload terms or subtracted again from earlier
hypothetical globally interned layouts.

## Correctness and resilience gates

- All 3,213,522 loaded hash records were queried directly, then with a mutated
  digest and alternate size: **9,640,566 queries**. Exact return-code/name
  transcript SHA-256 is
  `82d80724141f53a3adba75a8316bb250c4bfbf790de1fc0e6e965f0dac704928`
  in all three implementations.
- The retained full engine passes **1,816 C checks**, **65 Rust tests**, and
  **145 clamscan tests**, with one skipped test and five passing subtests.
- ASan/UBSan covers **16 compiled-store allocation failure points**, successful
  retries, duplicate choice, NULL/empty names, unaligned digests, pointer
  lifetime, normalization and the 24-bit offset boundary. A separately compiled
  legacy matcher branch passes 12,672 differential queries under sanitizers.
  Pool internals/the entire shared library are not sanitizer-instrumented;
  leak detection is disabled for these targeted probes.
- The 10,000-rule-pair duplicate-order differential passes, also with 10,000
  harmless hash distractors. Strong detections survive mixed weak/PUA cases at
  three positions, with three first-hit repetitions and all-match checks.
- The final C/Rust ABI field-offset comparison passes.

The existing hash algorithm's worst-case collision behavior is retained; no
new probabilistic membership or attacker-selected fallback is introduced.
Digest ordering, full digest equality, all signature families, certificate
trust processing and the previous nonterminal-evidence repair remain active.
The tests establish specific equivalences; they are not an exhaustive proof
against every adversarial file, architecture or allocation schedule.

The daemon suite was attempted but cannot allocate its Unix socket in this
environment (`Operation not permitted`). No daemon pass is claimed. A complete
OFF-profile engine rebuild, no-pool build, 32-bit/big-endian qualification,
concurrency stress and controlled reload testing remain promotion gates; the
legacy matcher branch alone was additionally exercised here.

## Less certain experiment: independent token decoding

The [OnPair paper](https://arxiv.org/abs/2508.02280) motivates independent
short-string decoding with a shared substring dictionary. This experiment uses
[SpiralDB onpair 0.2.1](https://github.com/spiraldb/onpair), pinned with a separate
Cargo lockfile and Rust 1.91. It is a different implementation from the paper's
reference benchmark. No third-party codec is linked into libclamav.

The input is all **1,066,576 unique specialized token sequences**, including
29,241 sequences requiring 16-bit tokens. Every byte and width is verified.
Dictionary/index data, retained vector capacity, descriptors and an 8,016-byte
padded decoder buffer are charged. Raw input/oracle, training workspace and
query vectors are excluded from layout bytes. These are component measurements,
not engine RSS reductions.

| Token representation | Retained layout | Status |
|---|---:|---|
| Existing specialized raw token prototype | 34.214 MiB | Fast reference profile |
| Independent dictionary, 12-bit budget / 16-bit codes | 35.198 MiB | Reject: expands this input |
| Independent dictionary, 14-bit budget / 16-bit codes | 28.635 MiB | Larger than 16-bit-budget result |
| Independent dictionary, 16-bit budget | 25.549 MiB | Intermediate profile candidate |
| Same, width flags retained in code offsets | **25.422 MiB** | Successful follow-up simplification |
| Zstd 4 KiB blocks, 1 MiB decoded cache | 23.704 MiB | Smaller; miss amplification remains |
| Zstd 256 KiB blocks, 1 MiB decoded cache | 22.219 MiB | Smallest tested token layout |

The flagged-index variant removes 133,322 bitmap bytes and one 24-byte vector
descriptor. The proof is simple: every code emits at least one byte, so code
count cannot exceed raw payload length. The existing specialized layout already
requires that length to be below 2^31. Its original width flag therefore still
fits in the code-offset high bit. Masking that bit reuses the old indexing
convention; it adds no tighter bound. All rows and widths round-trip in the
follow-up experiment.

Independent decoding costs around 0.1 microsecond per random row in these
probes. Rerun block probes take approximately 11 microseconds for 4 KiB blocks
and 518 microseconds for 256 KiB blocks on random access; deliberately colliding
block traces are also expensive. Access counts differ (262,144 versus 4,096),
so these are comparable workload classes, not a paired same-query-count speedup
estimate. Repeated longest-row reconstruction takes approximately 6 microseconds
versus about 2 ns for a raw slice reference. Raw references do not reconstruct
or verify every byte, so that ratio is not a scanner slowdown estimate.

This candidate could replace the *previously proposed* token block cache and
its eviction state, improving predictable random access at a roughly 3.20 MiB
cost versus the smallest token layout. It still adds dictionary construction,
serialized-data validation and a dependency. It has not replaced the scanner's
verifier or preserved early-exit verifier performance by measurement. The raw
profile would need to remain available. Malformed dictionary/output-capacity
smoke tests pass; a codec audit and full scanner differential are still required.

No high-entropy compression guarantee is possible: the 12-bit-budget experiment
already expands this real input. Nor does independent decoding cap total scan
work: an attacker can still trigger many legitimate candidate verifications.
Immutable dictionaries can be shared; scratch must be multiplied by concurrent
active decoders. Training/benchmark process peaks are separately recorded and
must not be confused with the retained representation.

## Lead review and deployment decision

The [live lead log](complexity-shift-leads.md) records 22 leads and a final
reconsideration for every one. Two discovered leads were implemented and
validated: whole-pool cleanup and width flags in code offsets. Direct name
allocation and reuse of the original size hash repaired measured startup and
lookup regressions. Small-dictionary bit packing was rejected by arithmetic:
even ideal packing remains larger than the 16-bit dictionary before adding
unpacking work. Global name interning has only 0.427 MiB of duplicate text to
recover in this corpus. Bucket-relative name offsets offer at most 2.547 MiB
before a new directory and do not justify another access convention yet.

For the planned SiteGround WordPress use, the evidence supports an optional
approximately 49 MiB resident saving in this integrated fork. It does **not**
support a 200 MiB production engine or a fourfold reduction. The observed
approximately 930 MiB construction peak may be the binding limit on a small
host. Do not deploy this option based only on its lower steady RSS. Direct
final-layout construction or more carefully separated builder lifetimes are
logged follow-ups requiring a new rollback/ownership design.

Nothing was deployed, published or changed on SiteGround. Enable the prototype
for further qualification with `-DENABLE_FLAT_HASH_STORE=ON`; the default legacy
layout remains available. No optional codec or signature omission is enabled.

## Reproduction and provenance

See [aggregate evidence](complexity-shift-results/README.md),
`tools/compact-memory/summarize_complexity_shift.py`, and the individual probe
sources. Build both recovered baseline and retained source as full-feature
Release configurations. The custom hash probes use separately relinked copies
of the same objects with private symbols exported; production shared libraries
are not modified. Public corpus probes link the production libraries.

Both engine builds used Cargo release `codegen-units=1` in an external local
configuration after a toolchain archive step produced an empty codegen object.
This build workaround was applied equally and is not a scanner-source change.
The codec uses its own pinned package/lockfile and explicit release profile.
Codec and block timings run sequentially on CPU 2; engine timing CPU affinity
was unrestricted and other host load was uncontrolled.

The archive preserves prior research, source, licensing and patch history.
The original Git objects were unavailable; this revision follows a documented
recovery snapshot. Archive source bytes were restored from the saved input;
Git's recovery normalization/mode handling is not represented as identical
ancestry to the earlier recorded source tree. Database/corpus hashes, toolchain,
configuration, source/evidence hashes and patch provenance are recorded. Raw
signatures, databases, WordPress downloads, third-party codec source, toolchains
and built binaries are excluded from the deliverable.
