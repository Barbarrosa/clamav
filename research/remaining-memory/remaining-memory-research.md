# ClamAV: remaining memory contributors and research opportunities

> Correction, 28 October 2026: logical-template estimates and aggregate budgets derived from the old range exporter are superseded by source/docs/logical-sharing-implementation.md in this archive. This was a diagnostic over-read/counting defect, not a scanner range change.

Research date: 27 October 2026. Source revision: `2c464040eddf2c04951a21e6277f16823f5e5bf8`.

## Findings and recommendation

The strongest immediately calculable opportunity is **20.465 MiB of gross payload reduction** across hash-bucket metadata, hash-to-name IDs, and name/token offsets. This is a proposed representation calculation, not an implementation result or measured RSS saving. Search/select support and allocation overhead must be added.

The strongest new codec experiment is **OnPair16 on the already deduplicated token sequences**, compared with OptFSST/OptFSST12, the existing small-block Zstd profile, and raw storage. Independently decoding a roughly 30-byte sequence could avoid the existing 4–256 KiB block-decode amplification. Compression effectiveness on ClamAV is unknown.

The largest remaining long-run name cost is an **ownership and residency problem**. Better compression does not reduce the bytes of names that must remain decoded behind escaped C pointers. An immutable, file-backed name arena could preserve those pointers while allowing physical pages to be reclaimed. Its memory and latency depend on the working set, including adversarial access; it offers no unconditional small memory bound.

These findings do not establish the quarter-memory target. After the four calculated reductions and adding known previously excluded costs, the partial model is **141.179 MiB with name blocks unexpanded, or 202.950 MiB with all name blocks expanded**, before additional engine costs. The latter already exceeds the **202.042 MiB** target. Neither figure is a SiteGround workload average or measured engine memory.

## Evidence and scope

The existing database snapshot is main 63, daily 28164 and bytecode 339, with 3,628,192 signatures. This investigation correlates the saved measurements with source and primary publications. It does not rebuild the scanner or integrate a new codec. The source tree and patch remain unchanged.

Evidence in the accompanying archive:

- `source/docs/profile-prototype-results/profile-summary.json`: component sizes and standalone access benchmarks.
- `source/docs/profile-prototype-results/token-preparation.json`: exact token interning and byte specialization.
- `source/docs/frontier-results/encoding-census.jsonl`: hash buckets, names, AC payloads and filters.
- `source/docs/correlation-results/correlation-summary.json`: prior name-codec and ownership experiments.
- `source/libclamav/matcher-hash.{c,h}` and `clamav.h`: bucket representation, comparison/selection and name-pointer API contracts.
- `remaining_memory_calculations.py` and `remaining-memory-calculations.json`: reproducible arithmetic and SHA-256 hashes of its inputs.

All sizes below are MiB (2^20 bytes). “Cold” means the prior model's compressed name blocks remain unexpanded; it does not imply zero OS page-cache residency. “Expanded” means all those blocks have materialized. There is no measured probability distribution from which to calculate an average WordPress working set.

## What remains large

| Contributor | Existing proposed compact payload | Significance |
|---|---:|---|
| Names plus hash-to-name IDs | 42.078 cold / 103.850 expanded | Largest variable retained component |
| Exact digest keys | 49.038 | Mostly high-entropy MD5 values |
| Token store, including index/cache/decoder | 22.219 minimum; 23.704 with 4 KiB blocks | Smaller blocks cost 1.486 more but reduce miss amplification |
| Pattern records and extension-pointer directory | 12.012 | Already extensively packed; extension contents are separate |
| Hash-bucket metadata | 11.645 | Present in older census; explicitly outside latest subtotal |
| Cyclic AC routes | 10.632 | Earlier route optimization already counted |
| Candidate links | 8.223 | Earlier exact column packing already counted |
| Node output/failure pairs | 2.953 | Earlier exact column packing already counted |
| Logical records and counted auxiliary data | 1.541 | Earlier template/expression sharing already counted |

This table is not a complete engine census. Other matchers, auxiliary indexes, allocator/pool retention, parser and archive buffers, worker state, build peaks and overlapping reload generations still require accounting. Subtracting this hypothetical compact budget from the historical engine RSS would not measure fragmentation: they describe different representations.

## 1. Compact static metadata before attempting deeper compression

### Bucket directories and exact IDs

The source allocates a `cli_sz_hash` containing two pointers and a count for each size bucket, plus an open-addressed hash-table entry and unused capacity. The census contains 244,986 size buckets across seven nonempty purpose/type groups, costing 12,211,056 bytes.

Flatten each group's digest and name-ID arrays into contiguous storage. Store a 32-bit file-size key and 32-bit starting record number per bucket, with one terminal offset per group. The next start supplies the end. The base directory becomes:

`8 × 244,986 + 4 × 7 = 1,959,916 bytes`.

This saves **9.776 MiB gross**. Small group/wildcard descriptors and any search accelerator remain extra. Preserve the original sorted contents within every bucket, including duplicate digest order and the binary-search midpoint behavior that selects a name. Merely preserving the set of matching names is insufficient for the acceptance criteria.

A sorted directory with binary search provides a simple bounded implementation. A checked minimal perfect hash is an alternative: PtrHash (SEA 2025) studies compact, fast static hashing [S3]. A perfect hash does not establish membership for an absent size; compare the stored full 32-bit size before using a bucket. PGM's bounded search prediction is another optional accelerator [S4]. Its predictions must only narrow an exact search. None of these methods justifies discarding a candidate.

The 3,213,522 hash-to-name references currently budgeted as 32-bit IDs need only 22 bits for 3,547,706 names, including room for a reserved value. This saves **3.831 MiB**. A simpler 24-bit layout saves **3.065 MiB**. Derive widths from the compiled database and retain a wide fallback; the snapshot's width is not a permanent signature limit.

### Monotone offsets: Elias–Fano

String start positions are monotone. Elias–Fano stores their small low parts and a unary-coded high-part sequence, instead of allocating a fixed-width integer for every position. A conservative payload bound is `n × (ceil(log2(U/n)) + 2)` bits for n positions in universe U, before select support. SEA 2025's Orzo work reinforces that rank/select support has its own measurable space/time tradeoff [S2]; its headline percentage is not a discount to apply to all ClamAV data.

| Structure | Old payload | Proposed base | Gross saving |
|---|---:|---:|---:|
| Hash-bucket metadata | 11.645 | 1.869 | 9.776 |
| Hash-to-name IDs | 12.259 | 8.428 | 3.831 |
| Name offsets | 6.767 | 2.960 | 3.806 |
| Token offsets and width flags | 4.069 | 1.017 | 3.052 |
| **Total reduction** | | | **20.465** |

For names, encode global logical starts; convert to a block-relative position by subtracting the first start in the existing 64-name block. Keep the existing block ownership and descriptors for this calculation. Thus compressed offsets do not require moving any returned string.

For tokens, use 1,066,577 offsets including the end marker, within 31,609,522 positions, plus one width bit for each of 1,066,576 sequences. This is compatible with the existing logical uncompressed stream and block decoder. The token reference is already in each packed pattern; do not add another per-pattern directory.

**Weak points:** select adds loads and arithmetic relative to one direct integer access; current compact-column probes already demonstrate that space savings can have substantial access penalties. Actual select indexes, boundary padding, alignment, and construction peaks must be measured. These calculated payload savings are independent of scan inputs on this snapshot, but performance is not. Releasing old builder arrays and their containing pool pages is necessary to convert payload reduction into RSS reduction.

## 2. Independently compressed tokens: the strongest new experiment

OnPair (2025 preprint) compresses individual strings using a shared dictionary and two-byte codes. OnPair16 limits each dictionary entry to 16 bytes; at 65,536 entries, dictionary data and 32-bit offsets require at most 1.25 MiB, excluding other runtime overhead [S1]. The Rust implementation reached 0.2.1 in September 2026 [S1b]. This is an experimental dependency, not a demonstrated scanner optimization.

Our deduplicated, byte-specialized sequences average **29.636 bytes**. The current compact prototype may decode **4,096–262,144 bytes** on a cache miss to retrieve one. My inference is that independent decoding addresses a better problem than marginally improving block compression: it removes unrelated reconstruction work.

The next comparison should train and encode the **unique sequence corpus**, preserving 16-bit token tags, prefix boundaries and all extension semantics. Compare OnPair16 against OptFSST/OptFSST12 (2026), raw byte-specialized sequences, and 4 KiB Zstd. OptFSST uses improved table construction and optimal parsing for a fixed symbol table [S5]. Our earlier name measurements already show OptFSST at 44.765 MiB versus front coding at 26.309 MiB under their respective directory models; novelty does not make it the smallest name representation. Binary token results remain unknown.

An actionable break-even calculation avoids borrowing another dataset's compression ratio. With N = 1,066,576 sequences and mean c two-byte codes per sequence:

`new bytes = dictionary + offset index + 2Nc + scratch + remaining overhead`.

To beat the existing **23,298,134-byte** token layout:

| Dictionary data/offset budget | Existing index: c must be below | Proposed succinct index: c must be below |
|---|---:|---:|
| 1 MiB | 8.427 | 9.927 |
| 1.25 MiB | 8.304 | 9.804 |

These thresholds allow 8,000 bytes of single-worker scratch from the snapshot's small-block probe, but exclude actual codec headers, padding and select support. Each additional worker and larger/custom token must be accounted for. The succinct-index estimate remains conservative when the compressed stream is shorter than the current logical stream. These are pass/fail thresholds, **not predicted ratios or savings**.

A further original experiment is to **fuse dictionary expansion with token verification**, stopping as soon as the original verifier can reject. This might avoid a full temporary decoded sequence and preserve cheap early mismatches. It is not equivalent to blindly searching encoded codes: wildcards, tags, rewinds and partial comparisons require exact handling. Start with a bounded scratch decoder; add fused decoding only where the verifier's access contract supports it, with exact fallback elsewhere.

**Adversarial tests:** many distinct candidate tokens, immediate mismatches, long common prefixes, maximum-length sequences, cache cycling, malformed indexes and concurrent workers. A 16-byte dictionary-entry cap does not bound total sequence decoding. Audit any unsafe decoder's input/output padding and dictionary-ID validation. Keep the raw configuration available; neither paper benchmarks nor microbenchmarks establish baseline scan throughput.

## 3. Names: reduce permanently resident materialization

The census contains **83.133 MiB** of unique NUL-terminated name bytes. `clamav.h` documents returned signature names as statically allocated, including the newer extended scan API. An ordinary evicting decoded-name heap cache can invalidate pointers still held by callers or evidence records. The existing monotone expansion scheme correctly retains decoded blocks, but its all-expanded name component reaches 91.591 MiB before hash-to-name IDs.

Two designs compete:

1. **Compressed names with monotone expansion.** Lowest compressed starting footprint; touched blocks become permanent for that engine generation. Improve IDs and offsets, but do not assume a later eviction is safe.
2. **Immutable raw name file with a stable read-only mapping.** Return pointers into a mapping held for the full required lifetime. The OS may reclaim physical file pages while virtual addresses remain valid [S12]. Use the succinct offset directory directly; the old per-block expansion descriptors disappear.

For the second design, the calculated fixed base for name offsets plus hash-name IDs is **11.388 MiB**, followed by **W**, the actual charged raw-name pages, plus select support, page tables and other overhead. If W happened to be 4 MiB, the base would be 15.388 MiB. That is a sensitivity example, not a WordPress prediction. W can approach the entire 83.133 MiB file; generating or verifying it can charge those pages before scanning starts. Linux cgroup accounting includes file cache [S13], so falling process RSS alone is not sufficient evidence of hosting-memory savings.

Read-only mapping alone does not prevent another writer from modifying or truncating the backing file. The compiler must publish and pin a verified immutable generation, protect it against later mutation, and retain it until all users release it. Updates need a new generation; never overwrite a live mapping. Filesystem verification/sealing capabilities must be established on the deployment rather than assumed. Storage faults and mapping failures must become errors, never clean verdicts.

Tune prefetch and residency without changing coverage: predict pages early, but retrieve any required missed page exactly. A fully resident configuration can remove page-fault latency at higher memory cost. Benchmark page cycling and cold storage as well as normal access. There is no guarantee that arbitrary name accesses can retain in-RAM latency while using only a small fraction of the name pages.

## 4. Exact digest keys: a real but smaller opportunity

Exactness does not require storing every digest as an independent fixed-width byte array. An ordered set can encode common prefixes or gaps and reconstruct every bit. A prefix directory plus exact suffixes is therefore a valid research direction. Short fingerprints or a filter's positive response alone are not acceptable replacements for exact membership.

The dominant 3,213,298 MD5 records occupy 49.031 MiB. For a **single set of distinct uniformly distributed 128-bit keys**, an ideal set encoding requires approximately:

`log2 choose(2^128, n) ≈ 128n − log2(n!)` bits.

This model gives an ideal saving of **7.727 MiB**, leaving about **41.304 MiB** before values and indexes. It is not a universal lower bound for this particular corpus. Separate size/purpose buckets reduce the sorting information that can be removed: roughly sum(log2(n_j!)) rather than log2(n!). Duplicate handling and cross-bucket associations also matter. Export the bucket occupancy and duplicate histograms before assigning a realistic gain.

Hu et al.'s STOC 2025 static-dictionary result demonstrates near-optimal exact membership with worst-case constant queries in its computational model, but its construction uses polynomial-time linear algebra [S6]. It is a useful theoretical direction, not a ready production component. Practical prefix-partitioned layouts with exact suffix verification and bounded fallback deserve the first test.

Preserve ClamAV's comparison and selection behavior. On little-endian targets `hm_cmp` compares its first 32-bit word in descending numerical order, then the remaining bytes lexicographically. A conventional bytewise reorder is not automatically equivalent. Preserve the original bucket sequence and duplicates; changing equal-key name selection could revive the reporting regression.

## 5. Other research: useful, but lower priority

| Research | Fit and decision |
|---|---|
| **Grammar random access, ICALP 2026** [S7] | Tunable space/access bounds with matching lower bounds in broad regimes. Consider bounded grammars for repetitive token data, but do not assume minimum grammar size and constant-time access come together. |
| **LZBE, CPM 2026** [S8] | Reference-based compression with efficient random access is a possible competitor if tokens retain substantial substring redundancy. More complicated dependencies than independent decoding; prototype only if it beats the simpler codec frontier. |
| **Bit-packed grammar engineering, SEA 2025** [S9] | Reinforces the need to measure grammar metadata and extraction cost, not just grammar size. |
| **C² succinct tries, 2026 preprint** [S10] | Cache-conscious unary-path compression is more plausible for longer string dictionaries than for ClamAV's short anchor trie. Its published dataset ratios cannot be applied to the already optimized cyclic route structure. |
| **In-place initializable arrays, TCS 2022** [S11] | Useful for zero-default worker state and reset costs. Constant-time initialization does not compress arbitrary fully populated payloads. Earlier demand-zero experiments are existing work, not a new saving here. |
| **Mesh, PLDI 2019** [S14] | Pointer-stable physical compaction targets fragmentation, not live payload. ClamAV has its own mapped pools; replacing malloc may miss the dominant allocations. Measure pool occupancy before considering allocator substitution. |

The new static-dictionary paper also discusses whether jointly encoding structures can reduce redundancy beyond separate encodings. This suggests examining bucket boundaries together with IDs and lengths, but does not prove that arbitrary ClamAV columns have exploitable correlation. A concrete experiment must compare the joint representation against the sum of already optimized components and charge all access indexes.

## Accounting correction and next experiments

The older partial budget omitted hash-bucket metadata. It must be added before subtracting that metadata's proposed reduction:

| Calculation | Cold names | All name blocks expanded |
|---|---:|---:|
| Prior partial subtotal | 148.697 | 210.468 |
| Add previously excluded bucket metadata | +11.645 | +11.645 |
| Four proposed gross reductions | −20.465 | −20.465 |
| Revised base subtotal | 139.877 | 201.649 |
| Add known extension contents and filters | +1.302 | +1.302 |
| **Still-incomplete subtotal** | **141.179** | **202.950** |

The 1.302 MiB is 840,432 bytes of extension contents and 524,320 bytes of filters, distinct from the extension-pointer directory already counted. Select/search indexes and other engine costs still remain. Do not add the mapped-name model on top of this table; it replaces a name-ownership design and needs its own complete accounting.

Recommended experimental order:

1. **Close the census:** live versus reserved pool bytes, bucket occupancy/duplicates, all matchers, worker contexts, build/reload peaks, RSS/PSS and cgroup file/anonymous memory. Reuse the exact pinned database and export no threat-name strings into public benchmark reports.
2. **Flatten directories and narrow IDs:** preserve every bucket's original result behavior. Compare binary search, checked static hashing and direct-width options. Measure both final storage and whether builder pages are actually released.
3. **Prototype independent token decoding:** apply the break-even thresholds above; benchmark early exit and hostile candidate traces. Publish a measured memory/time frontier, including raw and small-block configurations.
4. **Evaluate name residency separately:** contrast monotone compressed blocks with a verified immutable mapping under representative WordPress scans, all-name touches, memory pressure and reload overlap.
5. **Only then attempt digest-set or grammar compression:** their realistic marginal gain and engineering cost need the missing histograms and codec results.

Each accepted profile must preserve detections, severity, ordering, callbacks, stop/trust/error behavior and returned-name lifetimes. Require complete-scan differential tests, malformed-data and allocation/I/O-failure tests, and bounded behavior under attacker-controlled access. Retain a configuration meeting current performance, and report its own memory figure; never pair a compact profile's space with a raw profile's speed. No new whole-engine performance or quarter-memory qualification is claimed here.

## Primary sources

- **S1.** Gargiulo and Venturini, *OnPair: Short Strings Compression for Fast Random Access*, 2025 preprint. [Full text](https://arxiv.org/html/2508.02280v1).
- **S1b.** OnPair Rust implementation, version 0.2.1, September 2026. [Implementation documentation](https://docs.rs/crate/onpair/0.2.1).
- **S2.** Hough and Bhatele, *Elias-Fano Compression for Space-Efficient Rank and Select Structures*, SEA 2025. [DOI/full text](https://doi.org/10.4230/LIPIcs.SEA.2025.23).
- **S3.** *PtrHash: Minimal Perfect Hashing at RAM Throughput*, SEA 2025. [DOI/full text](https://doi.org/10.4230/LIPIcs.SEA.2025.21).
- **S4.** Ferragina and Vinciguerra, *The PGM-index: a fully-dynamic compressed learned index with provable worst-case bounds*, PVLDB 2020. [Paper](https://www.vldb.org/pvldb/vol13/p1162-ferragina.pdf).
- **S5.** Chehaidar et al., *OptFSST: Optimized FSST String Compression*, 2026, revised August 26. [Full text](https://arxiv.org/html/2607.11271v3).
- **S6.** Hu et al., *Optimal Static Dictionary with Worst-Case Constant Query Time*, STOC 2025. [Full text](https://arxiv.org/html/2412.10655v2).
- **S7.** Duyster and Kociumaka, *Random Access in Grammar-Compressed Strings*, ICALP 2026. [DOI/full text](https://doi.org/10.4230/LIPIcs.ICALP.2026.86).
- **S8.** Shibata et al., *LZBE: An LZ-Style Compressor Supporting O(log n)-Time Random Access*, CPM 2026. [Paper record](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CPM.2026.34).
- **S9.** Cleary et al., *Bit Packed Encodings for Grammar-Compressed Strings Supporting Fast Random Access*, SEA 2025. [Paper record](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SEA.2025.12).
- **S10.** Zhang, Zhao and Xu, *C²: Cache-Conscious Succinct Tries with Adaptive Unary Path Compression*, June 2026 preprint. [Paper record](https://arxiv.org/abs/2606.16104).
- **S11.** Katoh and Goto, *In-Place Initializable Arrays*, TCS 2022. [Author manuscript](https://arxiv.org/abs/1709.08900); [journal DOI](https://doi.org/10.1016/j.tcs.2022.03.004).
- **S12.** Linux `mmap(2)` documentation. [Manual](https://man7.org/linux/man-pages/man2/mmap.2.html).
- **S13.** Linux kernel, cgroup v2 memory accounting. [Documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
- **S14.** Powers et al., *Mesh: Compacting Memory Management for C/C++ Applications*, PLDI 2019. [Author manuscript](https://arxiv.org/abs/1902.04738).
