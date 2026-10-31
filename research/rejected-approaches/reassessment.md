# Reconsidering rejected compression and memory approaches

28 October 2026 UTC. Reviewed against saved project version 9, source commit `282052bd1577d918a2a5de135f47567d8d78830f`.

Several earlier rejections apply to one algorithm, ownership policy, or point in the build process—not to the entire family of approaches. The strongest new nearby candidate is **reclaiming physical pages inside existing free pool fragments without moving objects**. An isolated probe against the saved allocator passed. The next important architectural candidate is **compaction after the legacy candidate order has been established**, with a separate requirement to demonstrate physical memory release.

This report enumerates both rejected and deferred approaches, and distinguishes them. “Prototype passes” below means only the stated experiment passed. It does not mean scanner integration, performance qualification, or the whole-engine memory target passed. This review adds a reproducible research probe and report; it does not enable the rejected scanner changes.

## Constraints used in this reassessment

Preserve exact membership, detection severity, selected names, ordered callbacks, multiplicity, stop/trust/error behavior, and caller-visible string lifetime. Preserve at least one performance-oriented configuration; an explicitly selected compact configuration can trade time for memory. Count resident memory, per-scan state, construction/reload overlap, and charged backing-store pages. Prefer removing or replacing machinery over adding caches, allocators, or codecs.

The original 200 decimal MB goal and later quarter-memory target of 202.042 MiB are different thresholds. Neither has been demonstrated. Component payload savings from different experiments must not be added as if they were independent whole-engine RSS savings.

## Rejection register and nearby alternatives

| ID | Rejected or deferred approach | Actual obstacle | Related variant and present verdict |
|---|---|---|---|
| R01 | Sorted size directory instead of the original hash directory | Random successful lookup rose from 44.1 to 415.4 ns in the recorded probe. Min/max rejection helps distant misses, not these hits. | **Already successful opt-in alternative:** retain the original hash algorithm, capacity and probing, but store integer indexes into flat bucket arrays and direct name offsets. Recorded lookup was 37.0 ns; scanner RSS fell about 49 MiB. Construction peak rose about 104 MiB, so the option remains off by default. |
| R02 | Copy into compact arrays and individually free the old pool objects | `mpool_free` retains fragments in a free list; the old physical pages can remain resident alongside the new representation. | **Already successful for hash builders:** give construction data disposable ownership and destroy the entire builder pool. **New, narrower alternative:** purge whole interior pages of already-free fragments without changing allocation addresses. Mechanism passed this review's probe; actual database opportunity is unmeasured. |
| R03 | Put AC construction nodes in a separate disposable pool before building | Altering shared-pool allocation changes address-based tie breaking, duplicate order and selected names. | **Plausible:** establish legacy candidate order first, then translate existing links into ordered IDs and compact. Release pages separately. Merely changing allocation order or replacing address ties with insertion IDs does not preserve the old observable order. |
| R04 | Share logical descriptors and expressions during loading | The experimental 168-to-40-byte rule layout saved 51.693 MiB RSS but failed the duplicate-alert ordering gate. Interner keys and tables also remain resident; all-distinct data can expand. | **Plausible:** canonicalize immutable descriptors after ordering, keep every rule identity and ordered reference, use full equality, then discard temporary interner keys. An adjacent-run variant needs less indexing but offers less sharing. Neither automatically returns mixed-pool pages. |
| R05 | Move four AC length bounds into existing extension records during parsing | Native payload fell 11.373 MiB and measured RSS fell 5.754 MiB, but both first selected duplicate name and all-match order changed. | **Plausible:** perform the same representation change after ordering. All constructors and existing zero-bound exceptions must remain exact. Keeping the old allocation footprint during loading can preserve allocation behavior, but offers no record saving until a later stage actually releases storage. |
| R06 | Global whole-name interning, or a new pointer table just to narrow references | Only 0.427 MiB of full-name text is duplicate in this corpus; a new interner/directory can cost more. | **Different redundancy works:** direct arena offsets already replace pointers in the flat hash store. Prefix/substring compression can exploit similarity among distinct names. Whole-name interning remains unjustified for this corpus; a repetition-heavy corpus could change the decision. |
| R07 | Bucket-relative 24-bit offsets and constant-NULL name columns | Extra bucket bases/lookup conventions offer at most 2.547 MiB gross savings here. No nonempty all-NULL group in this census can eliminate a name column. These were deferred, not disproven. | **Conditional:** use an existing descriptor's narrow/zero-width mode only where a measured group benefits, with exact overflow/raw fallbacks. Current expected gain is too small to lead the work. |
| R08 | An evicting cache of decoded names | Public C strings and retained Rust evidence can outlive the cache entry. Keeping every compressed and decoded copy forever also wastes memory. | **Prototype passes:** monotone block conversion—compressed block becomes permanent raw storage; publish stable pointers, then retire that block's compressed bytes. A 64-name-block model used 29.820 MiB cold and 91.591 MiB fully expanded, including directory, versus 83.133 MiB unique raw text. Native concurrency/publication/error handling is not integrated. Cold savings are not a worst-case bound. |
| R09 | Mapping raw strings or cold data and treating their bytes as free | Stable virtual addresses do not imply zero physical or cgroup cost. Page cache and fault latency remain. | **Valid conditional profile:** map immutable backing storage, count charged cache, and accept qualified I/O behavior. Useful for cold working sets; not proof of a hard memory ceiling or unchanged latency. |
| R10 | Universal replacement of dense AC routing with cyclic compressed rows | 75.164 MiB of rows became 10.631 MiB, with exact transition checks, but all-zero and cycling inputs took 3.529× and 3.344× as long. | **Reclassified:** eligible for an optional compact profile, still unqualified in the scanner. **Plausible performance-oriented variant:** static choice of dense rows and shared 16-entry microblocks, without an eviction cache. The microblock prototype used 19.078 MiB and reconstructed exact rows; lookup timing remains unmeasured. |
| R11 | General succinct/grammar automata or a double-array paper's byte/state estimate as a drop-in engine replacement | Published models omit ClamAV's full outputs, associations, allocation holes, verifier state and integration costs. Dynamic succinct schemes add randomization, tables or rebuilding. | **Plausible restricted variants:** bounded-history short-window routing with exact fallback, smaller rank directories, or a static double-array implementation. Existing short-window/dense payload was 21.282 MiB under its applicability condition. These are separate designs requiring exact trace and adverse-input tests. |
| R12 | A very large compressed token block with a small decoded-block cache | An isolated size minimum of 22.219 MiB relies on block/cache choices that expose miss latency and cache thrashing. | **Prototype passes:** independent per-sequence dictionary decoding, retaining the existing width flag in code offsets. The measured layout is 25.422 MiB with 8,016 bytes scratch per active decoder. This removes eviction state but retains dictionary/decoder validation work. It is not yet a scanner implementation. |
| R13 | Generic token RLE or bit-packing smaller dictionaries | Mostly short runs limit RLE. The 12-bit dictionary expanded specialized input; ideal 12/14-bit packing still failed to beat the larger dictionary once the actual dictionaries were counted. | **Still reject as the default for this corpus.** A bounded per-block choice with raw fallback could help a different distribution. Byte-token specialization is a distinct opportunity, but its second verifier representation was deferred for complexity, not disproven. |
| R14 | Directly link the research OnPair codec implementation into the scanner | The recorded research dependency differs from the engine's toolchain and needs licensing/integration review. This is an implementation/dependency obstacle, not an information-theoretic one. | **Conditional:** use a compatible implementation after review, or an already supported independent codec if it wins the same byte/time tests. Changing the dependency alone does not establish a smaller or simpler engine. No licensing conclusion is made here. |
| R15 | Replace exact digest membership with an MPH, fingerprint or probabilistic filter alone | A placement index is not membership evidence; collisions or absent keys can change exact results. Exact digest payload is 49.038 MiB in the census. | **Plausible:** lossless static-set encoding that stores enough quotient/remainder information to recover exact membership, or an MPH with exact verification. A negative filter before an authoritative store is also exact but adds a structure and can be forced into positive-path work. None supports a 100-fold digest saving. |
| R16 | Predict which rules will matter and omit or never load the rest | An attacker can select the input; false negatives violate the task. | **Conditional exact variant:** a conservative prefilter or applicability partition may avoid work only when it proves rejection. Keep an authoritative backing store and exact fallbacks for generic/nested types. False positives cost work rather than detections; adversarial lookup/I/O still needs a bound. |
| R17 | Reach the memory target merely by reducing a cold-data cache | The earlier resident boundary already cost 223.94 MiB for routing, stable names and logical headers, before the cache and other state. | **Reopen the boundary:** compact the hot core first, then select bounded cold storage. Paging is not disproven; that particular resident/cold split cannot meet the target. |
| R18 | Keep only the latest evidence item, or deduplicate output as an unordered set | Removing the top item can reveal an older item; callbacks, order, severity, multiplicity and context are observable. | **Prototype passes for evidence:** ordered run encoding of identical pointer/depth/object-ID triples preserves push/pop/merge. A literal/run hybrid can avoid pure RLE's 32-byte versus 24-byte all-distinct expansion. **Plausible for candidate lists:** share only byte-for-byte identical ordered tails after order is frozen. Emitting z observable callbacks still costs Ω(z). |
| R19 | Replace all logical scan-state arrays with sparse hash maps | An additional mutable index, reset logic and worst-case dense occupancy complicate the runtime; this was not a measured impossibility result. | **Prototype passes for sparse page residency:** encode each 32-bit offset as `x XOR CLI_OFF_NONE`, making unset entries zero. Untouched anonymous zero pages can remain cheap; all-written arrays have essentially the same physical cost. All direct, bytecode and YARA accesses plus context reuse must be adapted before integration. |
| R20 | Count a compact final image as if construction and reload overlap disappear | The retained flat-hash build increases peak memory; old/new engines can coexist during reload. An off-process compiler in the same cgroup still consumes charged memory. | **Plausible:** counted/two-pass construction, lifetime-separated builder regions, or immutable chunks with stable local IDs shared across generations. Sharing helps only unchanged chunks and cannot certify an all-changed update. Destroying the old engine first changes availability and is not a transparent replacement. |
| R21 | Runtime relocation, a general entropy array framework, or a new adaptive cache as an automatic complexity reduction | Handles, synchronization, relocation and recovery create more mechanisms; a lower payload alone does not meet the complexity requirement. | **Plausible narrower borrowing:** static allocation by role/lifetime, existing codec modes, and immutable local indexes. Dynamic object motion remains deferred; address-preserving reclamation is materially different. |
| R22 | Treat every >100× field ratio as a major architectural opportunity, or omit fields that happen to be zero in one database | Huge relative ratios may represent tiny absolute bytes; dataset defaults are not universal invariants. | **Small valid cleanup:** detect a global constant in the existing scalar codec, with raw/exception fallback. `rtype` can fall from 17,676 to 18 serialized bytes here. Conditional expression-reference modeling offers only 59,963 gross bytes before tables. Neither merits a separate subsystem. |

These groups cover the rejected/deferred families in the retained lead log and reports. Retained correctness fixes, already-successful flags/index simplifications, and the separately recorded absolute-zero prefix bug are not “rejected compression approaches.” Hardware/remote-execution changes would alter the deployment contract rather than answer this storage-design question.

## New experiment: physical reclamation without address changes

The saved `libclamav/mpool.c` uses anonymous private mappings. A freed fragment retains a next-pointer at its start and a size class from its free-list bucket. `mpool_flush` currently releases only unused mapping tails. It leaves interior freed fragments resident. In `readdb.c`, the existing engine-compilation flush follows AC construction and precedes bytecode preparation.

For a free fragment with base `b`, extent `s`, page size `P` and free-list metadata size `h`, the proposed candidate range is:

```
start = ceil((b + h) / P) * P
end   = floor((b + s) / P) * P
purge [start, end) only when end > start
```

This retains the fragment's free-list metadata and every partial boundary page. It never purges a page partly owned by a live object. On Linux, `MADV_DONTNEED` releases backing pages of anonymous private mappings; subsequent accesses receive zero-filled pages while the virtual mapping remains. The payload of a freed allocation is already invalid to clients, so this is a different ownership situation from evicting a live returned name [W1].

The probe copies the project's **unmodified allocator source and header** into a temporary build, supplies minimal dependency headers, and adds the purge routine in the harness. The unused string conversion functions are removed by linker section garbage collection. Logging is stubbed. This exercises the real pool allocator but not the rest of ClamAV.

| Check | Result |
|---|---|
| Native runs | Three separate processes, all passed |
| Free fragments at purge | 102: 64 small, 32 large, six irregular-size fragments |
| Successful advice calls | 36 per measured purge; zero failures |
| Physical range advised | 33,562,624 bytes = 32.0078125 MiB |
| Native RSS decrease after the existing tail flush | 32,776 KiB in each run |
| Small-fragment-only control | Zero advice calls |
| Integrity and allocation behavior | Live guards unchanged; every free-list node, next-link and bucket unchanged; repeated purge passed; 32 large blocks reused the same addresses in the same pop order; malloc writes and calloc zeroing passed |
| Sanitizers | AddressSanitizer and UndefinedBehaviorSanitizer run passed with leak detection disabled |

LeakSanitizer's default process/thread enumeration failed in this execution environment. It was disabled explicitly for the repeat; no leak-check success is claimed. ASan does not automatically understand individual allocations inside this custom pool, so explicit payload/metadata assertions remain important.

The test deliberately creates about 32 MiB of free large fragments. **It does not measure 32 MiB of recoverable space in the actual engine.** It does not prove callback equivalence, scanner performance, failure behavior under memory pressure, or cross-platform support. Native RSS is the measurement here, not cgroup memory.

Recommended next qualification: first census the eligible interior pages at the existing flush point on the real database. If the value is material, add a guarded, best-effort purge at that existing phase. Advice failure should leave correct allocated storage and simply forgo savings. Then run exact ordered-result fixtures, normal corpus tests, post-flush allocations, load/reload peaks and timing. Do not infer that this reclaims sub-page gaps, dead fields inside live records, or the memory of small freed objects; those need different ownership arrangements. Avoid an additional bitmap or allocator rewrite until the simple census justifies it.

Reproduction from an extracted archive:

```sh
python3 research/rejected-approaches/probe_free_pages.py source
ASAN_OPTIONS=detect_leaks=0 python3 research/rejected-approaches/probe_free_pages.py source --sanitize
```

Results are preserved in `free-pages-native.json` and `free-pages-sanitized.json`. The measured source hash is recorded in both.

## Which earlier rejection should change?

**Already reversed by prior work:** sorted-directory rejection led to the indexed-hash layout; token width metadata moved into an existing offset bit; a disposable hash-builder pool fixed retained-copy ownership. These are existing results, not new discoveries from this review.

**Reclassify as eligible:** cyclic AC routing is unsuitable for the performance-preserving profile but remains eligible for a selectable compact profile. Its known repetitive-input slowdown must remain visible. Requiring every profile to match baseline speed would contradict the clarified time/memory tradeoff.

**Reopen with a different mechanism:** address-preserving free-page purging; post-order descriptor/bounds compaction; monotone name-block conversion; independently decoded token sequences; static dense/microblock routing; zero-default scan state; ordered-tail/output and run/evidence sharing. Only the explicitly named standalone mechanisms have passed prototypes.

**Keep rejected under the current contract:** approximate membership without exact verification, missing rules, eviction of caller-retained strings, unordered output deduplication, and latest-only evidence. Their exact variants work by restoring the very information or lifetime those versions discarded.

**Keep deferred for payoff or complexity:** global whole-name interning on this corpus, extra narrow-offset conventions, small-dictionary packing, all-NULL columns without qualifying groups, runtime relocation, and a new framework for tiny constant columns.

## Priority and falsification tests

1. **Census address-preserving page reclamation.** It uses existing free lists, changes no live object layout, and has the smallest new mechanism. Stop if real eligible resident pages are negligible or flush/reuse cost outweighs them. This is an allocator-memory opportunity, not an entropy-compression claim.
2. **Preserve order first, then compact descriptors and bounds.** These address the remaining large >100× representation gaps. First test ordered graph translation and exact pointer escapes, then demonstrate that old storage really releases pages. A design that retains the full builder indefinitely fails the memory goal; rebuilding all order with new insertion IDs fails the behavior goal.
3. **Qualify one compact routing/token profile.** Use existing prototypes to reduce uncertainty instead of introducing multiple new decoders. Independently decoded tokens avoid cache thrashing state; static routing variants avoid an additional dynamic cache. Measure worst-case candidate and repetitive traces as well as ordinary throughput.
4. **Treat monotone names and zero-default state as workload-dependent savings.** Include fully expanded names, every scan-state page touched, concurrent decoders and reader lifetime in the bound.
5. **Only then tackle exact digest-set encoding and cross-generation sharing.** Both may save memory, but require association/update distributions and can add enough metadata or construction work to erase the gain.

The existing >100× audit needs the same distinction between the native engine and the best prototype. Corrected logical descriptors occupy 44.098 MiB natively versus a 0.235 MiB serialized witness including associations/escapes (about 188×). The four conditional length columns have a 1,876-byte witness versus 3,193,168 bytes in the existing block codec (about 1,702×). Those remain important integration problems. Dense routing's 75.164 MiB is about 120× a 0.6256 MiB leading trie counting term, but the 10.631 MiB prototype is already about 17× that term. That counting term omits scanner outputs and is not an attainable whole-engine optimum.

An exact uniform-set calculation also narrows the digest claim: approximately `n * (128 - log2(n) + log2(e))` bits encode a distinct set of n 128-bit values in the sparse-universe model. For 3.214 million values, the ideal reduction from raw keys is about 7.7 MiB, before partitions, duplicates, name/value associations and access indexes. The real database uses several digest widths and partitions. This is a reason to investigate exact set encoding cautiously, not a measured 7.7 MiB engine saving or an argument to remove verification.

## Evidence and primary research

Recorded project evidence:

- [Lead log L01–L44](../../source/docs/complexity-shift-leads.md): R01–R07, R12–R14, R20–R22 and accounting corrections.
- [Flat-hash and independent-token experiments](../../source/docs/complexity-shift-implementation.md): R01, R02, R06, R12–R14.
- [Logical sharing experiment](../../source/docs/logical-sharing-implementation.md): R04, exact ordering failure and corrected logical counts.
- [Length-bound experiment](../../source/docs/length-bounds-implementation.md): R05, constructor exceptions, exact outcomes and RSS.
- [Correlated optimization report](../../source/docs/correlated-optimization-opportunities.md): R08–R11, R15, R18–R20; names, routing, zero pages and digest-set calculation.
- [Tunable profile prototypes](../../source/docs/tunable-profile-prototypes.md): exact names/evidence/token models and budgets.
- [Demand-engine implementation and resident floor](../../source/docs/demand-engine-implementation.md): R03, R16–R17 and reload accounting.
- [Algorithm inventory](../../source/docs/memory-algorithm-inventory.md) and [entropy-gap audit](../../source/docs/entropy-gap-audit.md): component sizes, bounds and distinctions between native and prototype layouts.

Primary sources checked during this review:

- **W1:** [Linux man-pages: madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html). Documents page alignment, private-anonymous zero-fill semantics and RSS behavior. Supports the new purge mechanism's operating-system premise; does not certify our allocator integration.
- **W2:** [Linux kernel: Control Group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html). Both anonymous memory and page cache are charged categories. Supports rejecting “mmap makes the bytes free” accounting.
- **W3:** [Kanda, Akabe and Oda, Engineering faster double-array Aho–Corasick automata](https://arxiv.org/html/2207.13870v3), [version of record](https://doi.org/10.1002/spe.3190). Shared/forest output representations exploit overlap but trade locality and parent-index cost. Its outputs are sets; adapting the idea to ordered ClamAV effects is our proposed restriction, not a guarantee from the paper.
- **W4:** [Boncz, Neumann and Leis, FSST: Fast random access string compression](https://ir.cwi.nl/pub/32922). A static symbol table permits independent access to compressed strings. This supports the distinction between independent decoding and a large block cache; stable public-pointer ownership remains an application-specific problem.

No paper's performance result is treated as a ClamAV benchmark. All numerical scanner results above are historical saved experiments; only the free-page mechanism probe was newly executed for this review.
