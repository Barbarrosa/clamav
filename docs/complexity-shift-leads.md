# Complexity-shift implementation lead log

Entries are recorded when identified, then revisited with evidence. Dates use the user's 27 October 2026 work session. No entry is a measured saving unless explicitly labeled.

## L01 — Name-ID prerequisite is not integrated (discovered during initial source read)

The running hash matcher still stores `const char **virusnames`; the earlier 22/24-bit IDs were a proposed component layout. Adding a global pointer table solely to narrow these references could increase memory. Investigate a flat name arena with direct offsets, replacing individual string ownership, before adding any interning subsystem. Audit compile-time pointer escape and null-name semantics. Classification: uncertain until ownership is verified.

## L02 — Bucket flattening can remove object ownership work (initial source read)

Builder buckets are individually allocated and carry their own digest/name arrays. A compiled immutable flat directory can replace these objects. Keep sorting and duplicate-name selection identical; compile transactionally and propagate allocation failure. Measure whether the existing memory pool actually releases freed pages. Classification: likely shift/reduction; initial implementation priority.

## L03 — Existing hash comparator has alignment undefined behavior (source read)

`hm_cmp` casts arbitrary byte pointers to uint32_t pointers. Replace with memcpy loads preserving the exact comparison order; compilers can lower these to unaligned loads. This shifts alignment responsibility to the compiler and removes a sanitizer blocker without changing the algorithm. Validate aligned and unaligned inputs. Classification: likely simplification; include.

## L04 — Independent token decoding must replace cache machinery (planning)

Experiment with shared-dictionary independent sequences against the existing block cache only after the first phase. Charge decoder/dictionary/index/scratch bytes and identify code/state actually removed. Do not integrate a second codec into the scanner merely because a standalone probe exists. Classification: uncertain; experimental.

## L05 — Bounded sorted search may cost more than existing size hashing (source read)

Do not assume flatter directories are faster. Compare the original hash lookup with plain binary search on successful, absent, sequential and repeated sizes. If necessary investigate reusing the existing size hash with integer bucket indices: it could remove per-bucket objects while retaining its original lookup algorithm. Classification: likely complexity shift, but smaller savings.

## L06 — Direct offsets can replace name pointers without a global interner (ownership audit)

Hash names are independently owned copies created after the signature-load callback. Public database loading rejects compiled engines. A name arena built during compilation can replace the individual allocations and pointer arrays; scan-time pointers remain stable thereafter. Null names from trusted catalogs require a distinct zero sentinel. Select 3/4/size_t-byte offsets from the arena length, not a hard signature-count limit. Revisit with pointer-lifetime and null-name tests. This changes the earlier ID-budget assumptions and must be accounted against the actual source, not subtracted again from the hypothetical global-interner subtotal.

## L07 — Native-width bucket starts simplify large-database handling (implementation)

Using size_t starts rather than 32-bit starts costs roughly 0.935 MiB for this census on LP64 but avoids an additional format/fallback for databases with more than 2^32 total records. Prioritize simpler invariants; measure this concrete layout. Width-compressing these starts is a separate experiment, not an automatic inclusion.

## L08 — Construction peak and pool fragmentation can erase payload savings (implementation)

Transactional compilation briefly holds old and new arrays. Pool holes from individually freed names/buckets may remain resident. Consider a dedicated hash-builder pool only if instrumentation shows material retained pages; this would shift ownership to one build lifetime but complicates shared-name allocation unless assigned at creation. Do not claim reclaimed RSS from free() calls alone.

Reconsideration: `mpool_free()` only links a fragment into a free list; it does not release its mapping. This is direct evidence that merely copying into flat heap arrays can increase resident memory. Explore a dedicated hash-builder pool, reusing the existing AC disposable-build ownership pattern. Copy accepted hash names into that pool while releasing the temporary loader name back to the engine pool; destroy the complete builder pool after successful compilation. Failure keeps the pool owned and cleanup-safe. This is a required ownership correction, not an optional allocator substitution.

## L09 — Codec implementation requirements differ from the paper (dependency inspection)

The published OnPair Rust crate 0.2.1 requires Rust 1.91 and is Apache-2.0, while this engine is built with Rust 1.90 and includes GPL-2.0-only source. Keep the codec experiment a separate executable with pinned dependency metadata; do not add it to scanner linkage or redistribute its source in this fork. Investigate implementation complexity and integration/license requirements before adoption. This is not evidence about compression effectiveness.

## L10 — Do not equate runtime simplification with fewer implementation obligations (implementation review)

Flat compilation removes runtime bucket objects, but needs allocation rollback, a builder/compiled state distinction and retained legacy configuration for performance comparison. Record these additions in the final complexity assessment. The safest classification is a shift of runtime ownership into the existing compilation stage, not a claim that total source lines decrease. Experimental options remain off until their performance and correctness gates are met.

## L11 — Bucket-relative name offsets (during arena review)

An additional name-base offset per bucket might let more references use 24 bits. It also adds a directory and changes every name lookup. Large wildcard buckets may defeat it entirely. Revisit bucket-size/name-byte histograms; do not implement without a material net saving after the directory and a simple uniform access rule.

## L12 — Constant-null name columns (during arena review)

Groups containing only trusted hashes with NULL names could omit their name-offset array. This can use the existing width descriptor's zero-width case, but adds a runtime special case. Earlier official-corpus counts show no large all-null group, so expected current saving is small. Reconsider after the new census; leave out unless a material case is demonstrated.

## L13 — Hash-name interning has little corpus evidence (during arena review)

The previous census's total names versus globally unique name bytes differ by less than one MiB. A new interner and pointer directory would likely cost more than deduplicating those bytes saves. This reinforces choosing direct offsets. Revisit only if a different corpus has substantially more name repetition.

## L14 — Allocate accepted hash names directly in the builder pool (after ownership fix)

Current compatibility path transfers a loader-owned name by copying it into the disposable pool, then returns the original allocation to the engine pool. Moving name normalization/allocation into the hash builder could remove roughly one temporary allocation/copy per named record. It changes internal ownership across the database and OpenIOC loaders, so first measure load time and retained engine-pool bytes. Likely benefit is construction time and temporary allocation traffic, not a second large resident saving; avoid mixing it into the initial equivalence comparison.

## L15 — Independent codec needs a width bitmap (experiment preparation)

The existing raw token index hides byte-versus-16-bit token width in an offset bit. Replacing it with a codec's code offsets loses that information. Charge and verify a separate 133,322-byte width bitmap for this corpus; any claimed saving that omits it is incorrect. Keep independent decoding as a standalone replacement experiment, not another scan-time cache tier.

## L16 — Large token scratch is per active decoder (experiment preparation)

Independent decoding removes shared block-cache eviction state but still needs bounded scratch per concurrent verifier. Measure maximum decoded row length and charge padding. A high-concurrency deployment must multiply scratch, whereas dictionary and codes can remain immutable/shared. Repeated longest-row queries provide an adverse time trace; they do not establish adversarial whole-scanner throughput.

## L17 — Range rejection before size binary search (static review during baseline run)

For sizes below the minimum or above the maximum, the sorted directory can reject with one or two comparisons instead of logarithmic search. This relocates the existing exact equality/range check and adds no auxiliary index. It could substantially improve far-out absent sizes but costs extra branches for hits. Measure the existing adverse trace first; do not assume it fixes randomly distributed misses or replace baseline hashing without evidence.

### L05 reconsideration — first full-database measurement

The sorted directory matches all 9,640,566 result queries, but median random successful size lookup is 415 ns versus 44 ns for the original hash table (single run, eight within-run repeats). Sequential and hot traces also regress; far-out misses improve. This is substantial evidence to exercise L05: replace the sorted size-key array with the existing hash directory containing integer bucket indices. Retain the same hash algorithm/capacity, remove per-bucket objects, and avoid shipping two new indexing algorithms. Keep the sorted prototype's results as a rejected experiment.

### L14 reconsideration — first full-database measurement

Loading rises from 9.00 to 15.01 seconds, while compilation rises from 2.30 to 3.99 seconds. These are single-run observations, not confidence intervals. Copying millions of temporary engine-pool names adds allocation/free traffic; inspect a single ownership-taking hash-loader API that normalizes/allocates names directly in the hash builder. Preserve error and callback behavior and test independently. Do not trade a clear startup regression for unmeasured runtime simplicity.

## L18 — Destroy the builder pool without individual fragment frees (ownership review)

Once all hash-builder allocations belong to a disposable pool, walking millions of names to free each fragment before destroying that same pool is redundant. A single pool destruction plus clearing the builder descriptors replaces that walk. This directly reduces cleanup complexity and work, including compile time. Apply it only when the dedicated builder pool exists; retain ordinary cleanup for legacy/shared-pool and no-pool builds.

## L19 — Shared-pool address changes can affect older AC tie-breaking (validation review)

Moving hash allocations out of the engine pool changes subsequent allocation addresses even though the hash lookup itself is exact. Run the existing duplicate-alert-order differential and mixed weak/PUA-versus-strong regression probes again, as well as whole-corpus ordered callbacks. Do not enable the separate AC disposable-build option, whose known ordering caveat is unrelated to this hash change.

## L20 — Construction peak needs lifetime separation, not just compact arrays (measured)

The indexed variant records approximately 49 MiB less compiled RSS, but approximately 104 MiB more construction peak than the baseline. Allocation-before-commit retains old and new representations. Separating name and digest builder pools could release one lifetime before touching the next destination, or a direct final-layout builder could avoid the duplicate. Both add ownership transitions and require a fresh failure/retry proof. This is a plausible subsequent experiment, not a free memory saving; keep the legacy profile available and do not count the resident reduction as a peak reduction.

## L21 — Reuse the existing token-width bit in code offsets (codec accounting review)

The L15 bitmap is avoidable if the codec uses the same index convention as the existing specialized-token layout. Each nonempty code emits at least one byte, so code count is at most raw payload length. That layout already requires payload < 2^31 bytes. Therefore the high bit remains available in every 32-bit code offset: retain the original width flag there, mask it when taking a code slice, and eliminate the parallel width bitmap entirely. This shifts existing index semantics rather than adding another format constraint. First measure the library-compatible bitmap version, then exercise and verify the flagged-offset adapter as a follow-up if the codec is otherwise competitive. Expected saving is exactly 133,322 bytes plus one vector header for this corpus, not a major engine-RSS reduction.

### L19 additional validation

The old ordering fixture contains only AC rules. Extend it with optional harmless hash distractors so the differential can exercise hash-pool allocation changes alongside AC ties. Keep exact first-alert and ordered all-match comparison; a multiset-only match would be insufficient.

### L04/L21 reconsideration — first codec results

All 1,066,576 sequences round-trip for dictionary budgets 12/14/16. The 16-bit budget occupies 25.549 MiB, versus 34.214 MiB for the specialized raw store and 22.219 MiB for the prior smallest block store. Random row reconstruction is roughly 92 ns in this probe; repeated 8,000-byte rows take roughly 6 microseconds. The 12-bit budget actually expands the specialized input. Independent decoding is therefore a plausible intermediate time/memory profile, not the minimum-memory answer. Exercise L21's flagged-index adapter on the 16-bit profile to remove the unnecessary bitmap and validate its exactness.

## L22 — Bit-pack small-dictionary codes only if they beat the larger dictionary (results review)

The implementation emits fixed 16-bit codes even at 12/14-bit dictionary budgets. Packing 12-bit codes would save 8,118,300 bytes, but its resulting layout is still about 27.46 MiB; packing 14-bit codes saves about 3,187,686 bytes and leaves about 25.60 MiB. Both remain larger than the already measured 16-bit dictionary layout (25.55 MiB), before charging unpacking work or indices. This arithmetic rejects a new bit-unpacking path for this corpus; do not implement complexity that is already dominated.

## Final reconsideration register

| Lead | Decision and evidence |
|---|---|
| L01, L06 | Use direct offsets into a stable raw-name arena; no global name-ID table. Full hash and corpus comparisons preserve names and callbacks. |
| L02 | Implemented flat record/name ownership as an opt-in prototype. Retaining the existing size-hash algorithm trades some metadata savings for baseline lookup behavior. Total compiler/testing obligations increase, so this is not certified as an overall complexity reduction. |
| L03 | Retained alignment-safe memcpy loads; same comparison order, sanitizer-covered unaligned inputs. |
| L04 | Independent decoding is a plausible intermediate profile. It removes cache state but adds dictionary training/validation; leave outside the scanner. |
| L05, L17 | Reject sorted-directory production path after random successful lookups regressed roughly 9x. Range rejection cannot repair successful lookups. Reuse the existing hash directory with index values instead. |
| L07 | Retain native-width starts; avoid another overflow fallback format. |
| L08, L18 | Implement disposable builder ownership and one pool destruction. Measured resident reduction confirms pages are released; redundant per-fragment cleanup removed. |
| L09 | Keep codec dependency in a separate, explicitly licensed research executable and separate Cargo workspace; engine dependencies unchanged. |
| L10 | Keep the flat-store option off by default. Record its builder/compiled invariant, transient allocation and rollback obligations. |
| L11 | Defer bucket-relative name offsets. At most 2,670,542 bytes (2.547 MiB) of references can shrink before adding bucket bases; that ceiling is only 0.33% of current RSS, and wildcard buckets may defeat it. Insufficient evidence for another lookup convention. |
| L12 | Defer constant-NULL columns. Every nonempty group in this census has name bytes; the only empty groups have no reference arrays to eliminate. |
| L13 | Reject interning for this corpus. All name bytes exceed globally unique name bytes by only 448,096 bytes (0.427 MiB), insufficient to justify a new global table. |
| L14 | Move normalization/allocation into the hash string loader. It removes the temporary engine-pool copy; the large initial loading slowdown disappears. Exact unofficial-name normalization and malformed-name rejection are tested. |
| L15, L16 | Account width metadata and per-decoder scratch explicitly. Independent decoding needs 8,016 scratch bytes here, multiplied by concurrent active decoders. |
| L19 | Duplicate order, mixed hash/AC allocation fixtures, weak/PUA-vs-strong cases and full-corpus ordered callbacks pass. Separate AC disposable-build option remains off. |
| L20 | Defer direct final-layout construction/lifetime-separated compaction. Peak memory is an unresolved cost; a new transaction/rollback design is required before claiming a safe reduction. |
| L21 | Exercise flagged code offsets as a standalone follow-up; full token and width equality required. It removes 133,322 bitmap bytes and one 24-byte descriptor without tightening the existing input bound. |
| L22 | Reject small-dictionary bit packing here: even ideal packing is larger than the measured 16-bit dictionary, before charging decoder complexity. |

No entry is a universal worst-case memory or throughput guarantee. Theoretical compression can expand high-entropy inputs. Retaining a raw/baseline profile is necessary; no approximate membership test, skipped rule family, prediction-based omission or altered threat ordering was introduced.

## Continuation: 27 October 2026 — complexity gate and fresh literature

- **L23 — descriptor ownership sharing.** Inspect immutable TDB and expression
  ownership before integration; share exact values only after all subsignatures
  (including macros) have been parsed. Reuse existing facilities if possible.
- **L24 — adjacent sharing instead of a global interner.** A general interner
  needs keys, a construction index, and ownership state. Measure consecutive
  identical descriptor/expression runs first: a run-owned immutable object can
  use existing rule order for ownership, eliminating the new index entirely.
- **L25 — allocation census gap.** Existing `mpool_getstats` measures high-water
  allocation, not live object bytes. Distinguish size-class rounding, reusable
  holes, mapped tails, libc allocations and file pages before claiming savings.
- **L26 — direct token specialization.** Byte tokens avoid decoding but introduce
  a second verifier access representation. Audit current branches before calling
  this a complexity shift; defer if it multiplies paths or needs scratch caches.
- **L27 — range-count accounting defect found during the ownership audit.**
  `lsigattribs` increments `cnt[CLI_TDB_RANGE]` by TWO for each range, and allocates
  exactly that many uint32s. The prior census/exporter multiplies it by two again.
  This overcounts auxiliary bytes and the exporter reads beyond the logical
  allocation. Correct diagnostics, regenerate exports, and invalidate prior
  descriptor-sharing totals derived from that export. Production parser/scanner
  does not use the erroneous export arithmetic.
- **L28 — newer constant-time rank/select engineering (ESA 2026).** The paper
  reports sub-1% bit-vector overhead and fast difficult-input queries; reassess
  small local exception bitmaps separately from million-entry monotone indexes.
  It cannot eliminate the integer residuals or per-field headers themselves.
- **L29 — object hotness fragmentation (OBASE, OSDI 2026).** Prefer static grouping
  by known matcher lifetime/access role before runtime migration; published
  instrumentation/migration would add complexity and cannot be assumed available
  on the intended host.
- **L30 — output forests versus unordered graph compression.** DAAC output-set
  sharing is potentially relevant to candidate links, but an occurrence set is
  insufficient: preserve ClamAV's exact linked traversal and duplicate order.
- **L31 — pointer interning key overhead.** Full descriptor keys are construction
  data. Measure their retained size and all-distinct worst case; hash-consing is
  not automatically a win on every custom database. No unmeasured universal
  memory or load-time claim.
- **L32 — allocation-address ordering blocks a loader-only optimization.** The
  repeated 10,000-rule-pair + 10,000 hash-distractor test has identical first
  result and alert multiset, but different all-match sequence before/after
  sharing. Repeats of each binary are stable. `sort_list_fn` and
  `sort_heads_by_partno_fn` break ties with pattern addresses. Even an unrelated
  matcher-header size change can perturb pool allocation. Do not promote this
  prototype merely because the ordinary corpus and severity fixtures pass.
  Preserving historical pointer order while changing allocation generally needs
  legacy allocation simulation; stable IDs define a new tie order. Both are
  outside this pass's strict order/complexity contract. Preserve the experiment
  in a patch/branch and retain the existing runtime representation by default.
- **L33 — compact only after candidate order is frozen.** Post-link sharing or
  relocation can preserve the already-built ordered edges, unlike loader-time
  allocation changes. However inline TDB headers occupy mixed engine-pool pages:
  freeing individual fragments need not lower RSS. Reusing an existing compile
  relocation phase is worth investigation; a second relocation framework,
  shadow allocator or page-hole collector would add complexity. No claim of a
  qualified implementation or memory saving yet.

## Reconsideration after logical-sharing experiments

| Lead | Final disposition this pass |
|---|---|
| L23 shared metadata | Implemented and measured; 51.693 MiB compiled RSS reduction in experimental flat-hash profile, then rejected for active integration by L32. |
| L24 adjacent runs | Not integrated; fewer ownership/index objects but weaker sharing. Earlier counts depended on the flawed export and are withdrawn. Post-link variant may merit analysis. |
| L25 allocator census gap | Extended logical auxiliary accounting; still no complete allocator attribution or fragmentation saving claim. |
| L26 byte-token specialization | Deferred: adds verifier representations; not a proven complexity shift. |
| L27 range overcount/over-read | Fixed in retained diagnostics; full logical arrays counted; previous logical-layout estimates explicitly superseded. |
| L28 rank/select | Literature reviewed; suitable for large directories, not automatically tiny bitmaps. No new scanner dependency. |
| L29 object/page locality | Static roles/lifetimes worth investigation; runtime movement excluded. |
| L30 output forests | Newly read primary AC paper supports exact ordered-tail census; no set deduplication or runtime merge introduced. |
| L31 hash-consing overhead | Actual key/table costs counted; all-distinct case can increase memory and load collision cost. |
| L32 ordering coupling | Repeated failure demonstrated; corpus equality does not override it. Runtime unchanged; experimental patch/branch retained. |
| L33 post-link compaction | Plausible lead, but mixed-pool residency and relocation costs remain. Needs reuse of an existing phase to meet complexity constraint. |

## 100-fold bound audit: leads recorded before measurement (28 October 2026)

- **L34 — pay for the association.** Repeated descriptor/expression payloads look hundreds-fold redundant only before paying for each rule's identity, selection and order. Measure corrected exact template frequencies, reference entropy, run structure and dictionary overhead before claiming a 100-fold gap.
- **L35 — constants and sparse exceptions within pattern fields.** Whole-record compression can hide nearly information-free columns. Count each actual field, exclude exporter-generated IDs, and compare both native and existing block-codec storage. Source-proven elimination can reduce complexity; dataset-specific elision requires a checked fallback.
- **L36 — implicit trie versus materialized transitions.** The 2019 compressed-dictionary-matching bound may expose a 100-fold gap in retained dense routing, but not in the best existing prototypes. Count topology separately from terminal labels, duplicate ordering and ClamAV verifier metadata. Do not apply a worst-case family lower bound as a pointwise minimum for this one trie.
- **L37 — entropy-compressed array access.** Newly found August 2026 Blelloch et al. preprint addresses nearly optimal entropy space with constant-time array access. Read the model, randomness and additive redundancy before treating it as a practical replacement. Dynamic machinery may be unnecessary for immutable engine data.
- **L38 — dependencies across shared template IDs.** The descriptor, expression and target ID may predict each other. Measure conditional entropy and exact exceptions without reordering rules. A relation-discovery framework would add complexity; a source-proven relation could remove storage.
- **L39 — four duplicated pattern-length bounds.** The corrected export shows only 110/121 pattern-length exceptions and 32/35 prefix-length exceptions to equality with the corresponding token count, across 1,508,210 patterns. Check whether every exception has the existing special-pattern extension. If true by parser construction, moving the four exceptional bounds into that existing object can avoid an added sparse-index subsystem. Measure this before deciding; allocation-dependent order still blocks naive loader-time changes.
- **L40 — global constants still pay per-block headers.** The existing 1024-row codec charges 1,473 twelve-byte headers for the all-zero `rtype` column. A global constant can replace these, but the absolute saving is only about 17 KiB. Prefer that narrow change over inferring a large opportunity solely from a huge ratio.

### Reconsideration after the 100-fold audit

| Lead | Evidence and disposition |
|---|---|
| L34 | Association cost included. Corrected native TDB storage is 44.098 MiB; dictionary + indexed Huffman reference witness + conservatively retained escapes budgets 0.235 MiB, a 187.6-fold gap. This is a data-layout result, not integrated RSS; direct-pointer sharing already closes much of it but failed the ordering gate. Expression sharing alone is below 100-fold after associations. |
| L35 | Seven actual pattern fields use 34.520 MiB natively versus 0.0549 MiB in verified constant/run/sparse layouts. Existing block codec already uses only 0.1999 MiB for these fields. Dataset-specific defaults are not universal invariants. |
| L36 | Dense routing is about 120 times the 0.6256 MiB leading trie counting term, but the term is a worst-case family benchmark and omits scanner output metadata. The 10.631 MiB existing prototype is about 17 times that benchmark. Do not promote a new 100-fold routing opportunity over the best prototype. |
| L37 | Re-examined full theorem and model. Archive search found this paper was already listed in the October 27 correlation/profile reports; the initial "newly found" description above was mistaken. Randomization, virtual-memory model, lookup tables and rebuilding make it a research reference, not a complexity-neutral replacement. |
| L38 | Conditional expression-reference entropy falls from 543,609 to 63,904 bits given template IDs, but the gross difference is only 59,963 bytes before conditional tables. Defer additional machinery for this small increment. |
| L39 | All 298 field-level length exceptions have existing extensions. Four conditional exception columns occupy 1,876 bytes versus 3,193,168 bytes under the existing block codec (1,702-fold). Native-field opportunity is 11.507 MiB. Growing every existing 17,509 extension by eight bytes costs 0.134 MiB, so the simpler extension-based design projects 11.373 MiB net payload saving. Priority lead; ordering and pool-release integration remain unresolved. Offset-max differs 5,565 times, including 2,967 records without extensions, so it does not share this simple implementation argument. |
| L40 | Verified: 17,676 bytes in block headers versus an 18-byte scalar layout. Worth folding into existing codec selection; too small to drive architecture. |

No scanner runtime changes were made in this audit. See [the full bound audit](entropy-gap-audit.md) for the distinction between a counting lower bound, an entropy benchmark and an exact reconstructible upper bound.

## Length-bound implementation: leads recorded before testing (28 October 2026)

- **L41 — reuse extension ownership.** Store the four byte bounds in the existing extension and leave token counts in the pattern. The parser already retains a stack extension until finalization. No new allocation class, index, decoder or lifetime is needed. Verify native and Rust layouts, both prefix directions, short buffers, relative offsets, extension cleanup and full ordered alerts.
- **L42 — allocator and ordering qualification.** Eight bytes less native payload per pattern does not imply eight bytes less resident allocation: pool size classes and mixed pages matter. Measure actual memory and strict duplicate ordering before promotion.
- **L43 — non-parser patterns have different defaults.** Regex-suffix and logical-macro constructors historically keep zero byte bounds despite nonzero token counts. Both already require extensions; preserve their zero bounds there. Test these explicitly rather than assuming every bound equals the token count outside special alternatives.

- **L44 — pre-existing absolute-offset prefix underflow.** A new short-prefix test initially failed: `(6162|63646566)676869` at absolute zero rejects `abghi` but accepts `cdefghi`. The same standalone probe reproduces this on the baseline (return codes 0 and 1). The unsigned lower-offset bound wraps when the maximum prefix exceeds the candidate position. Keep behavior unchanged in this representation-only patch; test both variable branches at offset two. This is a separate correctness follow-up, not a new regression fixed by this change.

### Reconsideration after the length-bound implementation

| Lead | Evidence and disposition |
|---|---|
| L41 | Implemented in the existing extension; no new ownership mechanism. All exported pattern bounds agree, C/Rust layouts agree, 1,825 C checks and 65 Rust tests pass. Preserved as an experimental patch/branch because the strict ordering gate fails. |
| L42 | Native payload falls 11.373 MiB; compiled RSS mean falls 5.754 MiB (0.742%). Both first selected duplicate name and ordered all-match sequence change. Repeat outputs are stable within each build. Default runtime remains unchanged. |
| L43 | Preserved zero bounds for regex-suffix and macro constructors through their existing extensions. Explicit constructor-default regression added. |
| L44 | Baseline probe confirms the absolute-zero variable-prefix underflow behavior. Recorded as a separate issue; no behavior change in this storage experiment. |

## Incorporating qualified reconsiderations — 28 October 2026

### L45 — Free backing pages without moving pool objects

The rejected copy-and-fragment-free ownership path did not imply that every free pool page must remain resident. The new Linux flush path advises only whole pages inside already-free fragments, excluding their linked-list metadata. It preserves addresses, size classes, list order and errno; failed/unsupported advice is a no-op. The production allocator harness passes reuse, boundary, live-byte, failure-injection and sanitizer checks. The pinned database has 35,516,416 bytes of successfully advised ranges; initial compiled RSS falls about 33.5 MiB. Full paired results, exact-output fixtures and scope limits are recorded in [the implementation report](qualified-strategies-implementation.md). No construction-peak or whole-engine target achievement is claimed.

### L46 — Borrow the evidence key before allocating an owned string

Use the existing IndexMap raw-entry lookup to allocate a name only on insertion. Retain every metadata item, severity map and original name pointer; do not implement latest-only evidence or unordered deduplication. The isolated 100,000-repeat probe eliminates 100,000 temporary allocations, with identical ordered histories and no allocation increase for the all-distinct case. This replaces the existing insertion path rather than introducing an evidence codec or interner. Added Rust tests cover pointer history, pop/reinsert, severity and child-depth behavior. See the same implementation report for integrated qualification.

No throughput, cross-platform, production/reload or quarter-memory qualification
is claimed. Detailed results: [length-bound implementation](length-bounds-implementation.md).
