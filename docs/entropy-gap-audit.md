# Where the compression is still more than 100 times larger than necessary

28 October 2026. Scope: retained fork `4eae1ad`, corrected exports of the pinned 3,628,192-signature database, and the existing standalone compact prototypes. This is a representation audit and targeted literature review. The scanner is unchanged; there is no new whole-engine RSS or scan-performance result.

## Principal finding

**The strongest newly quantified gap is conditional redundancy in four pattern-length fields.** Even the existing packed-column prototype spends 3.045 MiB on values that can be reconstructed from already-retained base lengths and 1,876 bytes of exceptions: a **1,702-fold gap**. Every exception in the snapshot has the existing special-pattern extension. Moving exceptional bounds into that object is therefore a better complexity fit than importing another general-purpose codec.

Several other 100-fold gaps exist in the retained native layout, but earlier prototypes already close most of them. That distinction prevents repeatedly rediscovering savings which the experimental representations already achieved.

| Area and accounting boundary | Retained native payload | Exact smaller representation / benchmark | Native ratio | Status against existing prototypes |
|---|---:|---:|---:|---|
| Four additional pattern/prefix length bounds, conditional on two base lengths | 11.507 MiB | 1,876 B of exact exceptions and headers | 6,432x | Existing block encoding still uses 3.045 MiB: **1,702x gap remains** |
| Seven sparse, constant or run-heavy pattern fields | 34.520 MiB | 57,528 B of exact scalar layouts | 629x | Existing block codec uses 209,615 B; remaining improvement to this witness is only 3.64x |
| Logical target descriptors, including inline headers and auxiliary values | 44.098 MiB | 246,422 B layout budget including dictionary, reference decoder/index, headers and retained escapes | 188x | Previous direct-pointer sharing already removes most duplication; it remains rejected for ordered-output changes |
| `offset_max`, conditional on retained `offset_min` | 5.753 MiB | 44,542 B of exact exceptions | 135x | Existing block codec uses 77,820 B; only 1.75x to this witness |
| `rtype` global constant, a subset of the seven-field row | 2.877 MiB | 18 B scalar layout | 167,579x | Existing codec still uses 17,676 B: 982x, but only about 17 KiB remains |
| Completed AC transition rows | 75.164 MiB | 0.6256 MiB leading trie counting term, **not a complete ClamAV representation** | about 120x | Existing cyclic prototype is 10.631 MiB, about 17x the same benchmark; no 100x residual gap established |

Rows overlap where stated and are not additive engine savings. The descriptor row is a budget with original escape objects retained, not a complete new scanner serialization. None of these ratios establishes performance parity or that a new layout satisfies the complexity constraint.

## What “theoretical constraint” means here

A particular finite database has no computable, model-independent minimum encoding size that this audit can measure. A compressed-file size, empirical entropy and a lower bound for a whole family of inputs are different quantities.

This audit uses three explicit comparisons:

1. **Constructive exact witness:** if the current representation costs B bytes and a fully specified reversible representation costs U bytes, then the minimum over encodings allowing those operations is at most U. Thus B/U > 100 establishes a real gap without pretending U is the minimum. Access costs and construction memory must be considered separately. The simple witnesses use direct constants, binary-searchable sparse entries/run starts, or indexed prefix codes; they do not promise the native hot-path cost.
2. **Conditional counting bound:** for a sequence with known labeled frequencies f_i, `log2(n! / product(f_i!))` is the worst-case counting bound over sequences with that histogram. Symbols, frequencies and access indexes are additional costs. It is not a pointwise bound on this one ordered sequence.
3. **Empirical zero-order benchmark:** `H = sum(f_i * log2(n/f_i))`. Serial and cross-field dependencies can beat it. Adding a dictionary to H gives a useful model budget, not proof of optimality.

Constant columns have zero conditional information, but their value, shape and mode still need representation. This audit charges an explicit header instead of reporting an infinite ratio. Exporter-generated IDs are marked and excluded from native savings. The raw `patterns.bin` first column is a diagnostic identity; the token-specialized prototype replaces that column with a real token ID. Consequently this audit's whole-export codec total is not a replacement measurement for that token-specialized prototype. Comparisons of the four length columns and seven sparse columns are unaffected.

## 1. Conditional pattern lengths: the remaining prototype-level gap

Each pattern stores three pattern lengths and three prefix lengths. The zero-indexed length is the token count; the other two account for expanded minimum and maximum lengths of special alternatives. They usually coincide but cannot be unconditionally equated.

| Dependent field | Retained reference | Records differing out of 1,508,210 | Existing 1024-row codec | Exact exception layout |
|---|---|---:|---:|---:|
| `length[1]` | `length[0]` | 110 | 1,371,044 B | 682 B |
| `length[2]` | `length[0]` | 121 | 1,371,044 B | 748 B |
| `prefix_length[1]` | `prefix_length[0]` | 32 | 225,540 B | 214 B |
| `prefix_length[2]` | `prefix_length[0]` | 35 | 225,540 B | 232 B |
| **Total** | Base lengths remain stored | **298 field-level exceptions** | **3,193,168 B** | **1,876 B** |

The witness stores each differing row as a uint32 position and uint16 exact replacement, plus 22 bytes per column for shape, mode, default and base reference. The positions are sorted, so a single-field access can binary-search the exception list. No row or alert is reordered. Reconstruction of every field passed. The 298 count is not a count of distinct patterns.

The source gives a simpler implementation lead. In `matcher-ac.c::cli_ac_addsig`, ordinary tokens increment both expanded lengths by one. Special tokens read bounds from `ext->special_table`. `ac_shift_pattern_prefix` follows the same distinction when splitting prefixes. All exported exceptions have a non-null extension.

**Preferred follow-up:** keep ordinary token counts in the pattern and place the four additional bounds in the existing extension object; accessors return the ordinary count when no special bound is needed. Adding eight bytes to all 17,509 existing extensions costs 140,072 B, versus removing 12,065,680 B from pattern records: **11.373 MiB projected net payload saving**. This is an intentionally less compressed design than the 1,876-byte witness, to reuse existing ownership and lookup paths.

That is not an implementation approval result. Audit all construction paths, partial-parser cleanup, custom signatures, YARA and diagnostic layouts. Loader-time object-size changes can still alter address-based sort ties; post-order compaction and actual pool release remain unresolved. No new shadow allocator or stable-order substitution is authorized by this analysis.

The four-field codec improvement is about **3.043 MiB**, not 1,702 times the whole scanner. It is already included within the native 11.507 MiB opportunity, so the two savings must not be added.

## 2. Sparse fields and over-local codec metadata

The seven actual pattern fields are `lsigid[0]`, `offdata[0..3]`, `rtype` and `type`. Their native widths total 24 bytes per pattern. Exact constants, runs or sparse entries reconstruct all their values in 57,528 B, including per-column headers. Original sequence positions are retained.

The existing block codec already compresses these fields to 209,615 B. The large native ratio mostly indicates an integration gap; it does not justify another elaborate codec. Defaults observed in the pinned database must never be assumed for arbitrary custom signatures.

There is a smaller residual problem: `rtype` is zero throughout this snapshot, yet its codec allocates 1,473 identical 12-byte headers. Detecting a global constant before allocating block descriptors reduces 17,676 B to one 18-byte descriptor. The ratio exceeds 100, but the absolute saving is small. Extend the existing mode selection only if this avoids redundant per-block state; a separate constant-column framework would be disproportionate.

`offset_max` equals `offset_min` except at 5,565 positions. This gives a 135x native comparison, but 2,967 exceptional patterns lack the extension used above. It therefore does not inherit the same simple relocation argument. The current block codec is already close enough to the simple witness that this is lower priority.

Logical `bc_idx` is also sparse, and the snapshot's logical type/flag fields are constant. Their native widths differ from the normalized uint32 export, especially the one-byte flag; do not charge four native bytes for it. They support the general field-audit direction but do not establish another large engine component.

## 3. Logical descriptors: include the references

Corrected input has 312,310 logical rules, 1,205 distinct eligible target descriptors, and 82 escapes. The native descriptor cost is:

`136 * 312310 + (6,807,226 - 3,041,019) = 46,240,367 bytes`.

This subtracts expression text from the fully counted auxiliary allocation and retains the inline TDB header. Rule names, IDs and unrelated header fields are outside this boundary.

The association sequence has H0 = 811,308 bits and a fixed-histogram counting term of 808,880 bits. It cannot be omitted. A diagnostic prefix-code construction, independently restarted every 64 rules, has these sizes:

| Item | Bytes |
|---|---:|
| Distinct serialized eligible descriptors | 71,268 |
| Dictionary offsets, including an empty escape marker | 4,828 |
| Reference bitstream, including block padding | 105,439 |
| Block offsets | 19,524 |
| Flat decoder tree | 28,932 |
| Prefix-code header | 24 |
| Conservative retained escape budget | 16,375 |
| Additional directory/header allowance | 32 |
| **Total budget** | **246,422** |

The escape budget includes 82 entire original 176-byte rule/directory records, 1,284 counted escape value bytes and all 659 additional string/macro bytes from corrected accounting. This deliberately overcharges unrelated escape header fields. The diagnostic does not export those extra descriptor kinds; they remain original objects. Eligible values, their pointer coordinates and every reference round-trip exactly.

This is a **187.6x native payload comparison**, but it is not a qualified native decoder. A lookup may decode 64 codes of at most 18 bits each; Python construction objects and engine allocation rounding are not included. This witness establishes space feasibility without claiming a new complexity-neutral runtime feature. The existing rejected direct-pointer-sharing implementation remains the simpler performance-oriented design; its ordering blocker is still decisive.

Expression-only duplication is a useful counterexample to inflated ratios. Its 3,041,019 B of repeated text collapses to 25,623 B of distinct text, superficially over 100x. Adding an exact reference decoder and offsets gives **150,677 B**, only **20.2x** against repeated text, or about **36.8x** if the old expression pointers are also charged. It does not qualify as a separate 100x gap on this accounting.

Conditioning expression IDs on descriptor IDs lowers the modeled ID entropy from 543,609 to 63,904 bits, but the gross saving is only 59,963 B before conditional tables. That is insufficient evidence to introduce another mapping mechanism under the complexity constraint.

## 4. Routing: a useful theoretical comparison with an important boundary

The census has 555,935 trie edges across matcher roots. Summing the leading term `log2 binom(256*(m+1),m)` per root gives 5,247,886 bits, or **0.6256 MiB**. Retained transition rows occupy 75.164 MiB: approximately 120 times that term.

Kosolobov and Sivukhin derive a closely related worst-case trie counting lower bound and succinct matching constructions. This is a benchmark for the byte-trie family, not proof that ClamAV can operate in 0.6256 MiB. Terminal annotations, state mapping, ordered candidate multisets, verifier rules and practical rank/select overhead still cost memory. The strongest near-bound result assumes a pattern-count regime that has not been established for these anchors.

Most importantly, the existing 10.631 MiB cyclic prototype is already about 17 times this benchmark. Thus routing is a retained-layout integration opportunity, **not evidence of an unclosed 100x gap in our best explored compression**. The paper's experiments include extracted ClamAV signatures, but do not test the full scanner semantics or this fork's short-anchor workload. Its appendix also shows that the succinct alternatives are not uniformly fastest on short patterns.

## 5. Targeted scholarly review

The search was driven by the measurements above: conditional copying and exact exceptions; entropy-coded small alphabets with local access; overhead of constant/run-heavy columns; and succinct literal-trie routing. Sources were checked on 28 October 2026. Three sources below were not found in the saved earlier reviews; the other three were deliberately re-examined. Publication recency is not used as evidence of a better implementation.

| Primary source and review depth | Relevance and decision |
|---|---|
| **[Storage-Centric Relation Design via High-Quality Approximate Functional Dependencies](https://vldb.org/2026/program.html)**, Ding et al., VLDB 2026, DOI [10.14778/3819518.3819558](https://doi.org/10.14778/3819518.3819558). Newly reviewed official conference abstract; full PDF could not be retrieved. | RelaxRD selects dependencies by storage benefit while retaining violating tuples. This matches the measured length-copy/exceptions problem. Borrow the cost accounting; do not import relation discovery, decomposition or reconstruction machinery. “Approximate dependency” must still retain every exception for our exact scanner. |
| **[Corra: Correlation-Aware Column Compression](https://arxiv.org/html/2403.17229v2)**, CloudDB/VLDB workshop 2024. Revisited full encoding sections. | Direct cross-column encoding and outlier retention explain why compressing each length column separately misses the largest residual gap. Our code-derived equality is simpler than general correlation prediction. Use existing extension ownership when possible. |
| **[Dynamic Entropy-Encoded Arrays in O(1) Time with Nearly Optimal Space](https://arxiv.org/html/2608.06066v1)**, Blelloch et al., 6 August 2026 preprint. Revisited theorem, model and construction sections. Previously listed in this project's reports. | Motivates reducing template-ID space near its measured entropy. The theorem uses a virtual-memory model, randomness and high-probability bounds; the construction includes tables and rebuilding. It does not establish a small practical decoder for 312,310 immutable rules. Reject direct adoption under the complexity constraint. |
| **[Succincter](https://people.csail.mit.edu/mip/papers/succinct/succinct.pdf)**, Pătraşcu, FOCS 2008. Newly reviewed locally decodable arithmetic-coding and redundancy/access results. | A theoretical reason not to equate compressed size with mandatory whole-block decoding. Recursive representations and lookup machinery remain extra implementation work. Use as an access/space reference after testing simpler static representations. |
| **[LeCo: Lightweight Compression via Learning Serial Correlations](https://people.iiis.tsinghua.edu.cn/~huanchen/publications/leco-sigmod24.pdf)**, Liu et al., SIGMOD 2024. Newly reviewed formulation, model/residual method and partitioning tradeoff. | Explains why zero-order entropy misses ordered regularity; FOR, delta and RLE are special cases. Exact residuals preserve values, but a learner and partition-selection subsystem are unnecessary for our observed constants and 44-run boolean column. Retain simple deterministic encodings as the comparator. |
| **[Compressed Multiple Pattern Matching](https://drops.dagstuhl.de/storage/00lipics/lipics-vol128-cpm2019/LIPIcs.CPM.2019.13/LIPIcs.CPM.2019.13.pdf)**, Kosolobov and Sivukhin, CPM 2019. Revisited counting proof and experimental appendix. Previously listed in the frontier report. | Establishes the routing-family benchmark and the limits of applying it to short anchors and ordered extended signatures. No new automaton replacement is justified by the 100x residual criterion. |

No paper's reported compression ratio or throughput improvement is transferred to ClamAV. The new quantitative findings come from the corrected local data and the explicitly costed layouts.

## 6. Areas not established as 100x opportunities

- **Digest keys:** under the distinct uniformly random 128-bit set model, the main corpus has an ideal set-encoding saving of roughly 7.7 MiB from roughly 49 MiB, before bucket/value/index costs. This is nowhere near a 100x gap under that model. A particular digest dataset is not proven incompressible merely because it contains hashes.
- **Names and tokens:** existing layouts demonstrate useful factors, but there is no tight dataset-specific lower bound establishing either a remaining 100x gap or closeness to optimality. Stable C-string pointers impose an additional residency/interface constraint. Do not present a general compressor's output size as a lower bound.
- **Candidate links:** exact reference identities, duplicate multiplicity and traversal order remain required. The audit's marginal entropies and existing 8.223 MiB layout do not establish a remaining 100x gap. Shared ordered tails remain an unquantified lead.
- **Default scan state and evidence history:** prior synthetic/fresh-state tests can exceed 100x when nearly nothing is touched or every entry repeats. They do not prove a large resident-engine gap; fully touched or distinct workloads remove the saving. Keep that working-set question separate.
- **Allocator retention and reload overlap:** lifetime overhead can be substantial, but it has no meaningful compression ratio until live information and physical allocation are reconciled. The unexplained RSS gap is not counted as compressible data.

## Next work under the existing acceptance criteria

1. Prioritize the four length bounds and existing extension structure. Establish all-path invariants and find a post-order storage/lifetime change that releases memory without changing address-derived output ordering.
2. Fold global-constant detection into the existing scalar representation if it simplifies block state. Treat the approximately 17 KiB residual as a small cleanup.
3. Resolve order-preserving compaction before more logical-sharing integration. The descriptor witness shows ample information redundancy; more sophisticated entropy coding does not solve ownership or ordering.
4. Defer learned partitioners, dynamic entropy arrays and new succinct-routing machinery unless simpler replacements fail and the complexity constraint changes.

The fourfold whole-engine target remains unproven. This audit does not change that result.

## Reproduction and validation

Run `tools/compact-memory/audit_entropy_gaps.py CORRECTED_EXPORT_DIRECTORY docs/entropy-gap-results/audit.json` with Python 3 and NumPy. The corrected exporter is `export_exact_layouts.c`; do not reuse pre-correction logical exports. Raw signature exports and databases remain excluded from the archive.

The diagnostic verifies every simple scalar column, every conditional copied field, every eligible dictionary entry and every independently restarted prefix-code block. Source SHA256 values, per-field counts and detailed byte accounting are in [audit.json](entropy-gap-results/audit.json).

An independent run of the existing C scalar codec on the same corrected pattern export verifies all **37,705,250 fields** and reproduces the audit's per-column total: 8,518,897 payload bytes + 441,900 directory bytes = 8,960,797 B, before the C store header and eight-byte read padding. Its recorded output is [scalar-verification.jsonl](entropy-gap-results/scalar-verification.jsonl). These timings are incidental and are not a new scanner performance qualification.

The runtime was not edited; a full scanner rebuild/test suite was unnecessary for this research-only pass. New leads and reconsideration outcomes are recorded in [complexity-shift-leads.md](complexity-shift-leads.md).
