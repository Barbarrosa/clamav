# Restricted Legal Redress database selector — experimental

**Follow-up:** the documented `--database-profile=legal-redress` flag now opts in to all-match restricted scanning, with full mode remaining the default. The user accepted alert-order differences when detection multisets and severity are preserved. See [the configuration follow-up](subset-selector-configuration.md) for that contract and new validation. The results below preserve the original, stricter experiment; parser-completeness holds remain in force.

28 October 2026, America/Phoenix. **Working selector and intake prototype; qualification failed. Automatic clean release from a reduced database is disabled.** The retained full-database runtime, configuration defaults, prior experiments and evidence remain unchanged at `005bb6c6ca880b13184775956d0f87faf541ea0b`.

The candidate reduces compiled RSS from **790.113 to 129.724 MiB (83.582%)** on the pinned official database. That is approximately **136.0 decimal MB**, below 200 MB for the measured scanner process. It does **not** establish a qualified sub-200-MB service: exact generic-alert ordering fails; parser completeness is not observable in all cases; reload and updates exceed the budget; isolated page-cache accounting and production concurrency remain unqualified.

The primary result is [results/summary.json](subset-selector-results/summary.json). Full signed input hashes, versions, record inventory, reasons and preparation results are in [database-manifest.json](subset-selector-results/database-manifest.json). New executable tools are in [tools/subset-selector](../tools/subset-selector/README.md).

## What is implemented

- A streaming CVD/CLD inventory and SQLite-backed conservative selector, with signed-input verification, a mandatory **full-database load and compile before selection**, bytecode dependency protection, explainable callback-name decisions and reproducible generation hashes.
- A public-API C scan/load probe with a temporary mapped exclusion manifest, exact ordered public callback/evidence transcripts, original-byte integrity checks, construction and scan memory observations, and actual FreshClam database-test calls.
- A private local intake prototype that snapshots original bytes, records original metadata, distinguishes detections, holds and failures, and never authorizes reduced clean release. A shadow-generation pointer supports atomic switching and rollback; production activation explicitly fails.
- Unit, synthetic differential, signed-input, integration, sanitizer, retained-engine and workload tests; repeated paired memory/performance measurements and preserved failure evidence.

No parser, matcher, allocator, engine option default, production clamd configuration, live WordPress/Forminator site, notification channel or real complaint data was changed. No real submissions were processed.

## Selection rule and dependencies

The selectable families are **plain explicitly Target:1 NDB/LDB rules** and **PE section/import hash formats `.mdb`, `.msb`, `.imp`**. PE rules are candidates only under a policy that holds the **whole original upload** whenever PE processing becomes reachable. No exclusion is justified by the outer filename, MIME claim, magic alone, or malware-name prefix.

For NDB/LDB, the selector requires an unambiguous literal target `1`. It retains Target:0, every other target, unknown attributes, handlers, macro references (`$`), missing/ambiguous targets and unparsed cases. An unparseable record prevents generation activation. Container and intermediate constraints are inventoried, but never used alone to justify omission. The selector does not attempt to reduce the entire database to three outer file types.

The callback provides format and name, not parsed target or occurrence identity. Therefore **all occurrences in the same callback namespace must be eligible**. NDU shares the NDB namespace and LDU shares LDB; a generic or uncertain occurrence protects the whole name group. CBC files remain signed and loaded, and their second-line logical names protect same-name LDB groups. The loader's `load_oneldb()` is also used by bytecode, which makes this protection necessary. The 85 serialized CBC records include hooks and rules that may be version-ineligible; they are not assumed to be 85 active detection signatures.

All whole-file `.hdb/.hsb` hashes are kept, including names beginning `Win.*`. All type recognition (`.ftm`, `.sdb`), configuration, icon data, container metadata rules, allowlists, certificates/trust records, phishing data, unknown-purpose rules and bytecode are kept. PUA hash variants are kept; the measured `CL_DB_STDOPT` configuration does not enable their optional PUA database loading. `.imp` is supported as an exclusion family but is absent from this snapshot.

The remaining PE matcher has **75 AC patterns and 36 logical records**, principally retained dependencies/effect-sensitive cases. It is not deleted. The generic and non-PE matcher records remain present. Keeping unknown formats is not sufficient to certify their dependencies: unknown database extensions also block activation.

The final generation has **369,984 eligible callback names**, plus format-level hash exclusions. It loads **601,004 signatures**, versus **3,628,192** full. The callback reports **3,027,189 skipped events**. Callback events and loaded signature counters are not identical quantities: the callback can precede engine-functionality eligibility checks, and ignored/dependency records follow separate loader accounting. Do not derive loaded signature counts by subtracting these event counts.

## Inventory and memory accounting

The manifest inventories each archive member, serialized bytes, physical non-comment records, explicit targets, container/handler constraints and selection reasons. Examples below include optional/version-ineligible records and therefore differ from loaded signature counts.

| Family | Serialized records | Serialized bytes | Disposition |
|---|---:|---:|---|
| NDB / NDU | 106,068 | 24,736,824 | Select only unambiguous PE-only name groups |
| LDB / LDU | 322,403 | 91,956,299 | Same, with effect/dependency protections |
| MDB / MSB | 2,670,550 | 167,425,910 | PE-specific hash candidates |
| HDB / HSB | 541,981 | 38,181,818 | Retain whole-file hashes |
| CBC | 85 | 1,274,849 | Retain original signed bytecode |
| FP / SFP | 998 | 54,131 | Retain trust/false-positive behavior |
| FTM | 268 | 20,097 | Retain type recognition |
| CDB | 135 | 14,353 | Retain container metadata effects |
| IDB / CRB | 252 | 57,876 | Retain icon and trust data |

A new compiled census uses the **current default, non-flat hash layout**, not the prior opt-in flat-hash census. See `census-full.jsonl` and `census-reduced.jsonl`.

| Measured compiled component | Full bytes | Reduced bytes |
|---|---:|---:|
| AC core nodes/transitions/filters | 92,682,712 | 23,993,304 |
| AC candidate records/directories | 72,957,408 | 3,721,536 |
| AC pattern/extensions/tokens | 248,057,570 | 19,103,020 |
| Hash payload/directory accounting | 89,339,132 | 21,476,676 |
| Counted names before interning | 87,619,213 | 16,058,081 |

These are incomplete payload/capacity categories, **not RSS**. Logical records, auxiliary arrays, other matchers, parsers, allocator rounding and other process costs are separate. The PE-only five-component subtotal from earlier work is neither added to these totals nor subtracted from RSS. The new census independently confirms the opportunity; only the paired process runs establish the RSS saving.

### Why the callback was selected

| Mechanism | Benefits | Preservation/maintenance cost | Decision |
|---|---|---|---|
| Derived plaintext database with `-d` / DatabaseDirectory | Stock loader; no runtime name lookup | Changes signed-container provenance and official-name labeling; extracted bytecode loses original signed trust unless separately retained in signed form; record/order reconstruction and updates become another artifact format | Not selected |
| Generated `.ign2` | Stock configuration; optional record-MD5 pinning | Global names can cross formats; duplicate-name cases need conservative grouping or exact-record handling; millions of PE hash names create a large ignore structure; ignore paths can affect CBC | Not selected; no memory claim for an unmeasured ignore list |
| Exact callback manifest over original CVD/CLD files | Original signed files, official status, bytecode trust and loading path retained; per-format grouping; no runtime scan lookup | Temporary name index and binary searches during loading; cannot distinguish same-format/name occurrences | Implemented |

`ScanPE no` changes PE parsing but does not prune the PE database; it is not used. All parsers remain enabled in both variants. No transformed signature payload is described as still covered by Talos's original signature.

## Runtime enforcement and evidence handling

Initial root types are **PDF/JPEG/PNG for benchmarking only**, not an approved current form allowlist. The broader shadow profile includes OLE2, OOXML Word/Excel/PowerPoint/HWP, mail, RTF, ZIP, RAR and 7z. Recordings, other formats and executables remain eligible evidence through the hold/exception path; this prototype does not automatically release them.

The closure from accepted roots is deliberately over-approximated: a PDF stream can decode to arbitrary bytes; embedded files can be archives or executables; image metadata/appended content may be discovered and rescanned; Office and mail can contain arbitrary attachments. Normalization can expose text/HTML/script content. Handler signatures can reclassify any layer. Bytecode unpackers can produce another recursive scan. Every non-PE target and generic rule remains available for these paths. The omission argument is conditional on detecting and holding **all paths that use PE semantics**, not on an extension allowlist.

| Audited path | Observation/enforcement | Limit |
|---|---|---|
| Initial and recursive magic scans | FILE_TYPE plus PRE_HASH/PRE_SCAN callbacks; sticky PE hold | A pre-scan magic callback alone is insufficient |
| On-the-fly refinement | `others.c:cli_recursion_stack_change_type` dispatches FILE_TYPE; scanner retyping sites audited | New engine revisions must be re-audited |
| HandlerType | Retained rules rescan a child; generated handler fixture proves PE hold | Handler rules cannot simply be removed as non-alerting |
| Normalized direct matcher calls | `matcher.c:cli_scan_buff`, `cli_scan_desc`, `cli_scan_fmap`; current direct callers use non-PE targets and those rules are retained | These paths do not all have ordinary recursive callbacks; no general callback completeness claim |
| PE hashes | `pe.c` section/import code reached through PE processing | PE holds are sticky even when another retained rule detects malware |
| Encrypted/limited content | Archive metadata, encrypted/limits/broken heuristic alerts and JSON ParseErrors generate holds | Not every parser/size skip is surfaced |
| Truncated/malformed content | Some broken-media fixtures are held | Malformed PDF and ZIP fixtures can finish without any error/alert; automatic release remains disabled |

In particular, `scanners.c:scanraw` can skip an embedded PE after `MaxEmbeddedPE` without a complete public incomplete-scan outcome. A universal enforcement proof is not available. The source retains the same limits; this work does not reduce limits to obtain a memory or throughput result.

The intake snapshot is a separate private object created from one no-follow regular-file descriptor. Its SHA-256, length, original filename, filesystem timestamps/mode and snapshot stability are recorded. Embedded metadata stays in the untouched bytes. The scanner reads the snapshot and verifies bytes before and after. JSON scan metadata is a separate analysis record. A derivative, if later added, requires its own identity and verdict and cannot clear the original. File permissions are a prototype access measure, not WORM storage, durable chain-of-custody certification or a complete retention system.

The harness reports raw status, final verdict/severity, final name, ordered modern callbacks (with layer/object/attributes), legacy virus callbacks, multiplicity and byte counts. It checks final borrowed-name lifetimes across subsequent scans until engine destruction. Existing Rust tests continue to cover internal evidence history; the new public transcript is **not a dump of every private evidence allocation**.

Raw `CL_VIRUS` is preserved: this retained development API sometimes returns it even though the newer `_ex` documentation describes separate verdicts. The adapter accepts that value only with a detected verdict. Other errors are failures, never clean. Policy reasons are independent of the detection evidence: an executable can be both detected and held, with the original detection retained.

`candidate_outcome` is diagnostic. Reduced `outcome` never becomes clean. `intake.py` additionally enforces this, and `activate_for_release()` always rejects activation. Complaint narrative submission is architecturally independent: no WordPress hook was installed, and the attachment record explicitly requires the narrative to proceed without waiting. An authorized full-scan/manual exception route is recorded, not automatically executed or forwarded.

## Validation and failed gates

- **32 selector/lifecycle tests pass**: target parsing, name ambiguity, macro/handler retention, CBC protection, unknown formats, failed signature/full-load checks, updates, extra files, changed engines/manifests, shadow rollback, symlinks and evidence preservation. Synthetic signed-container unit tests mock verification explicitly; they are not claimed as trusted official databases.
- Real signature verification accepts the official bytecode CVD and rejects a byte-flipped copy. The same signed members in uncompressed CLD transport verify successfully. No signature bypass or `BytecodeUnsigned yes` was used.
- Retained C/Rust/scanner suites pass (1,816 C checks, 67 Rust tests, scanner suite 145 passed, one skip and five subtests). An initial invocation lacked the existing pytest dependency path; rerunning with the recorded test dependencies passes. Both attempt and successful suite logs are kept.
- **28 valid PDF/JPEG/PNG files, 14,846,009 bytes**: 504 scan calls per variant, three fresh processes, three repetitions in each of two modes. All public semantic transcripts agree, all bytes remain equal, and no policy holds occur at the diagnostic eligibility layer. The reduced release result remains held because global qualification fails.
- **40 mixed/adverse generated files** plus broader compatibility fixtures cover renamed PE, false filename/MIME assumptions, embedded/decoded PE in PDF, PDF/ZIP and PNG/PE combinations, nested ZIP and email, OOXML, malformed/encrypted containers, recursion limits, image corruption, missing files and a test-only size limit. The limit override is not used for performance claims.
- **89 upstream generated positive fixtures**: both variants detect 87 files in both modes and the recorded public transcripts agree. There are 174 held scan outcomes across the two modes and four nonheld clean outcomes. Held detections do not count as coverage-equivalent eligible scans.
- Synthetic 10,000-rule duplicate fixtures: strong/weak/PUA severity behavior, ignore/stop/trust callbacks, handler retyping, allowlist trust, limits, errors and name lifetimes are exercised. The required-equivalence command exits **3**, with `qualification_passed:false`.
- AddressSanitizer/UBSan of the new harness passes the 300-rule mechanical/ownership cases with leak detection disabled. The linked existing engine is not sanitizer-instrumented; ordering qualification still fails. This is not whole-engine sanitizer coverage.

### Why exact equivalence fails

The AC sorter deliberately breaks equal-pattern ties using pattern addresses (`matcher-ac.c:sort_list_fn` and `sort_heads_by_partno_fn`). Removing PE allocations changes addresses of generic patterns. For an accepted-type PDF containing the same harmless marker, the full first-hit rule was `Synthetic.Order.09897`, while the reduced first hit was `Synthetic.Order.09989`. Both are strong detections. In all-match mode both have 10,000 alerts with equal multisets but different order. Ignore/stop/trust callback histories also diverge, and weak/PUA all-match evidence history can differ even when the strong final result agrees.

This is a failure against the **retained full fork**, not a claim of universal equivalence between that fork and untouched upstream. Fixing it by changing the full comparator would itself change the stipulated baseline. No such semantic change is smuggled into this selector. The earlier rejected compactions remain experiments.

## Paired memory and performance

Same retained library, GCC 13.3 Release engine, O2 public-API harness, pinned CVDs, all parsers, limits, bytecode, metadata and heuristic settings; cache disabled; one scan at a time; CPU affinity; six fresh processes in F/R/R/F/F/R order. No heavy build/tests ran concurrently with the paired benchmark. Engine flat hashes and disposable AC builder remain OFF. Memory includes the probe in the scanner process. The certificate directory is explicitly set and verification remains enabled.

| Valid 28-file workload | Full | Reduced candidate |
|---|---:|---:|
| Mean compiled RSS | 790.113 MiB | 129.724 MiB |
| Maximum construction HWM | 823.645 MiB | 160.461 MiB |
| Maximum process HWM after scans | 823.645 MiB | 160.461 MiB |
| Mean database load | 6.693 s | 3.563 s |
| Mean compile | 1.697 s | 0.108 s |
| Mean first-hit batch | 1.633 s | 1.678 s |
| Mean all-match batch | 1.637 s | 1.676 s |
| First-hit throughput | 8.670 MiB/s | 8.435 MiB/s |
| Per-file median latency, both modes | 10.574 ms | 10.739 ms |
| Per-file p95 latency, both modes | 338.995 ms | 350.668 ms |

First-hit/all-match batches were **2.79%/2.39% slower** in these observations. The sample is small and shared-host noise remains; no broad latency bound or speedup is claimed. The much faster reduced all-match time on the separate mixed corpus includes omitted PE work on held files and is **not** a valid coverage-preserving performance improvement. Per-file measurements include opening, original-byte hashing before/after, parsing and scanning; batch times also include transcript serialization.

HWM is lifetime `ru_maxrss`: scan-phase HWM includes construction, not a separate subtraction. RSS and HWM are independently sampled Linux counters. Three process replicates per variant do not establish worst-case adversarial bounds. Increased scan concurrency, large allowed documents and parser decompression allocations may dominate the reduced steady-state engine.

### Lifecycle and selector costs

| Measured scenario | Process high-water |
|---|---:|
| Full old/new engine overlap | 1,611.762 MiB |
| Reduced old/new engine overlap | 302.957 MiB |
| Two reduced engines + actual FreshClam main database test | 597.266 MiB |
| Two reduced engines + actual FreshClam daily database test | 818.977 MiB |
| Two reduced engines + actual FreshClam bytecode test | 303.152 MiB |
| Two reduced engines + complete-snapshot FreshClam test (conservative extra scenario) | 1,112.887 MiB |

These are sequential load/overlap probes in one process, using **the actual `fc_test_database_ex()` API**. FreshClam tests enable PUA database loading and prepare bytecode; they do not perform the same complete AC compile as the scan probe. The per-file scenarios model FreshClam's download callback; testing the directory is an additional conservative case. No real updater download, daemon handoff, cgroup isolation or multi-host memory measurement occurred. Moving a helper to another worker moves its resource cost; it does not eliminate it.

The callback's **14,925,375 bytes** of mapped names plus pointer index are charged during loading and released before compilation. The final generation's own Python selector HWM was **110,148 KiB** and elapsed time **18.813 s**, including waiting for the mandatory full-load child. Its child's construction HWM is separately recorded in the manifest; preparation is not a sub-200-MB operation. SQLite decision storage is 28,876,800 bytes, skip text 11,965,487 bytes, and signed inputs total 112,798,155 bytes. These disk/cache costs are not free scanner memory.

One end-to-end intake call recorded parent/worker high-waters of **14,944 / 164,480 KiB**. Their sum is a conservative sum of separate maxima, not a measured simultaneous total or deduplicated physical charge. Sampling the child tree was unavailable because `/proc/<pid>/task/<pid>/children` was absent; the failed aggregate observation is recorded as unavailable, not zero memory.

Shared-cgroup `memory.current` and `memory.stat` (file/anonymous/kernel) samples are included for every measured process. This workspace group contains other retained artifacts and processes; its totals cannot be attributed to the scanner by subtraction. The roughly 112.8 MB of signed files and other generation files can add charged cache beyond process RSS. An isolated cold/warm-cgroup budget remains a deployment gate. Neither reload nor full update validation fits 200 decimal MB here.

## Reproducible updates and disposition

Generate into a new private directory. Copy original signed CVD/CLD files; verify them; run the full unchanged loader/compiler; inventory; apply conservative grouping; record signed-file hashes/headers, engine and probe hashes, selector version/source hash, profile, decisions and exclusion-file hash. Do not edit existing signed files. The intake validates file sets/hashes and the same probe binary; unexpected files, changed engines or changed exclusions fail closed. The complete original DB remains the rollback/full-scan configuration.

Version 1.1 adds mandatory full-load validation and probe binding after the measurements. It produces **the identical exclusion SHA-256** as the measured generation. Both manifests are preserved and that equality is asserted in the result collector; all scanner measurements used the identical retained library, probe binary and exclusion bytes. The final preparation timing is newly measured for 1.1. Invalid PE rules could otherwise be skipped before ClamAV parses them, hiding a full-loader error.

Shadow switching validates the generation and updates only `shadow-current` / `shadow-previous`; it never edits the full service configuration. Automatic release activation is deliberately unavailable. After any real signature update, regenerate and rerun the qualification corpus and ordering/parser gates. A new signed database is authentic, not automatically safe to reduce. Rollback retains the previous immutable generation and all signed inputs. Filesystem crash durability and concurrent production deployment orchestration need further qualification.

The next blocking work is exact order preservation relative to the retained full engine, explicit propagation of incomplete-parser/limit outcomes, and isolated whole-lifecycle accounting. This experiment demonstrates a large real memory opportunity, but its current practical role is **shadow evaluation and evidence-preserving triage**, not an approved automatic-release scanner for Legal Redress.

## Primary sources consulted

The audited source in this archive is authoritative for this fork; current online docs can describe newer/older behavior.

- [Target/file types](https://docs.clamav.net/appendix/FileTypes.html): outer type is not recursive closure.
- [Logical signatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html): Target, Container, Intermediates and HandlerType.
- [Hash signatures](https://docs.clamav.net/manual/Signatures/HashSignatures.html): whole-file versus PE section/import formats.
- [Allow lists](https://docs.clamav.net/manual/Signatures/AllowLists.html): FP/SFP and optional record-MD5 `.ign2` entries.
- [libclamav](https://docs.clamav.net/manual/Development/libclamav.html): load paths, callbacks and verification.
- [Current public header](https://github.com/Cisco-Talos/clamav/blob/main/libclamav/clamav.h): callback and verdict contracts; runtime observations above preserve this fork's differences.
- [FreshClam configuration](https://docs.clamav.net/manual/Usage/Configuration.html#freshclam): updates; actual test implementation inspected in this archive's `libfreshclam/libfreshclam.c`.
