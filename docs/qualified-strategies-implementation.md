# Incorporated strategies: address-preserving page release and borrowed evidence keys

28 October 2026, America/Phoenix. This implementation follows the 22-family reassessment in `research/rejected-approaches/reassessment.md` in the project archive. It incorporates two narrowly scoped strategies into the retained engine: **R02, physical reclamation of free pool pages without relocation**, and **R18's simpler evidence-key reuse variant, preserving the full evidence history**.

The whole-engine memory target remains unmet. These changes reduce resident memory and allocation traffic; they do not remove signatures, alter threat priority, change result ordering, or introduce a compact decoder/cache configuration. The previously rejected logical-sharing and length-bound patches remain experiments.

## Runtime changes

### R02: release backing pages at the existing pool flush

`mpool_flush` now walks the existing free lists for fragments large enough to contain an entire page after their metadata. For each fragment, it excludes the free-list link and both partial boundary regions, then advises only whole interior pages with Linux `MADV_DONTNEED`.

The allocator retains the mapping, fragment size, free-list links and ordering. Allocation addresses and sizes are unchanged. No live object is moved or rewritten, and no allocation-size or parser-order change precedes the AC sort. The new routine allocates no memory and introduces no index, cache, ownership state or public API. It is called at the existing flush point; there is no additional scan-time polling.

`errno` is restored after advice. A failed call merely retains the backing pages. Other platforms, or builds without the detected function/constant, take the existing no-advice behavior. The CMake check uses the pre-existing `HAVE_MADVISE` configuration slot.

The reported advised bytes describe successful advice ranges, not necessarily resident bytes. Pool size statistics continue to describe owned virtual storage, so they need not fall when RSS falls. Small fragments, metadata pages, live objects and dead fields inside live records are not reclaimed by this change. Construction peak is not expected to improve because reclamation occurs after construction.

### R18 variant: allocate evidence keys only on insertion

`Evidence::add_indicator` previously allocated `name.to_string()` before discovering that the name was already in its ordered map. It now selects the same severity map, performs the lookup through the pinned IndexMap dependency's existing borrowed-key API, and constructs an owned key only for a vacant entry.

Every `IndicatorMeta` is still appended. Distinct original string pointers with identical name bytes retain their own pointer/depth/object-ID metadata. Pop/removal, reinsertion order, child merging, normalization depth, weak/PUA/strong distinctions and callback behavior are unchanged. This is not the rejected latest-only or unordered-deduplication design, and it does not introduce run encoding.

The ordered maps, their hashers and their vectors are unchanged. No dependency, feature flag, interner or runtime representation is added. The three duplicate insertion arms are consolidated into one insertion path.

## Qualification

Machine-readable measurements and complete test evidence are in [qualified-strategies-results](qualified-strategies-results/). `summary.json` is the numeric summary for the final paired runs; historical results from other profiles are not mixed into it.

| Requirement | Evidence |
|---|---|
| Preserve selected names and ordered alerts | 10,000 rule-pair fixture with 10,000 hash-allocation distractors: before/after first-match and ordered all-match observations agree. |
| Preserve threat severity | Strong signatures at indices 0, 5,000 and 9,999 among weak or PUA matches; repeated first-hit and all-match tests retain the strong result. |
| Preserve allocator invariants | Production `mpool_flush` harness checks live guards, every free-list link, same-address reuse, malloc writes, calloc zeroing, repeated flush, small-fragment control and injected advice failure. |
| Preserve unsupported-feature behavior | Same allocator harness compiled without `HAVE_MADVISE`: no advice and no RSS reduction, with allocation/history assertions still passing. |
| Preserve evidence history | Two added Rust tests cover same-name/different-pointer history, pop/reinsert ordering, all three severity classes, child merges and normalized depths. |
| Native and language tests | 1,816 C checks; 67 Rust tests; scanner suite: 145 passed, one skipped and five subtests passed. |
| Sanitizers | Isolated production allocator regression passes AddressSanitizer and UndefinedBehaviorSanitizer with leak detection disabled for this environment. This is not whole-scanner sanitizer coverage. |
| Clean scanning and performance | Four serial processes in AB/BA order scan the same 3,570-file, 89,192,023-byte corpus in first-hit and all-match modes. All return-code/name/ordered-callback transcripts agree; this corpus produces no detections. |
| Official-database detections | A separate before/after run scans 89 generated binary fixtures (10,086,758 bytes), whose hashes match the prior project corpus. Both detect 87 files with zero errors, 87 first-hit callbacks and 89 all-match callbacks. Final names and ordered callback transcripts match exactly in both modes. |
| Signature compatibility | All comparison processes load the normally verified pinned main/daily/bytecode snapshot, totaling 3,628,192 signatures. No verification bypass or rule-family omission. |

The allocator harness uses the actual updated `mpool.c`, with minimal compatibility headers for unrelated dependencies and a syscall wrapper for observation/failure injection. It contains no second copy of the purge algorithm. ASan does not automatically know individual allocations inside the custom pool, which is why explicit payload and metadata assertions are also checked. The no-advice build is a branch check on Linux, not a Windows or 32-bit engine qualification.

The four clean-corpus runs have the following means, with two fresh processes per variant:

| Observation | Baseline | Updated |
|---|---:|---:|
| Compiled RSS | 823.818 MiB | 789.932 MiB |
| Construction high-water RSS | 823.725 MiB | 823.416 MiB |
| First-hit clean-corpus scan | 45.657 s | 45.214 s |
| All-match clean-corpus scan | 45.942 s | 45.481 s |

Compiled RSS falls **33.887 MiB (4.11%)**. First-hit and all-match times differ by approximately -0.97% and -1.00%, respectively: comparable in these observations, not a proven speedup. Construction high-water differences are small run variation; no peak reduction is attributed to this post-construction reclamation. RSS and high-water are separately sampled Linux counters, and their small inconsistencies are preserved in the raw results.

The first corpus used source-tree test inputs, including encoded rather than generated binary fixtures. Its zero detections were explicitly noticed, so the generated fixtures were added as a separate official-database comparison. This distinction is kept in the evidence instead of describing the clean-only transcripts as detection coverage.

The separate detection-fixture runs took 21.948/22.061 seconds before/after in first-hit mode, and 50.743/48.984 seconds in all-match mode. These are single observations per variant and do not establish a speedup or a generalized regression bound.

## Targeted allocation result

The separate evidence-key probe links the engine's pinned IndexMap implementation and compares the original and new insertion expressions. It verifies equal ordered keys and complete metadata vectors. The measurements count allocation requests and requested bytes during insertion, not peak or resident memory.

| Scenario | Events | Old allocation requests | New allocation requests | Result |
|---|---:|---:|---:|---|
| One pre-existing name; metadata capacity preallocated | 100,000 | 100,000 | 0 | Eliminates 3,400,000 requested bytes of temporary name allocations. |
| All distinct | 10,000 | 20,028 | 20,028 | Requested bytes and ordered histories are identical. |
| 100 names, repeated | 100,000 | 100,914 | 1,014 | Eliminates 99,900 requests; metadata growth remains counted. |

These counts demonstrate removal of redundant allocator work. They are not a claim that 3.4 MB of resident memory is saved or that every workload speeds up.

## Measurement controls and limits

The baseline is retained source commit `282052bd1577d918a2a5de135f47567d8d78830f`. Before and after use the same full-feature Release build, GCC 13.3, Rust 1.90, pool allocator, interpreter bytecode, unrar support and signature database. Compact logical rows, AC node IDs and flat AC nodes are enabled. Experimental flat hashes and the disposable AC builder remain **off**, matching the retained defaults.

Both builds use one Rust release code-generation unit. Repeated default-parallel-codegen attempts produced truncated intermediate artifacts in this environment; the one-unit build completed. This build control is shared by both variants and is not a repository default change. Comparing these timings directly with earlier flat-hash or differently built experiments would be invalid.

Scans use the public API, disable the scan cache equally, preserve the same file order and hash return codes, final names, callback counts and ordered callback names. The paired timing run is pinned to CPU 2 on a shared host. No local build or other heavy test runs concurrently with those paired scans. Two processes per variant provide a regression check, not a statistical guarantee for all inputs, tail latency or production workloads.

The first load-only observation was 843,436 KiB before and 809,092 KiB after: approximately 33.5 MiB lower compiled RSS. The updated flush reported 35,516,416 successfully advised bytes. This observation is kept separately from the final paired summary because the updated observation enabled compilation debug output and ran alongside tests. It establishes a real database opportunity beyond the synthetic probe; the paired run supplies the final reported measurements.

The supported-platform fallback is unchanged code behavior, not a measured cross-platform performance result. Daemon reload, cross-generation sharing, cgroup limits, 32-bit layouts and Windows have not been newly qualified. Advice can add page-refault cost if a later allocator client reuses a reclaimed fragment; the paired whole-scanner checks include normal post-compilation use. This does not solve construction/reload peak memory or establish a sub-200-MB engine.

## Disposition of the remaining strategies

| Reassessment IDs | Disposition |
|---|---|
| R01; direct-offset part of R06 | Already retained as the existing opt-in flat-hash implementation. No default promotion: its higher construction peak remains unresolved. |
| R03–R05 | Post-order compaction remains unqualified. Correct graph translation and actual release of mixed-pool storage are still necessary; the rejected loading-time implementations are not restored. |
| R07, R13, R22 | Insufficient current payoff or an additional format/access mechanism. A tiny prototype-codec cleanup does not justify expanding the runtime in this pass. |
| R08–R12, R14–R17 | Native ownership, exact fallback, latency or integration obligations remain. Standalone compression results do not yet qualify these as scanner changes. |
| Other R18 variants | Ordered-run and tail-sharing representations remain prototypes. Full history is preserved with the existing vectors. |
| R19 | Zero-default scan-state encoding requires an audit/adaptation of bytecode and YARA consumers; it is not enabled merely on the zero-page probe. |
| R20–R21 | Lifetime/generation restructuring and dynamic schemes remain separate architectural work. The incorporated purge requires no such redesign. |

## Reproduction

Use ordinary ClamAV build dependencies and the same pinned database for a new comparison. The saved database provenance includes the Docker layer digest and CVD SHA-256 values; databases and downloaded third-party sources are not redistributed in this archive.

```
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
cmake --build build
ctest --test-dir build -R '^(libclamav|libclamav_rust|clamscan)$' --output-on-failure
python3 source/tools/compact-memory/test_mpool_flush.py source
python3 source/tools/compact-memory/test_mpool_flush.py source --no-advice
ASAN_OPTIONS=detect_leaks=0 python3 source/tools/compact-memory/test_mpool_flush.py source --sanitize
```

For the recorded Rust build control, export `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1` and `CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_CODEGEN_UNITS=1` consistently for both variants and their tests. The two alert-fixture tools now accept `--certs PATH`, so an uninstalled build can use its real certificate directory rather than depending on `/usr/local/etc/certs`. Verification is still performed normally. `probe_scan_corpus` accepts the database, certificate directory and ordered file list; `PROBE_DEBUG_COMPILE=1` enables compile diagnostics only when explicitly requested.

The evidence allocation probe is a standalone Rust source: link it with the pinned engine build's IndexMap rlib using `rustc --edition=2021 -O`, `-L dependency=BUILD/x86_64-unknown-linux-gnu/release/deps` and `--extern indexmap=PATH_TO_RLIB`. It adds no engine dependency.

OS semantics: [Linux madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html). Dependency API: [IndexMap 2.11.4 RawEntryApiV1](https://docs.rs/indexmap/2.11.4/indexmap/map/trait.RawEntryApiV1.html). The memory and correctness results above come from the saved local experiments, not those documentation pages.
