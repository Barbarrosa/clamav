# AC byte-bound relocation — implemented, not enabled

28 October 2026. The implementation reduces native payload by **11.373 MiB** and
measured compiled RSS by **5.754 MiB (0.742%)**, but it fails the strict
first-name and duplicate-alert ordering requirements. It is preserved in
`experiments/ac-length-bounds.patch` and branch `experiment/ac-length-bounds`
(revision `abd2431`). The retained scanner runtime is unchanged.

## What changed

`cli_ac_patt` keeps two token counts instead of six 16-bit length values. The
four matched-byte bounds move to `cli_ac_patt_ext`, which already owns special
patterns and other uncommon metadata. Four accessors read explicit bounds when
an extension exists and otherwise return the corresponding token count.

The parser already builds a stack extension and copies it only when a cold
feature is present. It now accumulates and shifts byte bounds in that object;
an ordinary pattern still allocates no extension. Variable alternatives already
require an extension. No new decoder, sparse directory, allocator, cache or
ownership phase was introduced. Arithmetic widths and wrap behavior are retained.

A constructor audit found an important exception to the naive default rule:
regex suffixes and logical macros have nonzero token counts but historically
zero byte bounds. Both already allocate extensions. Reading explicit bounds
from **any** extension preserves those zeros; conditioning only on special
alternatives would change behavior.

The change updates matcher checks, relative-offset validation, prefix shifting,
maximum-pattern accounting, filtering, non-parser constructors, Rust bindings
and diagnostics. Nine added C checks exercise literals, wildcards, retained and
discarded extensions, fixed and variable alternatives, both prefix directions,
short buffers, full-width scalar values and relative EOF bounds. Three existing
internal functions are exposed in the private test symbol group.

## Space actually saved

Measured on 64-bit Linux with the pinned signed database identified in
`length-bounds-results/database-provenance.json`; 3,628,192 signatures,
1,508,210 target-matcher patterns and 17,509 extensions. The opt-in flat hash
store is enabled in both builds; other matcher options match the retained defaults.

| Measurement | Before | Experimental | Reduction |
|---|---:|---:|---:|
| Main pattern size | 96 B | 88 B | 8 B per pattern |
| Extension size | 48 B | 56 B | costs 8 B per extension |
| Main records plus extensions | 138.882 MiB | 127.509 MiB | 11.373 MiB net payload |
| Compiled RSS, two-process mean | 775.121 MiB | 769.367 MiB | 5.754 MiB |
| Compilation peak RSS, mean | 928.605 MiB | 922.863 MiB | 5.742 MiB |

The payload arithmetic is `8 * (1,508,210 - 17,509) = 11,925,608` bytes.
Retained pattern-pointer tables have the same size in both censuses. RSS is a
separate measurement: pool size classes, reusable fragments and mapped tails
prevent equating native object bytes with released pages. This pass does not
fully attribute that difference. The quarter-memory target remains unmet.

## Verification and the failed integration gate

- Baseline C suite: **1,816 checks pass**. Changed engine: **1,825 checks pass**.
- Changed Rust suite: **65 tests pass**. C/Rust sizes and affected field offsets agree.
- Changed command-line suite: **145 tests pass, one skipped, five subtests pass**.
  Its first run had one infrastructure error: the generated `check_xlm_scanmap`
  helper lacked execute permission. Restoring that permission and rerunning the
  suite resolved it; scanner source was not changed for that issue.
- AddressSanitizer and UndefinedBehaviorSanitizer: **53 matcher checks pass**
  with production `matcher-ac.c` instrumented. Other C/Rust objects were not
  instrumented, and LeakSanitizer was disabled. This is targeted coverage.
- Exact exports preserve every semantic pattern field and all six length/count
  values for **all 1,508,210 patterns**. Extension presence is identical. Numeric
  extension IDs change because the diagnostic numbers them by allocator address;
  the comparator ignores only those numeric IDs. Tokens, names, logical records,
  descriptor templates and programs are byte-identical. This does not prove
  ordered-list equality; those are tested separately.
- The restored **3,319-file corpus** has every input hash verified. Four runs in
  before/after/after/before order have identical first-hit and all-match transcripts:
  87 detected files, zero scan errors, and respectively 87 and 89 callbacks.
- Six weak/PUA-versus-strong selection cases pass for both builds.

**The strict duplicate fixture fails.** With 10,000 duplicate patterns interleaved
with 10,000 distinct patterns and preceded by 10,000 hash rules, the first
selected name changes from `Foundations.Order.09884.UNOFFICIAL` to
`Foundations.Order.09836.UNOFFICIAL`. All-match emits the same 20,000 alerts with
the same multiset, but their sequence changes. Repeated runs of each binary are
stable. The evidence records binary and input hashes.

`sort_list_fn` and `sort_heads_by_partno_fn` break otherwise equal candidates by
pattern address. Smaller allocations change that address order. Full-corpus
agreement and preserved severity do not override this failure. Replacing the
tie order with stable IDs would redefine behavior; retaining a shadow legacy
allocator would add a subsystem. Neither was done. Post-order compaction remains
a separate lead, with mixed-pool page reclamation unresolved.

## Limits and additional finding

Performance is **not qualified**. Mean first-hit corpus times were 77.676 seconds
before and 105.102 seconds after; all-match means were 142.558 and 117.288 seconds.
Individual timings vary substantially, and some runs overlap other compilation
or tests allowed on the same CPU set. These are diagnostic observations, not a
claim of either equivalent throughput or a reliable speedup. The unchanged
retained scanner remains the baseline option.

A new prefix test exposed a pre-existing absolute-offset issue:
`(6162|63646566)676869` at offset zero rejects `abghi` but accepts `cdefghi`.
A standalone baseline probe reproduces return codes 0 and 1. The unsigned lower
offset bound wraps when the maximum prefix exceeds the candidate position.
This representation-only change preserves that behavior; the variable-prefix
regression uses offset two to exercise both matching branches. The existing
issue is logged separately as L44 and is not presented as a regression fix.

This pass does not qualify Windows, 32-bit targets, malloc-only builds, daemon
reload, production workloads or deployment. No scanner runtime change from this
experiment is enabled in the retained source. See the evidence README for
reproduction; raw database, corpus and exported signature payloads are excluded.
