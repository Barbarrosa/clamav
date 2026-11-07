# Length-bound experiment — not enabled

`ac-length-bounds.patch` moves four AC byte bounds into existing pattern
extensions, adds matching/offset tests, and updates C/Rust diagnostic layouts.
It is excluded from the retained scanner because both the first selected
name and duplicate all-match order differ from the baseline. See
`../docs/length-bounds-implementation.md` for measurements and exact test scope.

The patch applies to the retained source with `git apply`; it does not apply
its report/lead-log changes a second time. `git apply --check
experiments/ac-length-bounds.patch` passes. The history bundle contains the
complete implementation on branch `experiment/ac-length-bounds`, based on
`fe52606`, with final experimental revision `abd2431`.

Apply only in an isolated experimental copy. This is not a supported profile.

---

# Tighter pool size classes — rejected

[`tight-pool-classes.patch`](tight-pool-classes.patch) adds 184-byte and
1,040-byte LP64 pool classes behind `ENABLE_TIGHT_POOL_CLASSES`, default **OFF**.
It passed isolated allocator and sanitizer checks, but the strict engine
comparison failed **4 of 23 cases**: duplicate reporting and three PUA positions.
The runtime change was reverted. It must not be enabled as a memory improvement.

The patch contains the original `8a1b2d9` change with context refreshed for the
retained-directory default; the experimental flag still defaults to **OFF**.
`git apply --check experiments/tight-pool-classes.patch` passes on the retained
source. Apply only in a separate experimental checkout. The
[behavioral failure report](../docs/top-six-memory-results/rejected-tight-classes/summary.json)
and [top-six findings](../docs/top-six-memory-investigation.md) explain the
rejection. No whole-engine memory or performance qualification was pursued
after the correctness failure.

---

# Logical-sharing experiment — not enabled

`logical-sharing.patch` contains the implemented descriptor/expression sharing
experiment, its private-layout changes and sanitizer harness. It is intentionally
excluded from the retained scanner because the strict duplicate-alert ordering
fixture fails. See `../docs/logical-sharing-implementation.md` before use.

The patch is based on diagnostic revision `3d3034e`; the final report commit adds
only documentation/evidence. `git apply --check experiments/logical-sharing.patch`
passes against the retained source. Apply only in an isolated experimental copy.
The source-history bundle also contains branch `experiment/logical-sharing`.

This is not a supported memory-saving profile or a deployment recommendation.

---

# Logical-directory packing experiment — not enabled

[`logical-directory-ids.patch`](logical-directory-ids.patch) replaces large
64-bit logical-rule pointer directories with exact base-plus-32-bit-offset
directories after successful compilation. It does not move or merge the rules.
The optional CMake flag `ENABLE_LSIG_DIRECTORY_IDS` defaults to **OFF**.

The full-database smoke measured a 1.13 MiB table-payload reduction, with lower
compiled and hydrated RSS. Strict duplicate-order and active-format tests passed.
Reload CPU increased 2.98% in the small sample; complete performance and resource
qualification remains incomplete. It is excluded from the retained runtime.
See [the investigation and evidence](../docs/logical-directory-investigation.md).

The aggregate patch contains the prototype, guarded header and diagnostic
accounting changes from `52910e5`,
`dd4e368` and `c78da1d`, plus the logical-accessor adaptation used by the combined
directory-retirement test build (`5173341`). Existing directory-retirement and
pool-reclamation implementations are prerequisites and are not duplicated.
Its context is refreshed for the retained-directory default.
`git apply --check experiments/logical-directory-ids.patch` passes on the retained source.
Apply only in an isolated experimental copy. This is not a supported profile.
