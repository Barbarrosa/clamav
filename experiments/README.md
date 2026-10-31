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
