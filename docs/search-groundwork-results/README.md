# Search groundwork evidence

Follow-up: the [linked-counter feasibility investigation](../linked-counter-feasibility.md)
now demonstrates compact input access and audits the published fallback dispatch.
The historical results below remain unchanged.

These are offline research results on the same signed-database capture used by
the [earlier field model](../system-model.md): 3,628,192 signatures and
75,460,242 captured field values. No scanner runtime or rule-selection default
changed. The original upstream reference and retained captured branch remain
different identities.

## Actual-capture outcomes

| Search | Known steady bytes | Known conversion peak | Known equal-size reload/conversion peak |
|---|---:|---:|---:|
| Preserve captured native providers | 671,970,413 | 671,970,413 | 1,326,346,930 |
| Explicitly allow logarithmic identity lookup | 554,119,189 | 899,091,949 | 1,435,617,242 |

These subtotals include one worker's 17,593,896-byte logical tracking arrays.
They are **not RSS or whole-engine limits**. Additional scan/parser state,
allocator/page effects and compiler scratch remain unknown. Reload assumes two
captured equal-sized generations and one total configured scan-worker allowance.

The default control has exactly one declared configuration. The relaxed search
selects direct packed/constant/NULL-preserving programs, three active operation
kinds, one new identity index kind, one field-image format and the existing
seven-case generic decoder (285 noncomment source lines including its harness).
It does not enable the category carrying the earlier derived-field slowdown.

The relaxed layout is a **proposal awaiting qualification**. Its `O(log N)`
identity search violates the default direct-access growth rule. All selected
images and locator storage were rebuilt and charged. Python replay and a
separate C reader agree on every captured value. No whole-scanner performance
pass or minimum-RAM proof is claimed.

The independent C checks also measured short, uniform field-access traces.
Synthesized/native CPU ratios ranged from approximately 0.79 to 1.32 across the
six families. Some components improved and others regressed. The native baseline
is schema-driven memcpy, identity lookup is excluded, data was read during
verification, and trials were not pinned. These are not scanner timings.

Both searches completed in under a minute in the recorded environment. The
offline preparation/search process reached about 1.6 GiB high-water RSS; that
includes capture pages, model construction and the native solver. It is not
ClamAV memory. See exact timings and resource observations in the summaries.

## Counting and input-format checks

The actual relaxed budget query has **295,443 variables and 1,005,993 clauses**,
all width at most three. Its saved assignment satisfies every clause. Helpers
are deterministic full-equivalence gates; counts concern declared provider and
program choices, not equivalence classes of programs with the same behavior.

Conventional enumeration completed the one-configuration control. Unassisted
enumeration of the relaxed optimum timed out without completing its count.
The independently reconstructed optimizer witness still establishes at least
one answer. No count or speed result for the linked algorithm is reported.

Six synthetic fixtures provide independent exact oracles:

| Fixture | Complete configuration count |
|---|---:|
| Budget 135 | 0 |
| Budget 136 | 2 |
| Budget 152 | 3 |
| Budget 256 | 4 |
| Budget 256, native required | 1 |
| Budget 256, encoded required | 3 |

The fixtures compare hand-cost/dependency enumeration, complete SAT enumeration,
deterministic extension and an independent attempt to find a second extension
under fixed primary choices. Their byte weights are synthetic, not measurements
of ClamAV. The external-counter protocol was also exercised against the bounded
Minisat enumeration backend and its known two-answer fixture.

The full relaxed query's linked canonical input has **3,029,313,958,669 logical
bits**, or **378,664,244,834 packed transport bytes** (about 353 GiB). Only the
length was computed. The huge file was not written. A small fixture includes an
actual capped packed transport checked against the encoding definition. Packed
transport still needs an adapter to the formal counting machine.

## Files

- [preserve-summary.json](preserve-summary.json) and
  [explore-summary.json](explore-summary.json): exact costs, choices, limits,
  field/resource checks, solver outcomes and source/input hashes.
- [explore-query.cnf.gz](explore-query.cnf.gz),
  [explore-variables.json.gz](explore-variables.json.gz), and
  [explore-witness.json.gz](explore-witness.json.gz): actual Boolean query, map
  and complete satisfying assignment. These contain no signature bodies or
  native pointer constants.
- [canonical-input.json](canonical-input.json): exact length-only conversion.
- [source-comparison.json](source-comparison.json): matching upstream and retained
  C/header lexical measurements, with upstream Git blob identities verified.
  Disabled variants are included; allocator wrapper names are not dynamic calls.
  The prototype reader is measured separately and Rust is explicitly unmeasured.
- [earlier-work16-field-complexity.json](earlier-work16-field-complexity.json):
  resource analysis of the previous Work16 selection, separate from the new run.
- [native-probes/summary.json](native-probes/summary.json): current-layout C
  reconstruction, per-family timings and bound image/native/schema/probe hashes.
- [fixtures/summary.json](fixtures/summary.json): tiny exact-count oracles, with
  each query and map stored beside it.
- [counter-protocol-check.json](counter-protocol-check.json) and
  [enumerator-command.json](enumerator-command.json): conventional backend check
  and a repository-root command example. No caller label proves an algorithm ran.
- [measurement-template.json](measurement-template.json) and
  [expected-binding-template.json](expected-binding-template.json): deliberately
  unfilled evidence templates. Extend the cases to cover every workload required
  by the selected contract; the starter cold/warm/adversarial cases alone do not
  cover every parser, update, concurrency or input obligation. Nulls cannot pass.
- [verification.json](verification.json), [provenance.json](provenance.json) and
  [artifacts.json](artifacts.json): independent publication checks and identities.
- [tests.txt](tests.txt): groundwork unit checks.

There are eight catalog choice groups, six captured native record families and
two currently active catalog selection groups (`field_provider` and `lookup`).
Other catalog alternatives are gated extension points until implemented cost and
correctness adapters are available. Historical component sizes are not additive
cost coefficients. Full upstream parity requires source-bound whole-scanner
evidence and a compatible correctness contract, regardless of storage-model size.

[Commands, schemas and extension points](../../tools/compact-memory/search-groundwork/README.md).
