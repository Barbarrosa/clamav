# Memory-choice search groundwork

This is an offline research framework. It keeps correctness, performance evidence,
algorithmic work and maintenance complexity visible while preparing inputs for
ordinary SAT/MaxSAT and a future fixed-width counting implementation. It does
not change ClamAV's scanner, database selection or runtime defaults.

Read the [plain-language overview](../../../docs/search-groundwork.md) first.

## What is implemented

- `catalog.json` declares eight families and 26 choices: token storage, fields,
  logical descriptors, routing, names, scan state, allocation/reload lifetimes
  and identity lookup. Each has evidence, required properties and unknown or
  failed qualifications. Historical sizes are observations, never automatically
  additive current solver coefficients.
- `baseline-contract.json` declares ten correctness properties, 18 timing/memory
  dimensions, adversarial/cold/warm/concurrency workloads and complexity rules.
  The pinned upstream performance reference and current retained layout baseline
  are explicitly different identities.
- `search_model.py` implements the **captured field-provider adapter**. Native,
  packed, constant, NULL-preserving, affine, alias and sparse programs have
  serializers and capture-derived costs. Other catalog families remain at their
  retained choice until equivalent cost/serialization/checking adapters exist.
  They are declared extension points, not implemented optimizations.
- `choice_cnf.py` supplies full-equivalence gates, conditional choices and binary
  weighted budgets. Every primary assignment has a uniquely determined helper
  assignment. Inactive field choices are false; depth/resource predicates are
  derived rather than free variables. Counts concern declared configurations,
  not equivalence classes of programs with identical behavior.
- `complexity_metrics.py` analyzes field-provider reads, descriptor dispatch
  visits, dependent calls, rank/popcount work, bounded loops, allocations and
  identity lookup. It also measures lexical source indicators.
- `measurement_contract.py` checks source/workload-bound paired evidence. Unknown
  values, mismatched semantics, wrong measurement scopes and observed regressions
  cannot qualify a proposal. A pass is empirical, not a timing proof.
- `canonical_input.py` prepares the linked theorem's canonical Boolean input,
  computes its exact logical length without creating it, and limits optional
  packed transport writes.
- `lazy_canonical.py` accesses the same input without expanding unary codes.
  `linked_counter_audit.py` checks the pinned construction's integer settings
  and literal resource sizes. Neither executes the counting algorithm.
- `make_counting_fixtures.py` exports small independently checked count oracles.
  `run_counter.py` is an injectable external-counter protocol, not an extraction
  or implementation of the linked algorithm.

## Install and test

Use Python 3.10+, NumPy and python-sat 1.9.dev17. The gate kernel, canonical
frontend and measurement checker use the standard library; real capture search
also uses the existing system-model tools.

```sh
python3 -m venv /tmp/clamav-search-venv
/tmp/clamav-search-venv/bin/pip install numpy python-sat==1.9.dev17
/tmp/clamav-search-venv/bin/python -m unittest discover \
  -s tools/compact-memory/search-groundwork -p 'test_*.py' -q
```

Tiny tests independently enumerate choices and helper assignments, check cyclic
dependency rejection, byte-budget boundaries, lifetimes, conditional counts,
free declared variables, missing measurements, zero-cost baselines and malformed
canonical inputs. They do not replace whole-scanner tests.

## Prepare a real capture

Use the same-instance native exporter and signed-database procedure in the
[system-model reproduction guide](../../../docs/system-model-results/README.md).
Keep CVDs, native captures, pointer constants and generated field images outside
the repository in private directories. A capture from another build or database
is a new experiment.

The runner reuses validated candidate generation, but **does not reuse the old
encoding's loose depth variables or nonunique clause-splitting helpers**.

## Run a guarded search

From the repository root, with a prepared private capture:

```sh
python3 tools/compact-memory/search-groundwork/run_search.py \
  --capture /private/capture \
  --private-output /private/search-control \
  --report /tmp/search-control --policy preserve --enumerate-limit 2
```

`preserve` keeps native providers. This is a source-preserving control for the
captured branch, **not certification of that branch against original ClamAV**.
By default, even `explore` rejects the binary identity resolver's `O(log N)`
growth regression against direct `O(1)` native field access.

To investigate that tradeoff explicitly:

```sh
python3 tools/compact-memory/search-groundwork/run_search.py \
  --capture /private/capture \
  --private-output /private/search-explore \
  --report /tmp/search-explore --policy explore --allow-log-lookup \
  --query-units 64 --identity-reads 45 --dependency-depth 4 \
  --max-new-opcodes 4 --max-new-indices 2 --max-new-formats 1 \
  --max-decoder-cases 7 --max-reader-lines 400
```

This is an unqualified proposal. `--allow-component-regression` separately allows
exploration of a category with an observed isolated-reader slowdown, such as the
earlier Work16 derived-field experiment. It cannot enable rejected implementations
or override a declared correctness failure. Without this explicit flag, that
category is blocked. Its observation applies to the measured configuration, not
every possible future member of the family.

The concrete limits are:

| Parameter | Meaning |
|---|---|
| `query-units` | Conservative additive sum of descriptor visits, payload reads, dependency edges, popcounts, rank-loop iterations and data tests, plus identity-read allowance. Not CPU instructions or cycles; integer arithmetic and hardware effects remain separate qualifications. |
| `identity-reads` | Maximum charged binary-search key/index reads. The count uses integer bounds and is included in the per-query allowance. |
| `dependency-depth` | Maximum dependent field calls; every selected cycle is excluded. |
| `max-new-opcodes` | Active field-program kinds across the chosen configuration. |
| `max-new-indices` | New binary identity directory and sparse bitmap/rank mechanisms. |
| `max-new-formats` | New field-image format kinds. |
| `max-decoder-cases` | Seven compiled cases in the current generic prototype reader if used. This differs from the number of active opcodes. |
| `max-reader-lines` | Conservative lexical code-line cost of the entire existing C reader, including its diagnostic harness. It is not an integrated-engine patch-size estimate. |

All current field providers have zero new persistent decoded caches and no query
allocation/syscall. Resource bounds and lexical source counts do not establish
CPU parity. Unknown integer instruction counts are not set to zero.

## Budgets, conditions and counts

`--steady-budget`, `--conversion-budget` and `--reload-budget` are integer byte
limits on known modeled extents. One worker's three logical-slot arrays are
included by default; `--workers` changes that explicit term. Other scan state,
allocator/page effects and compiler scratch remain unknown. The reload curve
assumes equal-sized captured generations, with one configured total scan-worker
allowance, not every possible changed update.

The runner first minimizes known steady storage with RC2, independently rebuilds
the selected images and locators, and replays every selected native field. It
then exports width-at-most-three `query.cnf.gz` and `variables.json`. Without an
explicit steady budget, the query uses the optimizer's reported optimum. With a
budget, it retains that budget so larger near-optimal alternatives can be counted.
The MaxSAT result is not an independently checked optimality certificate.

Condition genuine primary choices using their names in `variables.json`:

```sh
# Add to an exploratory command to require a non-native provider:
--fix catalog/field_provider/native=false
```

An impossible condition means no answer in this gated model; an unavailable
adapter or missing qualification is not a mathematical impossibility for all
ClamAV designs. Unsupported names and contradictory duplicate conditions fail.

For measured feedback, copy a run's `selected-configuration.json`, attach the
SHA-256 of the evaluation evidence, and supply it with `--exclude-config FILE`.
The complete primary assignment is blocked, leaving other configurations in the
family available. A capture/choice-schema mismatch or partial assignment fails.
The schema binding prevents reusing variable names against different captured
values or candidate definitions. The evidence hash records provenance, not proof
that the exclusion is valid on another machine or under another policy; use the
measurement binding/checker for that judgment.

`--enumerate-limit N --enumerate-seconds S` supplies a conventional small-count
baseline. A timeout or limit gives only a lower bound. An independently replayed
optimizer witness already establishes at least one configuration even if the
unassisted enumerator finds none before timeout.

Generate complete, public-safe oracle queries:

```sh
python3 tools/compact-memory/search-groundwork/make_counting_fixtures.py \
  --output /tmp/clamav-count-fixtures
```

These are synthetic two-field models: budgets 135/136/152/256 have 0/2/3/4
configurations; conditioning the last on native/encoded gives 1/3. The script
checks a separate hand-cost/dependency oracle, complete SAT enumeration and
second-extension rejection under fixed primaries. Their byte costs are not real
ClamAV measurements.

## Performance evidence gate

```sh
python3 tools/compact-memory/search-groundwork/measurement_contract.py \
  --write-template /tmp/measurements.json \
  --write-binding-template /tmp/expected-binding.json
```

Fill both templates from controlled measurements. Required bindings cover the
baseline and candidate artifacts, database, corpus, scan configuration, hardware,
policy and selected observable-equivalence contract. Cases bind their workloads,
cold/warm cache states, adversarial class and concurrency. Recorded semantic and
policy digests must agree. The checker cannot authenticate an inaccurate reporter.

The 18 dimensions include scan CPU/wall time, externally measured p95/p99 latency,
startup/reload/update CPU/wall time, cold/hydrated residency, construction/reload/
update-overlap peaks and context/scan/builder scratch. Explicit measured zero is
valid; missing is not zero. New positive cost against a zero baseline fails.

```sh
python3 tools/compact-memory/search-groundwork/measurement_contract.py \
  --bundle /tmp/measurements.json --expected-binding /tmp/expected-binding.json \
  --output /tmp/qualification.json
```

`passed_observed` means no required paired observation exceeded baseline; exit 2
means missing evidence and exit 3 means failed evidence. The default ratio limit
is 1.0 and cannot be increased to excuse regressions. This strict filter is not a
confidence interval, a statistical no-regression test or an all-input guarantee.
No new representation is automatically promoted into the scanner.

## Canonical input and external counters

```sh
python3 tools/compact-memory/search-groundwork/canonical_input.py \
  --cnf /private/search-explore/query.cnf --report /tmp/canonical-length.json
```

Length inspection does not write a transport. Optional `--output` is capped by
`--max-bits`. The canonical unary-number/framed-list encoding is much larger than
DIMACS: the recorded full query has about 3.03 trillion logical bits, approximately
353 GiB packed. This is an input-encoding estimate, not optimizer or ClamAV RAM.
The packed transport needs unpacking into the formal Boolean input; it is not a
published executable solver interface.

The compact view avoids materializing that transport. Its full-query input test
used about 394 MiB resident RAM under a 2 GiB address-space cap:

```sh
(
  ulimit -v 2097152
  ulimit -S -t 110
  ulimit -H -t 115
  timeout 120s python3 tools/compact-memory/search-groundwork/lazy_canonical.py \
    --cnf /private/search-explore/query.cnf --report /tmp/lazy-input.json \
    --random-reads 100000 --run-limit 100000
)
```

Bit access costs `O(log m + k)` using an `O(m)` clause-end index, where `m` is
canonical clause count and `k` is clause width. The original compact formula also
remains resident. A run iterator can skip unary stretches; it does not simulate
or accelerate the published counter's formal trace.

Audit a checkout of the linked project at the pinned revision:

```sh
python3 tools/compact-memory/search-groundwork/linked_counter_audit.py \
  --cnf /private/search-explore/query.cnf \
  --math-source /path/to/openai-math --report /tmp/linked-counter-audit.json
```

The [feasibility report](../../../docs/linked-counter-feasibility.md) explains why
input access is practical but the published parameterization is not: our queries
take its finite fallback, and forcing the large branch violates its proved
parameter conditions. This is not a proof that every high-level adaptation is
impossible, nor an independent Lean proof build.

`run_counter.py` accepts a caller-supplied backend command and validates bounded
responses against the exact input hash and optional oracle count. It records
backend file hashes and timeouts; caller labels do not prove which algorithm
ran. See its `--help` and module protocol. The linked counting construction has
not been extracted or executed by this framework.

## Complexity and reproducibility

```sh
python3 tools/compact-memory/search-groundwork/complexity_metrics.py \
  --source retained-ac=libclamav/matcher-ac.c \
  --source prototype-reader=tools/compact-memory/system-model/probe_field_store.c \
  --output /tmp/source-complexity.json
```

Lexical lines, branch/loop/operator sites and allocator-call sites are maintenance
indicators. They include disabled conditional code and wrappers; they are not
formal cyclomatic complexity, executed instruction counts, or runtime allocation
counts. Compare matching paths against the pinned upstream source; measure a
standalone prototype separately. The published comparison verifies upstream Git
blob hashes for four matched files. Rust is explicitly outside this lexer.

The [published results](../../../docs/search-groundwork-results/README.md) include
actual-capture outcomes, source comparisons, earlier Work16 resource analysis,
canonical length, independent tiny counts, input/source hashes and known gaps.
Raw native data and generated executable field images stay private.
