# Allocation-padding evidence

Read the [plain-language findings](../allocation-perturbation.md) first. This
experiment intentionally adds RAM to locate sensitive allocations. Its results
are not measured savings or proof of unnecessary memory.

## Studies

| Study | Fresh processes | Files scanned per process | Purpose |
|---|---:|---:|---|
| Screen | 28 | 9 | Twelve groups at +8/+32 bytes, three interleaved zero controls and an ordinary retained-branch control |
| Confirmation | 16 | 9 | Names, candidates, patterns and nodes at zero/+32, two repeats with separate controls |
| Reload | 7 | 163 | Names, candidates and patterns at zero/+32, plus an ordinary control; two complete engines overlap |

All **51 processes** completed and all **1,537 scan records** matched their
corresponding controls, including captured callback order. All loaded engines
reported **3,628,192 signatures**. None exhausted its padding cap. The primary
engine is scanned; replacement engines are loaded, compiled and freed without
being scanned. These observations do not establish all-input equivalence.

The `stock` variant in raw files means the ordinary **retained branch**, not an
upstream ClamAV build. No upstream performance comparison is claimed here.

## Files

- [summary.json](summary.json): combined study status and the main numerical results.
- Screen: [plan](screen-plan.json), [summary](screen-summary.json),
  [independent audit](screen-audit.json), [complete raw records](screen-raw.tar.gz).
- Confirmation: [plan](confirm-plan.json), [summary](confirm-summary.json),
  [independent audit](confirm-audit.json), [complete raw records](confirm-raw.tar.gz).
- Reload: [plan](reload-plan.json), [summary](reload-summary.json),
  [independent audit](reload-audit.json), [complete raw records](reload-raw.tar.gz).
- [pool-classes.json](pool-classes.json): source-bound fixed-record class arithmetic
  using the earlier [full-engine capture summary](../system-model-results/summary.json).
- [build-provenance.json](build-provenance.json): measured engine source hashes,
  toolchain/options, artifact hash and 81 explicitly tagged source sites.
- [default-off-verification.json](default-off-verification.json): normal-build
  verification after the experiment, with [raw output](default-off-raw.tar.gz).
- [validation.json](validation.json): test results, source identities and resource scope.
- [measured-sources.tar.gz](measured-sources.tar.gz): measured engine and harness
  sources, for reproducing source identities without relying on later changes.
- [artifacts.json](artifacts.json): published file sizes and SHA-256 values.

The raw archives include each study's original `plan.json`, `summary.json`, audit,
stdout JSONL, stderr, padding snapshots and process outcomes. They contain no
signature databases, raw native captures or compiled binaries.

After measurement, the ordinary engine was rebuilt with the option OFF. No
perturbation symbols remained; injection environment settings were ignored and
nine additional scan transcripts matched the ordinary control. That rebuilt
library has a different binary hash from the preserved control; no byte-for-byte
or all-platform identity is claimed.

## Reproduce

Use the [tool guide](../../tools/compact-memory/allocation-perturbation/README.md)
to build ordinary and `ENABLE_MEMORY_PERTURB=ON` engines with matching toolchains,
dependencies and other options. The normal default is **OFF**. This harness
currently requires Linux. Both matching unrar modules must load.

Prepare the nine-file screen with `prepare_corpus.py --per-group 3`. Prepare the
full 163-file corpus with `--per-group 1000`. Both selections come from the same
published archive and are checked against its fixture manifest. The plans bind
database, certificate, fixture, executable, library and relevant source hashes.

The exact study options, in addition to the common paths in the tool guide, were:

```sh
# Screen: all twelve groups.
--doses 0 8 32 --repetitions 1 --zero-controls 3 --seed 20261106

# Confirmation: paired controls, no extra ordinary-build process.
--groups names candidates patterns nodes --doses 0 32 \
  --repetitions 2 --seed 20261107

# Reload: full corpus, paired controls, plus ordinary-build process.
--groups names candidates patterns --doses 0 32 \
  --repetitions 1 --reload --seed 20261108
```

Runs were serial and pinned to CPU 0. Every process had a 4 GiB address-space
limit, CPU limits of 120/125 seconds and a 150-second wall timeout. Padding was
capped at 512 MiB of cumulative successful requests. A cap refusal is an allocation
failure, not a complete smaller dose. The full-corpus reload cases took roughly
66–70 seconds each on this environment.

To independently check a published raw study, extract it into a fresh directory
and run:

```sh
python3 tools/compact-memory/allocation-perturbation/audit_results.py \
  --results /tmp/extracted-study --report /tmp/rechecked-audit.json
```

The audit checks actual raw bytes against their hashes and ordered scan inputs
against the plan, then reconstructs semantics comparisons and summary arithmetic.
It does not authenticate a dishonest reporter or prove complete instrumentation.

## Scope limits

The padding dose is per allocation request, including reallocations, rather than
per object in a bulk array. Counters accumulate over time and do not track live
injected bytes. RSS deltas must not be divided by cumulative padding to claim
physical amplification. Pool carved extent includes freed fragments; neither it
nor mapped extent is live payload or an RSS substitute.

The screen has one observation per nonzero cell. Confirmation has two paired
repeats for selected groups; reload has one paired observation per group. There
are no confidence intervals or no-regression guarantees. Scan-state sensitivity
depends on corpus and concurrency, and allocator plateaus can mask existing
rounding overhead. The class examples are modeled charges on a historical capture,
not implemented allocator changes or measured savings.
