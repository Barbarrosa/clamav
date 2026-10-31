# Demand-loaded engine: implementation and feasibility result

October 27, 2026. Experiment: `5ea56449142cc0e1482226a60651ca53632e655c`.
Default gating: `af776ff5579b85a10173a424c447b97522d6cff5`.

**Subsequent correctness repair:** commit `9c705c5` fixes the demonstrated
weak/PUA masking regression while retaining the compact layouts. See
[the repair and frontier research report](regression-fix-and-memory-frontier.md)
for current validation and further real-database experiments. The measurements
and implementation status below describe the earlier foundation; the fourfold
whole-scanner target remains unmet.

This branch implements shared row offsets, an opt-in construction-pool experiment,
and the full-database feasibility check. It does **not** implement the proposed disk-backed engine.
Gate G0 in [the implementation plan](demand-loaded-engine-plan.md) failed on the
first complete official database tested. The unchanged design cannot meet the
200 MB whole-scanner objective. No SiteGround deployment has been performed.

## Implemented changes

1. **Experimental disposable AC node construction pool.** Opt in with
   `ENABLE_AC_DISPOSABLE_BUILD=ON` and flat node storage enabled. The new option
   defaults to **OFF** because it changes duplicate-alert ordering. In this mode,
   temporary nodes live in a separate pool. Compiling the flat arena remaps the
   failure links and then destroys the construction pool. Transition rows and
   pattern records retain their original resident ownership. The growing node
   index uses ordinary `realloc` and is freed, instead of leaving retired buffers
   in the engine's pool. Candidate links no longer retain unused construction
   node aliases. The default and native/indirect builds retain the reference allocation path.
2. **Shared logical row offsets.** Three flat scan buffers replace three arrays
   of row pointers plus their backing buffers. One engine-owned prefix directory
   replaces the width table. Bytecode, YARA, macros and byte-compare keep their
   compatibility widths; counts, sentinels, offsets and evaluation order are
   unchanged by the row-offset replacement. The legacy private initializer uses an implicit 64-slot stride.
   A directory too large for 32-bit offsets falls back to that legacy stride;
   no identifier is truncated. Scan state borrows the directory for the existing
   engine lifetime.
3. **C/Rust dependency correctness.** Regenerated bindings and the ABI checker
   cover the new fields. CMake now includes C headers in the Rust build's
   dependencies, and bindgen tracks transitive headers. A header-only edit must
   not silently reuse bindings compiled for an old layout.
4. **Reproducible evidence tools.** `fetch_container_database.py` retrieves a
   digest-pinned official container layer without running it; `engine_census.c`
   counts compiled structures and exact distinct names; `assess_floor.py`
   rejects an impossible resident boundary. These are diagnostic tools, not a
   new engine format or substitute signature verifier.

No new scan-time algorithm, cache, prediction policy, parser, signature filter,
public API or resource limit was added. Candidate verification is unchanged;
the allocation experiment nevertheless changes address-based tie breaking, as
described below. This is why its memory saving is not enabled by default.

## Full database and trust

The direct database CDN returned HTTP 403. The test obtained main, daily and
bytecode CVDs from the official `clamav/clamav` image, pinned to the linux/amd64
manifest in [database provenance](demand-results/database-provenance.json).
The downloader checked the manifest and layer SHA-256 digests. Separately,
ClamAV's normal `sigtool --info` verification passed on all three CVDs, and
`cl_load(..., CL_DB_STDOPT)` succeeded with the original trust checks enabled.

| Database | Version | Header signature count |
| --- | ---: | ---: |
| main | 63 | 3,287,027 |
| daily | 28164 | 355,788 |
| bytecode | 339 | 80 |

The active engine reports **3,628,192 loaded signatures**. Header counts are not
a substitute for the loader's active count. Both reference builds and this build
report the same loaded count. The database is a reproducible snapshot, not a
promise that a future update has the same composition or memory requirements.

## Gate G0: failed resident budget

These are requested payload bytes from the compiled engine, not extrapolations
from the earlier synthetic test. The census runs against matching headers and
library. Its temporary name-sort buffer is diagnostic memory and is not counted
as engine memory.

| Data retained by the planned boundary | Bytes | MiB |
| --- | ---: | ---: |
| AC transitions, nodes and prefilters | 92,682,712 | 88.39 |
| Unique stable names, after ideal exact interning | 87,171,124 | 83.13 |
| Current logical-rule records and their pointer directory | 54,966,560 | 52.42 |
| **Subtotal** | **234,820,396** | **223.94** |

The subtotal alone exceeds both 200 decimal MB and 200 MiB. It excludes the
cold-block cache, code/runtime, allocator rounding, input/parser state, logical
expression and target metadata payloads, regex/bytecode and other compatibility
objects, build scratch, and kernel file cache. This is a lower bound for the
specified resident layouts, **not an information-theoretic limit on ClamAV**.

Even eliminating the logical descriptors entirely would leave **179,853,836
bytes** of routing and stable names; adding the proposed 48 MB cache gives
227,853,836 bytes before runtime and scan state. Two unshared resident generations
at reload require at least 469,640,792 bytes for the three measured categories,
before the shared cache or builder. Reducing cache size alone cannot repair all
of these lifecycle constraints.

The proposed cold payload is substantial: candidates account for 72,957,408
bytes, pattern records/extensions/tokens for 248,057,570 bytes, and hash
records/references/directories for 89,339,132 bytes. These counts explain why
paging could still reduce RAM. They do not establish a sub-200 MB engine.

Exact name interning would save only **448,089 bytes** in the measured name set:
3,547,706 names are distinct. It cannot provide the large remaining reduction.
Boyer–Moore and other names omitted by this census can only increase the lower
bound; the tool does not claim a complete allocation ledger.

Raw counts: [census.jsonl](demand-results/census.jsonl).
Budget arithmetic: [resident-floor.json](demand-results/resident-floor.json).
The assessor exits 1 for a blocked budget; a smaller subtotal remains
inconclusive because the omitted components still need measurement.

## A small but important row-directory tradeoff

There are 312,310 logical rules across the targets. Removing three 8-byte row
pointers saves **24 bytes per active rule per scan context**. The shared directory
adds roughly 3 bytes per rule versus the previous one-byte width table, or about
0.89 MiB once per engine. It is not a free reduction on every workload.

For generic + PDF matching, 7,075 active rules save approximately 0.162 MiB of
scan-local pointer tables. The permanent directory costs more than that for a
single such scan; the optional disposable-node change supplies the experimental resident saving.
The default therefore does not establish an additional RAM reduction for a
single-PDF deployment.
For generic + PE matching, 300,118 active rules save approximately 6.87 MiB per
context before subtracting the shared-directory increase. Nested/concurrent
contexts change the balance. Do not add these component calculations to an RSS
measurement that already includes them.

## Alert-order gate: experiment failed, default protected

A new differential fixture interleaves 10,000 duplicate wildcard signatures with
10,000 unrelated signatures. All builds report the same 10,000 distinct matching
names and the same 20,000 all-match output lines. However, the existing `sort_list_fn` and
`sort_heads_by_partno_fn` use allocation addresses as their last tie breaker.
Moving construction allocations changes those addresses.

| Build | First reported custom signature |
| --- | --- |
| Untouched upstream | `Foundations.Order.09958.UNOFFICIAL` |
| Previous compact fork | `Foundations.Order.09884.UNOFFICIAL` |
| Disposable-pool experiment, commit `5ea5644` | `Foundations.Order.09901.UNOFFICIAL` |
| Delivered default, experimental pool OFF | `Foundations.Order.09884.UNOFFICIAL` |

The default matches the previous compact fork's **entire ordered sequence** in
this fixture, as well as its first-alert selection. The experiment does not.
The test also exposes a pre-existing difference between the previous compact
fork and untouched upstream. Thus neither the earlier fork nor this branch is
qualified for the plan's strict upstream name/order equivalence requirement.
The original all-strong fixture showed a labeling/order difference without a
missed detection. That result did not establish functional equivalence for
mixed indicator categories. The follow-up below demonstrates missed strong
detections, including a clean result, and supersedes any broader interpretation.

Do not hide the difference by comparing only sorted detection sets. The test
records both ordered and multiset digests in
[alert-order.json](demand-results/alert-order.json), and can enforce the default
comparison:

```sh
python3 tools/compact-memory/check_alert_order.py \
  --clamscan build/clamscan/clamscan \
  --library compact=../build-previous-compact/libclamav \
  --library default=build/libclamav --expect-equal compact=default \
  --output ../alert-order-results
```

A deterministic tie policy would require an explicit compatibility decision;
substituting one silently would not preserve the observed upstream behavior.
The opt-in flag is a temporary experimental gate, not an additional shipping
cache policy.

### Follow-up: ordering can change detection, not only labeling

Harmless custom signatures reproduce a functional regression. Each database
contains 10,000 signatures matching the same marker plus 10,000 nonmatching
distractors. Exactly one matching signature is a normal strong indicator; the
others use either `Weak.` or `PUA.` names. Name lengths and patterns are held
constant. PUA detection is enabled and heuristic precedence is disabled.

With the strong signature at index 9958, first-match results are:

| Other matching indicators | Upstream | Previous compact | Delivered default | Pool experiment |
| --- | --- | --- | --- | --- |
| Weak | Strong FOUND, exit 1 | OK, exit 0 | OK, exit 0 | OK, exit 0 |
| PUA | Strong FOUND, exit 1 | PUA FOUND, exit 1 | PUA FOUND, exit 1 | PUA FOUND, exit 1 |

Moving the strong signature to index 9884 reverses upstream versus the default:
the compact/default builds find it, while upstream and the pool experiment
report OK for the Weak case or only PUA for the PUA case. Thus upstream already
has an order-sensitive path; the allocation changes alter which inputs it
affects. Disabling the disposable pool does not resolve the earlier compact
fork's difference from upstream. These are custom-rule counterexamples, not a
measurement of missed malware in the official database or a claimed attack on
a deployed installation.

The AC comparators in `libclamav/matcher-ac.c` use pattern addresses as final
tie breakers. In first-match mode, `cli_ac_scanbuff` returns a candidate before
`cli_append_virus` classifies its name. `matcher_run` in `libclamav/matcher.c`
does not resume the AC walk after a weak or deferred PUA result. The evidence
layer prefers strong evidence when collected, but that cannot recover a
strong candidate that was never examined. Weak indicators intentionally do
not alert on their own.

All-match mode finds the strong signature in every tested combination. It is
a demonstrated mitigation for these fixtures, not an established substitute
for a correctness fix: time, memory, callbacks, scan limits and adversarial
behavior still need qualification. A fix must continue candidate evaluation
after a nonterminal result, including callback-suppressed hits, while preserving
logical-signature accounting, false-positive handling and existing scan limits.
Changing tie breaking or sorting by apparent severity alone is insufficient.

Reproduce with the same four libraries used above:

```sh
python3 tools/compact-memory/check_alert_severity.py \
  --clamscan ../build-compact/clamscan/clamscan \
  --library upstream=../build-baseline/libclamav \
  --library compact=../research/resident-reference/libclamav \
  --library experimental=../research/experimental-reference/libclamav \
  --library default=../build-compact/libclamav \
  --strong-index 9958 --strong-index 9884 \
  --output ../alert-severity-results
```

The diagnostic records three fresh-process first-match runs and one all-match
run per combination. It can enforce a strong-detection gate with
`--require-strong default`; without that option it reports counterexamples
without making its exit status a correctness verdict. The measured results are
in [alert-severity.json](demand-results/alert-severity.json).

This finding is an additional deployment blocker. No scanner fix or deployment
change is included in this follow-up; the change records the regression and
corrects the earlier interpretation.

## Validation and measured footprint

The full-database measurement is a clean small input, with all parsers and all-match enabled
and the clean-file cache disabled. Its observed process peak is not a proven
worst-case scan, reload, update, nested parser, or cgroup peak. No unchanged-speed
or complete attacker-resilience qualification is claimed from this experiment.

Three fresh processes per build, serial randomized order, on the same host.
Each process loads the full database, compiles it, and scans the same 4 KiB
clean input three times. All 12 runs load 3,628,192 signatures and return clean.
These means describe repetitions of one probe, **not the average WordPress
workload**. Sample maxima are **not worst-case bounds**.

| Build | Mean compiled RSS (MiB) | Compiled RSS range (MiB) | Maximum reported process high-water RSS (MiB) |
| --- | ---: | ---: | ---: |
| Untouched upstream | 958.57 | 958.51–958.61 | 958.38 |
| Previous compact fork | 824.28 | 824.20–824.42 | 824.83 |
| Delivered default, pool OFF | 824.64 | 824.10–824.91 | 825.43 |
| Opt-in pool experiment (`5ea5644`) | 808.17 | 808.07–808.23 | 824.68 |

RSS comes from `/proc/self/status`; high-water RSS comes from `getrusage`.
The kernel's independently maintained counters differ by fractions of a MiB in
some runs, so the table reports them without forcing one to exceed the other.
The raw measurements are in [official-memory.json](demand-results/official-memory.json).
Compiler comments confirm GCC 13.3 and Rust 1.90.0 for all four libraries. The
bytecode runtime in this comparison is the interpreter, matching the references.

The opt-in experiment removes about **16.1 MiB (2.0%)** of compiled RSS relative
to the earlier compact fork. It does not materially reduce the observed loading
peak, which remains about 825 MiB. The default provides no measured additional
resident reduction on this probe. Neither is a 200 MB implementation, and these
numbers exclude WordPress and whole-cgroup filesystem-cache accounting.

The experimental synthetic comparison uses 30 randomized pairs for each of
three cases (180 fresh-process observations). The large clean case has a
compiled-RSS ratio of **0.948** versus the previous compact fork. Its scan-time
ratio is **0.972**, with a paired bootstrap 95% interval of **0.827–1.139**.
That interval crosses the predeclared 1.00 boundary: unchanged speed is **not
established**. The detected-marker case improves in this test, but cannot
establish a general speedup or adversarial-performance guarantee. These results
apply to experiment `5ea5644`, not to the guarded default.
Raw data: [experimental-synthetic.json](demand-results/experimental-synthetic.json).

| Validation | Result and scope |
| --- | --- |
| Final default (`af776ff`) C suite | 1,785 checks passed. |
| Final default Rust suite | 65 tests passed. |
| Final default scanner integration | 145 tests + 5 subtests passed; 1 existing skip. |
| Alert ordering | Default equals previous compact fork for first alert and full ordered sequence in the 20,000-rule fixture; experiment and upstream differ as described above. |
| Experiment (`5ea5644`) default/native C suites | 1,785 checks passed in each configuration. |
| Experiment (`5ea5644`) ASan/UBSan | Matcher and regex suites passed with the pool disabled and leak detection disabled due to environment limits. This is not a sanitizer result for every ClamAV parser. |
| C/Rust ABI | Affected sizes and offsets agree in default and native builds. Gating changes no record layouts. |
| Experimental flag ON | The gated matcher compiles with the flag enabled. Full experimental runtime/sanitizer measurements are from the preserved pre-gating commit `5ea5644`. |

The CI matrix includes the opt-in configuration; no GitHub CI run is claimed.
No cache, concurrent-generation, bounded-update, full adversarial or SiteGround
qualification has been completed. The existing daemon/updater environment
limitations remain documented in [compact-validation.md](compact-validation.md).


## Reproduce

Build the pinned upstream base `dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`, the
previous compact fork `d352706f40d1cb5a3213b8f8fc69c6030582bdd7`, and this branch
with the same configuration and toolchain. This comparison uses GCC 13.3 and
Rust 1.90.0; pin `RUSTUP_TOOLCHAIN=1.90.0` instead of a moving `stable` toolchain.
Use the build instructions in [compact-resident-engine.md](compact-resident-engine.md).

```sh
python3 tools/compact-memory/fetch_container_database.py \
  --manifest sha256:4a97d36895b9aa116c8db42c3dd701e7a713f7c3c3aea15a11006644f55c1d3c \
  --layer 6 --output ../official-database
sigtool --info ../official-database/main.cvd --cvdcertsdir=certs
sigtool --info ../official-database/daily.cvd --cvdcertsdir=certs
sigtool --info ../official-database/bytecode.cvd --cvdcertsdir=certs

cc -DHAVE_CONFIG_H -Ibuild -Ibuild/libclamav -Ilibclamav \
  -Ilibclamunrar_iface -Ilibclammspack \
  -I/usr/include/json-c -I/usr/include/libxml2 \
  tools/compact-memory/engine_census.c \
  -Lbuild/libclamav -Wl,-rpath,"$PWD/build/libclamav" -lclamav \
  -o build/engine-census
build/engine-census ../official-database certs > census.jsonl
python3 tools/compact-memory/assess_floor.py census.jsonl --budget-mb 200
```

Use the same generated configuration and library as the headers: this is an
internal layout census, not a public-ABI probe. Include paths depend on the
installed dependencies. The original `engine_bench.c` uses public APIs and can
compare the three libraries without internal-layout assumptions. The supplied
`measure_database.py` runs that probe in a randomized serial sequence:

```sh
python3 tools/compact-memory/measure_database.py \
  --build upstream=../build-baseline \
  --build compact=../build-previous-compact \
  --build foundations=build \
  --database ../official-database --input path/to/test-input \
  --output ../official-memory-results --rounds 3 --iterations 3
```

A frozen reference build must include `CMakeCache.txt`, `clamav-types.h`,
`clamav-version.h` and its library/symlinks; retain or reproduce its required
shared dependencies too. For the synthetic comparison against the prior compact
fork, use `compare.py --baseline-slots 4 --baseline-revision d352706f40d1cb5a3213b8f8fc69c6030582bdd7`
along with the usual build/output flags. Upstream uses the default 64 slots.

## What remains, and why

No engine store/cache, image writer, candidate/hash paging, eager prefetch,
bounded compiler, or generation reload path is implemented in this branch.
The feasibility gate required a credible resident boundary before those changes.
The failed lower bound makes the unchanged plan unsuitable for the stated target;
continuing it would add substantial complexity without satisfying that objective.

A revision would need to change the memory boundary itself—for example,
demand-loading some type-specific routing/metadata, revisiting how stable result
names are provided, or sharing immutable data across generations—or change the
memory/lifecycle requirement. Each needs its own correctness and adversarial
latency argument. The present measurements do not prove any such redesign.

The delivered foundation remains useful and reviewable, but it is not a completed
low-memory fork, a production release, or a SiteGround-ready scanner. Ordinary
scan measurements alone cannot establish hosting suitability or preserve update
availability. No live WordPress configuration has been changed.
