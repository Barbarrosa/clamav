# ClamAV — compact-memory branch

This development fork reduces ClamAV's memory use and provides tools for testing
further reductions. The normal engine keeps the full signature database; an
optional profile is limited to PDF, JPEG and PNG files while excluding eligible
Windows-executable rules. Research tools explore further savings separately.

ClamAV's project overview, installation links and licensing are preserved in
[the ClamAV README](README.ClamAV.md).

## Benefits

**Lower memory use with the full database.** The controlled Linux comparison
on 29 October 2026 loaded the same **3,628,192 signatures** in both engines:

| Measurement | Original ClamAV | This branch, full database |
|---|---:|---:|
| Compiled engine resident RAM, mean | 959.6 MiB | **791.2 MiB** |
| Two-engine reload peak resident RAM | 1,916.1 MiB | **1,613.2 MiB** |

That is about **17.5% less resident RAM** after compilation. The comparison used
a pinned upstream development revision and signed database snapshot, not the
latest ClamAV release or a universal memory limit. See the
[measurements, workloads and reproduction details](docs/three-way-performance.md).

Other useful changes and tools include:

- **Less space spent on bookkeeping.** The engine uses shorter references,
  smaller common records and fewer unused tracking slots. On Linux it can also
  return unused memory pages to the operating system.
- **A detection-selection fix.** A weak or deferred alert no longer stops the
  demonstrated search path before it can find a later strong detection.
- **An optional PDF/JPEG/PNG profile with PE exclusions.** This excludes
  eligible rules specific to Windows executables (the PE file format).
  That profile measured **131.1 MiB** compiled resident RAM while loading
  **601,004 signatures** from the same snapshot. It has a narrower rule set and
  an explicit hold policy; see the caveats below.
- **Checkable research results.** Tools capture the real engine's data, search
  for smaller ways to store it, and check that every original value can be
  recovered. The research explanation below separates this from running RAM.

## Caveats

- **This is an experimental 1.6.0 development fork.** Production qualification,
  security-maintenance parity and deployment isolation remain unresolved.
  Read the [readiness review](docs/production-readiness.md) before deployment.
- **Memory and speed depend on the workload.** Construction, concurrent scans,
  reload overlap and full update validation need separate budgets. There is no
  sub-200-MB whole-process guarantee or universal throughput improvement.
- **The same detections can be reported in a different order.** Identical
  first labels and duplicate-alert order are not established for every case.
  Some experiments failed this requirement and remain disabled or archived.
- **The restricted profile is opt-in and does not automatically clear files.**
  Reduced no-detection results remain held because recursive parser completeness
  is not established: a file may contain embedded material the scanner has not
  fully examined. Loading fewer rules is not a measurement of how much malware
  can still be detected. Full mode remains the default.
- **Research savings have not yet become scanner RAM savings.** The smaller
  storage model described below is not integrated into the engine.
- **Private layouts changed.** The public `clamav.h` API remains unchanged,
  but internal consumers and Rust bindings must match this build. Most recorded
  qualification is on 64-bit Linux; it does not establish Windows, macOS or
  32-bit parity.

## Research results in plain language

The research asks: **can we store the engine's information more efficiently
without losing any of it?** This is separate from reducing the set of rules.

For example, two fields might contain the same pattern length almost everywhere.
Instead of storing both complete lists, we can store one list and the exceptions.
A solver is an automatic chooser: it searches combinations of such decisions
while enforcing exact answers and a limit on the work needed to read a value.

The latest experiment used a real compiled engine with 3.6 million signatures.
For the parts of the engine it accounted for, it built a representation of about
**453 MiB instead of 624 MiB: 27.45% smaller**. Checks recovered all **75 million
field values** exactly. This does **not** mean the running scanner now uses
453 MiB. It is the size of the counted data and its supporting indexes; other
allocations remain outside the model, and the scanner still uses its existing
representation. This saving must not be added to the measured 17.5% RAM reduction
above.

There is a tradeoff: a prototype reader needed about **69% more CPU time** to
read pattern fields from the smallest layout in a small artificial benchmark.
Whole-scanner speed and memory remain to be measured after integration. The
useful result is a tested opportunity for further savings, rather than a finished
engine improvement.

The executed solvers were ordinary **RC2 and Minisat**. The newer mathematical
counting algorithm that prompted the investigation was **not executed**, and no
speed advantage for it has been demonstrated. The repository includes the
Boolean formulas—true/false constraints describing the storage choices—so other
solvers can be tried on the same problem.

Read the [plain-language findings](docs/system-model.md) for the results and
limits, or the [technical evidence and reproduction guide](docs/system-model-results/README.md)
for the actual formulas, assignments and checks. Earlier work lists
[40 ideas](docs/memory-search-ideas.md) and [five small initial experiments](docs/memory-search-five-results.md);
those small examples are not whole-engine memory measurements.

## What changed under the hood

| Area | Branch behavior | Implementation and evidence |
|---|---|---|
| Aho–Corasick (AC) matcher | Four-byte transition IDs and a contiguous node arena replace native pointer transitions on 64-bit targets. | [Compact engine](docs/compact-resident-engine.md) |
| Pattern records | The common LP64 record shrinks from 136 to 96 bytes; uncommon metadata uses a 48-byte extension. | [Layout and workload limits](docs/compact-resident-engine.md) |
| Logical scan state | Ordinary rules use their validated subsignature count; compatibility-sensitive rules retain 64 slots. Shared offsets replace per-context row-pointer tables. | [State and ownership](docs/demand-engine-implementation.md) |
| Allocation and evidence | Free pool pages can be reclaimed on Linux; borrowed-key lookup avoids allocating duplicate evidence names while preserving the full history. | [Retained strategies](docs/qualified-strategies-implementation.md) |
| Detection selection | Candidate traversal continues after nonterminal evidence; stop, trust and error handling remain explicit. | [Correctness repair](docs/regression-fix-and-memory-frontier.md) |
| Restricted database workflow | The `pdf-jpeg-png-pe-exclusions` profile accepts PDF/JPEG/PNG root files, skips eligible PE-specific rules and reports all matches. Preparation validates signed inputs in full; originals are preserved and incomplete outcomes remain held. | [Selector tools](tools/subset-selector/README.md) and [profile contract](docs/subset-selector-configuration.md) |
| Offline field synthesis | A solver chooses how native fields are stored or derived, then reconstructs every captured value to check the answer. | [Plain-language result](docs/system-model.md) and [formulas and reproduction](docs/system-model-results/README.md) |

The runtime still uses ClamAV's matching and full-pattern verification paths.
The default memory changes add no scan-time rule paging or solver dependency.

## Build and compare

Install the [normal ClamAV build dependencies](INSTALL.md), then build from
the repository root:

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_TESTS=ON \
  -DENABLE_MAN_PAGES=OFF \
  -DCVD_CERTS_DIRECTORY="$PWD/certs"
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The certificate path is for running from the source/build tree. Installed
deployments need the installed certificate directory. Keep signature verification
enabled when comparing engines.

These branch-specific CMake options make the layouts easy to compare:

| Option | Default | Purpose |
|---|---|---|
| `ENABLE_COMPACT_LSIG_STATE` | `ON` | Size ordinary logical tracking to the rule; `OFF` uses full-width rows. |
| `ENABLE_AC_NODE_IDS` | `ON` | Use compact transitions; `OFF` selects native pointers. |
| `ENABLE_AC_FLAT_NODES` | `ON` | Locate nodes by arena arithmetic when IDs are enabled; `OFF` uses indirect IDs. |
| `ENABLE_FLAT_HASH_STORE` | `OFF` | Experimental contiguous hash storage; its higher construction peak remains a concern. |
| `ENABLE_AC_DISPOSABLE_BUILD` | `OFF` | Experimental separate construction pool; it changes duplicate-alert ordering. |

Use separate build directories with the same database, dependencies and scan
options for comparisons. The [compact-engine guide](docs/compact-resident-engine.md)
includes ABI checks and comparison commands; the
[three-way report](docs/three-way-performance.md) distinguishes process RAM,
file-page caches, scan timing and reload costs.

## Where to go next

- **Work on the engine:** start with [compact layouts](docs/compact-resident-engine.md)
  and [retained allocation improvements](docs/qualified-strategies-implementation.md).
- **Try the restricted workflow:** follow the [selector setup](tools/subset-selector/README.md).
  Use `--database-profile=pdf-jpeg-png-pe-exclusions` on those adapters, not on
  `clamscan` or `clamd`. The name describes file types and rule exclusions,
  rather than an application. Generic and uncertain rules remain; finding
  embedded PE content still holds the file. Regenerate prepared generations
  after this rename or after changing the probe or library. See the
  [naming and migration note](docs/subset-selector-configuration.md#configuration).
- **Review rejected implementations:** [archived experiments](experiments/README.md)
  explain why logical sharing and length-bound relocation were not enabled.
- **Use a maintained-release base:** inspect the
  [1.5.4 and 1.4.6 backport patches](docs/boundary-backports.md). These remain
  custom experimental patches requiring their own qualification.

For upstream usage, community information and GPLv2/third-party licensing,
see [README.ClamAV.md](README.ClamAV.md).
