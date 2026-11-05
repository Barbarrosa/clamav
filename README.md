# ClamAV — compact-memory branch

This development fork reduces ClamAV's memory use and provides tools for testing
further reductions. The normal engine keeps the full signature database; an
optional restricted profile and offline storage experiments are separate paths.

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

- **Smaller matcher and scan-state structures.** Compact transition IDs,
  contiguous nodes, split pattern records and logical tracking sized to each
  rule reduce overhead. Linux can also release unused pool pages while keeping
  allocation addresses intact.
- **Correct handling of weak evidence before a strong match.** AC and
  Boyer–Moore matching continue after nonterminal weak or deferred potentially
  unwanted application (PUA) evidence, addressing the demonstrated case where
  it masked a later strong detection.
- **An optional Legal Redress profile.** Standalone adapters conservatively
  exclude eligible PE-specific rules for a restricted attachment workflow.
  That profile measured **131.1 MiB** compiled resident RAM while loading
  **601,004 signatures** from the same snapshot. It has a narrower rule set and
  an explicit hold policy; see the caveats below.
- **Reproducible optimization research.** Native structure exports, memory
  accounting, regression fixtures and solver models make proposed savings
  inspectable before changing the scanner.

## Caveats

- **This is an experimental 1.6.0 development fork.** Production qualification,
  security-maintenance parity and deployment isolation remain unresolved.
  Read the [readiness review](docs/production-readiness.md) before deployment.
- **Memory and speed depend on the workload.** Construction, concurrent scans,
  reload overlap and full update validation need separate budgets. There is no
  sub-200-MB whole-process guarantee or universal throughput improvement.
- **Detection agreement does not imply identical reporting order.** Exact
  upstream first-name and duplicate-alert order equivalence is not established;
  allocation addresses can affect ties. Order-changing experiments remain
  disabled or archived.
- **Legal Redress is opt-in and does not automatically release clean files.**
  Reduced no-detection results remain held because recursive parser completeness
  is not established. Signature-count reductions are not detection-coverage
  percentages. Full mode remains the default.
- **Solver savings are modeled storage, not measured scanner RAM.** The latest
  624 → 453 MiB result is an offline representation experiment. It is not
  integrated into the engine. RC2 and Minisat ran; the linked Lean counting
  construction was not executed.
- **Private layouts changed.** The public `clamav.h` API remains unchanged,
  but internal consumers and Rust bindings must match this build. Most recorded
  qualification is on 64-bit Linux; it does not establish Windows, macOS or
  32-bit parity.

## What changed under the hood

| Area | Branch behavior | Implementation and evidence |
|---|---|---|
| Aho–Corasick (AC) matcher | Four-byte transition IDs and a contiguous node arena replace native pointer transitions on 64-bit targets. | [Compact engine](docs/compact-resident-engine.md) |
| Pattern records | The common LP64 record shrinks from 136 to 96 bytes; uncommon metadata uses a 48-byte extension. | [Layout and workload limits](docs/compact-resident-engine.md) |
| Logical scan state | Ordinary rules use their validated subsignature count; compatibility-sensitive rules retain 64 slots. Shared offsets replace per-context row-pointer tables. | [State and ownership](docs/demand-engine-implementation.md) |
| Allocation and evidence | Free pool pages can be reclaimed on Linux; borrowed-key lookup avoids allocating duplicate evidence names while preserving the full history. | [Retained strategies](docs/qualified-strategies-implementation.md) |
| Detection selection | Candidate traversal continues after nonterminal evidence; stop, trust and error handling remain explicit. | [Correctness repair](docs/regression-fix-and-memory-frontier.md) |
| Restricted database workflow | Signed inputs are validated in full before generating the optional reduced profile. Local intake records preserve originals and hold incomplete outcomes. | [Selector tools](tools/subset-selector/README.md) and [profile contract](docs/subset-selector-configuration.md) |
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
  `--database-profile=legal-redress` belongs to those adapters, not `clamscan`
  or `clamd`; rebuild generations after changing their probe or library.
- **Investigate further savings:** read the [40 ideas](docs/memory-search-ideas.md),
  [five initial tests](docs/memory-search-five-results.md), then the
  [real-engine solver model](docs/system-model.md). Those reports describe
  different stages and their savings must not be added together.
- **Review rejected implementations:** [archived experiments](experiments/README.md)
  explain why logical sharing and length-bound relocation were not enabled.
- **Use a maintained-release base:** inspect the
  [1.5.4 and 1.4.6 backport patches](docs/boundary-backports.md). These remain
  custom experimental patches requiring their own qualification.

For upstream usage, community information and GPLv2/third-party licensing,
see [README.ClamAV.md](README.ClamAV.md).
