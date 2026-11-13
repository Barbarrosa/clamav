# Compact integration on upstream ClamAV

`upstream-optimized` tracks upstream ClamAV trunk without committing changes to
upstream-owned source paths. `compact-integration/` holds pinned adaptation
patches, native adapters, optional remote service and release qualification.
The original `compact-memory` research branch remains available.

The materializer archives the exact upstream Git commit, verifies the patch
SHA-256 values and Git blob identities, then applies the queue to a disposable
build tree. This avoids routine source-merge conflicts. An upstream semantic
change can still require adaptation: failed identities block optimized releases
and CI separately validates an unmodified upstream control.

## Build

Use Rust 1.90.0 and the pinned release builder, or install the documented native
dependencies. The website host does not compile this source.

```sh
python3 compact-integration/build.py \
  --output /tmp/clamav-optimized-source --build-dir /tmp/clamav-optimized-build \
  --configure --build --cmake-option MAINTAINER_MODE=ON \
  --cmake-option ENABLE_MILTER=OFF --cmake-option ENABLE_CLAMONACC=OFF
```

Output must be a new disposable directory. `--pristine` creates an upstream
control. The default optimized build enables compact AC IDs/flat transitions and
logical-signature state with the interpreter bytecode runtime. The patch queue
also reduces cold per-pattern state, evidence-key allocation and unused pool
pages. Stable source-occurrence ordering preserves same-position arbitration;
current upstream YARA negation behavior remains intact. Experimental hash and
disposable-pool variants without adequate correctness evidence are excluded.

## Profiles and native interface

`compact-scan` exposes `scan`, `worker`, `prepare`, `self-test`, `doctor`,
`options` and bounded validation. Protocol 1 JSON carries outcome, completion,
original SHA-256/length, exact engine/options/generation and coverage. Callers must
validate the entire record; exit success or an empty detection list is not a
clean decision. Commands require explicit address-space, CPU, wall and scratch
limits. `worker` uses JSONL and resets per-original state while reusing its engine.

The `full` profile retains the full authenticated database. The optional
`pdf-jpeg-png-pe-exclusions` profile removes only eligible PE-specific rules.
It retains generic, effect, dependency, uncertain and custom rules and prepares
a disk-backed rule inventory. Engine-owned sticky guards run before excluded
capability consumers, including missing matcher roots. Cache use is disabled.
Reaching an excluded capability produces a hold, never an unqualified clean.

The correctness contract is equal detections, severity and upload decision when
excluded capabilities are not reached; detection ordering may differ. Guarded
inputs remain non-clean. Qualified relative-coverage evidence is separate from
deployment qualification. This implementation is experimental and has not been
qualified on the actual SiteGround account. See [qualification](qualification/README.md).

`compact-update` runs unprivileged FreshClam directly against original ClamAV
sources, preserving authentication and persistent cooldown state. Downloads,
verification, extraction and CDIFF edit windows stream or spill to disk. Stock
isolated database tests run before profile compilation. A fully validated,
synced generation and its matching authenticated code package are activated
together; failures retain the preceding tuple. Scanning and updating serialize
under the same native lock. See [updates](docs/UPDATES.md).

## Delivery and maintenance

The optional [remote gateway](service/README.md) authenticates requests, streams
originals privately and reuses a bounded native worker. The separate
[WordPress plugin](https://github.com/Barbarrosa/wp-clamav) has no Python dependency.

Daily upstream tracking proposes pin changes and explicitly dispatches
qualification. Actions test native/Rust/parser/guard behavior and a pristine
control, then package matching source, notices, dependencies, SBOM and provenance.
Protected preview/stable promotion signs the exact artifact without rebuilding.
No signing private keys are included; unsigned builds remain development artifacts
and cannot be installed automatically. See [release procedures](release/README.md).
