# Three-way performance and cache experiment

These tools compare the original pinned ClamAV engine, the retained full engine,
and the retained PDF/JPEG/PNG with PE exclusions profile on the same machine, database and files.
They are measurement tools, not an upload service or a release authorization.
See [the measured report](../../../docs/three-way-performance.md).

The restricted variant is named `pdf-jpeg-png-pe-exclusions`: PDF, JPEG and PNG
root files, conservative exclusion of eligible PE-specific rules, and accepting
all-match scanning. Generic, uncertain and effect-bearing rules are retained;
the name does not mean all PE-related rules are removed. Executable content and
reduced no-detection candidates remain held by the adapter's existing policy.

New runs and summaries use this descriptive name. The readers also accept the
historical variant label in archived plans, process records and summaries,
normalizing only report keys and displayed labels. They never rename raw files,
change measurements, or rewrite the commands and hashes recorded at run time.
Regenerate prepared database generations with the renamed adapter, and use a
fresh results directory rather than resuming an old-label matrix.

## Build and identify the engines

Build upstream commit `dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d` and the
archive's retained engine with the same toolchain and these CMake settings:

```sh
cmake -S SOURCE -B BUILD -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON -DENABLE_MAN_PAGES=OFF \
  -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF -DENABLE_SYSTEMD=OFF \
  -DENABLE_UNRAR=ON -DMAINTAINER_MODE=ON
cmake --build BUILD --parallel 3
```

The recorded experiment used GCC 13.3, Rust 1.90.0, CMake 4.4.4, Ninja 1.13.2,
Ubuntu development packages and interpreter bytecode mode. Full CMake caches,
compiler descriptions and artifact hashes are in the result provenance.
The recorded cargo settings were `CARGO_BUILD_JOBS=3`,
`CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`, and
`CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_CODEGEN_UNITS=1`.
Enable pytest before CMake test discovery. MAINTAINER_MODE regenerates Rust
bindings; the exact generated diffs are recorded. They change comments/name/type
spelling and definition order without changing the ABI or scanner algorithms.

Compile **the same** `performance_probe.c` against each library. For example,
from this archive's `source/`, with installed json-c/OpenSSL development headers:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -Ilibclamav -I../build-fork $(pkg-config --cflags json-c openssl) \
  tools/subset-selector/performance/performance_probe.c \
  -L../build-fork/libclamav \
  -Wl,-rpath,"$PWD/../build-fork/libclamav" \
  -lclamav $(pkg-config --libs json-c openssl) -ldl -o ../perf-fork

cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I../upstream/libclamav -I../build-upstream $(pkg-config --cflags json-c openssl) \
  tools/subset-selector/performance/performance_probe.c \
  -L../build-upstream/libclamav \
  -Wl,-rpath,"$PWD/../build-upstream/libclamav" \
  -lclamav $(pkg-config --libs json-c openssl) -ldl -o ../perf-upstream
```

The harness includes the delivered policy/loader callbacks from `scan_probe.c`.
Do not change those callbacks, flags, library or probe during a matrix. The driver
adds the matching `libclamunrar_iface` and `libclamunrar` build directories to each
child's runtime library search path. Both modules must be present in the process
maps after `cl_init`; a missing module aborts the run. Module hashes are recorded.

## Prepare the exact input

Use `tools/compact-memory/fetch_container_database.py` with manifest
`sha256:4a97d36895b9aa116c8db42c3dd701e7a713f7c3c3aea15a11006644f55c1d3c`,
layer 6. Verify the three SHA-256 values in the recorded environment JSON.
The snapshot is main 63, daily 28164, bytecode 339. Build the normal `scan_probe`
and run `select_db.py` as documented in [the adapter instructions](../README.md).
Use a new generation directory. Generation preparation performs mandatory full
load validation and has its own memory budget.

The result directory's `corpus.tar.gz` contains all exact synthetic benchmark
bytes, including 28 distinct accepted inputs, 89 harmless upstream test payloads
and 46 adverse/mixed fixtures. It has no private evidence or real submissions.
Unpack it in a private benchmark directory. Its `manifest.json` maps groups to
members, original source paths, byte sizes and SHA-256. Create each file list in
the recorded order, using absolute paths in your extracted corpus directory:

```python
import hashlib, json
from pathlib import Path
corpus = Path('../corpus').resolve()
manifest = json.loads((corpus / 'manifest.json').read_text())
for group, entries in manifest.items():
    paths = []
    for entry in entries:
        path = corpus / entry['member']
        assert path.stat().st_size == entry['bytes']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256']
        paths.append(str(path))
    Path('../' + group + '.txt').write_text('\n'.join(paths) + '\n')
```

The accepted corpus deliberately has 28 unique hashes. One generated renamed PDF
was made distinct from `clean.pdf`, preventing a first-pass result-cache hit from
a duplicate input. The exact changed bytes are included. No evidence file was
edited. Do not benchmark private submissions or share paths containing secrets.

## Run the complete serial matrix

Run on an otherwise idle host. Do not run compiles, tests or parallel benchmarks
at the same time. Use private copies of the database and inputs: the driver
evicts only those file pages, using `fsync` and `POSIX_FADV_DONTNEED`; it never
uses global `drop_caches`. Linux `mincore`, `smaps_rollup` and process maps must
be available. A cache-residency mismatch aborts the process.

```sh
python3 tools/subset-selector/performance/run_matrix.py \
  --upstream-probe ../perf-upstream --fork-probe ../perf-fork \
  --upstream-lib ../build-upstream/libclamav/libclamav.so.14.0.0 \
  --fork-lib ../build-fork/libclamav/libclamav.so.14.0.0 \
  --upstream-freshclam ../build-upstream/libfreshclam/libfreshclam.so.4.0.0 \
  --fork-freshclam ../build-fork/libfreshclam/libfreshclam.so.4.0.0 \
  --generation ../generation --certs certs \
  --fixtures ../accepted.txt --positive ../positive.txt --adverse ../adverse.txt \
  --output ../results --rounds 5 --lifecycle-rounds 3 --repetitions 3 --cpu 0
```

Choose an allowed CPU if CPU 0 is unavailable. `--resume` reuses only completed
successful outputs whose command, probe and stdout hashes match. It is for an
interrupted identical experiment, not changed source/options/runtime modules.
Start a fresh output directory after any such change. The raw logs retain ordered
callbacks, hashes, CPU/user/system times, block I/O and memory snapshots.

The 78 processes comprise 30 primary runs, 15 clean-result-cache diagnostics,
27 reload/update tests, and six positive/adverse correctness runs. One primary
process has a fresh engine, one empty-input-cache scan and three hydrated scans.
One diagnostic process has metadata off, an enabled initially empty result cache,
and three subsequent batches verified to hit all 28 root entries. This diagnostic
does not change adapter evidence or release policy.

## Validate, summarize and render

```sh
python3 tools/subset-selector/performance/summarize.py \
  --results ../results --output ../summary.json
python3 tools/subset-selector/performance/render_tables.py \
  --summary ../summary.json --output ../tables
python3 tools/subset-selector/performance/build_report.py \
  --summary ../summary.json --output docs/three-way-performance.md
```

The summarizer requires success/hash integrity, complete matrix cardinality,
verified page-cache and runtime-module states, correct cache hit rates, unchanged
original bytes, and full detection equivalence for the accepted corpus and
extended fixtures. Full-mode extended mismatches and reduced eligible mismatches
abort analysis. Raw records of held/rejected inputs are retained independently.
It reports means, medians, ranges, SD and 95% bootstrap confidence intervals,
using fresh processes as the unit. No runs are trimmed or silently discarded.

Rendering requires Pillow and DejaVu Sans (font paths may be adapted). JSON,
Markdown and PNG cells are built from the same formatted values. The report links
back to exact evidence. For correctness, run the normal C/Rust/scanner suites,
`test_selector.py`, `test_configuration.py`, `test_signed_input.py` with its
required arguments, and `test_integration.py --require-detections`. Do not use
unittest discovery to import the argument-taking signed-input script.

The compatibility checks use the archived summary without changing its bytes:

```sh
python3 -m unittest discover -s tools/subset-selector/performance -p 'test_*.py' -v
```

No probe clean candidate authorizes automatic reduced release. Use the actual
`scan.py` / `intake.py --database-profile=pdf-jpeg-png-pe-exclusions` adapter for that policy.
