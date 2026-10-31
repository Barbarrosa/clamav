# Length-bound implementation evidence

This is a failed integration gate, not a qualified release. Read
`../length-bounds-implementation.md` first. `summary.json` contains all four
corpus runs and memory/timing means; `provenance.json` identifies source,
configuration, binary hashes and test scope. `alert-order.json` records the
first-name and all-match order failures. Within-build repeats and six severity
cases are separate files. The full field comparator has positive and negative
controls; numeric extension IDs alone are allocation-dependent.

Baseline source: `fe52606`. Experimental source: `abd2431`, or apply
`../../experiments/ac-length-bounds.patch` to an isolated retained checkout.
The patch applies cleanly to both the recovery checkout and the previously
saved archive source bytes. No raw database, corpus or exported signature
payload is included here. Corpus hashes are in the existing
`../logical-sharing-results/corpus-manifest.json`, with provenance alongside it.

Build both trees with the options in `provenance.json`, using the same C/C++ and
Rust toolchains and dependencies. Configure certificates normally; do not
bypass signature verification. Run the C/Rust/scanner tests with:

```sh
ctest --test-dir BUILD -R '^(libclamav|libclamav_rust|clamscan)$' --output-on-failure
python3 tools/compact-memory/check_layout.py --build BUILD --include JSON_INCLUDE --include XML_INCLUDE
```

Private diagnostics reuse production objects, with private exports enabled:

```sh
python3 tools/compact-memory/relink_internal.py --build BUILD --output DIAG
```

Compile each tree's `engine_census.c` and `export_exact_layouts.c` against its
matching headers and diagnostic library. Include BUILD, BUILD/libclamav,
libclamav, libclamunrar_iface, libclammspack, JSON and XML header directories;
define HAVE_CONFIG_H and link libclamav. Run with the matching LD_LIBRARY_PATH:

```sh
CENSUS DATABASE CERTS
EXPORT DATABASE CERTS EXPORT_DIRECTORY
python3 tools/compact-memory/check_length_bound_exports.py --before BEFORE_EXPORT --after AFTER_EXPORT --output field-comparison.json
```

The following strict comparison is expected to **fail**; keep the assertion:

```sh
python3 tools/compact-memory/check_alert_order.py --clamscan CLAMSCAN --library before=BEFORE_LIB --library after=AFTER_LIB --output ORDER --hash-distractors 10000 --expect-equal before=after
python3 tools/compact-memory/check_alert_severity.py --clamscan CLAMSCAN --library before=BEFORE_LIB --library after=AFTER_LIB --output SEVERITY --strong-index 0 --strong-index 5000 --strong-index 9999 --require-strong before --require-strong after
```

For corpus comparisons, compile `probe_scan_corpus.c` against the public library
and libcrypto. Pass DATABASE CERTS FILE_LIST; use the same ordered file list and
switch only LD_LIBRARY_PATH. The four recorded runs used before/after/after/before
order and CPU 0 affinity. Other work overlapped some runs, so timings do not
qualify performance. Each JSONL retains timing and resource observations.

For targeted sanitizers, compile only production `matcher-ac.c` with
`-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`. Relink the normal
shared library with this object substituted and the sanitizer link flags.
Run the normal `check_clamav` with that library, `CK_RUN_SUITE=matchers`,
`CK_FORK=no`, ASan preloaded, and halt-on-error enabled. Leak detection was
disabled; unrelated C/Rust objects were not instrumented. The 53-check result
must not be described as a fully instrumented engine or a leak audit.

The initial C test failure documents the baseline prefix-offset issue; the
final C suite passes after correcting that fixture's expected matching setup.
The initial scanner error was a missing execute bit on a generated helper;
the final scanner suite passes after restoring it. Initial failure logs remain
alongside final results to make these distinctions reviewable.
