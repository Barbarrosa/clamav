# Logical-sharing evidence

This is a **failed integration gate**, not a passing release qualification.
See ../logical-sharing-implementation.md for conclusions and definitions.
`lsig-summary.json` includes every process result, measured means, complete
logical-allocation totals, and corrected export hashes/equality flags.
`lsig-alert-order.json` records the strict-order failure; `lsig-order-repeat.json`
repeats both binaries. `lsig-alert-severity.json` records passing strong-threat
selection cases. Library hashes establish exactly which builds were tested.

Reproduction requires the saved signature inputs identified by SHA256, the
recorded corpus manifest and the build prerequisites. They are not redistributed
in this archive. Build the retained revision and an isolated copy with
`experiments/logical-sharing.patch`. Use the same CMake feature settings in
provenance.json. Build the experimental C/Rust/scanner suites with CTest.

Commands, replacing paths with matching builds:

```sh
python3 tools/compact-memory/relink_internal.py --build BUILD --output DIAG
python3 tools/compact-memory/check_layout.py --build BUILD --include JSON_INCLUDE --include XML_INCLUDE
python3 tools/compact-memory/check_alert_order.py --clamscan CLAMSCAN --library before=BEFORE_DIAG --library after=AFTER_DIAG --output ORDER_RESULTS --hash-distractors 10000 --expect-equal before=after
python3 tools/compact-memory/check_alert_severity.py --clamscan CLAMSCAN --library before=BEFORE_DIAG --library after=AFTER_DIAG --output SEVERITY_RESULTS --strong-index 0 --strong-index 5000 --strong-index 9999 --require-strong before --require-strong after
```

The order command is expected to fail on this experiment. Do not remove its
assertion to turn this into a passing profile. Compile `probe_scan_corpus.c`
against the public library and run `taskset -c 2 PROBE DATABASE CERTS FILE_LIST`
in before/after/after/before process order, setting LD_LIBRARY_PATH accordingly.
The scanner probe emits first-hit and all-match transcripts and resource data.

Compile `engine_census.c` and `export_exact_layouts.c` separately against the
matching old/new source headers and diagnostic libraries. Include build,
build/libclamav, libclamav, libclamunrar_iface, libclammspack, JSON and XML header
directories. Run `CENSUS DATABASE CERTS` and `EXPORT DATABASE CERTS OUTPUT_DIR`.
Compare exact exports, not allocator addresses or only counts. Full logical
auxiliary accounting includes string and macro arrays as well as ranges.

In the experimental tree, compile `test_lsig_store.c` with
`-fsanitize=address,undefined -fno-omit-frame-pointer`, the same include paths,
and the diagnostic library for unrelated external symbols. This harness embeds
the production store/hash implementations and substitutes tracked individual
allocations. Run with `ASAN_OPTIONS=detect_leaks=0` only because this environment
cannot run LeakSanitizer; the JSON reports its separate allocation accounting.
The full shared library is not sanitizer-instrumented.

Prior evidence remains in ../complexity-shift-results/ and earlier folders.
No database, corpus source, raw signature export or compiled engine is included.
