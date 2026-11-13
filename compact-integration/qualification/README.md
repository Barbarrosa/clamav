# Relative coverage qualification

`coverage.json` records a qualification of the pinned, patched source's
`pdf-jpeg-png-pe-exclusions` profile relative to its **full** profile with the
same options and original databases. It is not a certificate that either
profile detects all malware, that ClamAV recognizes every embedded format, or
that this package has passed deployment tests on SiteGround.

The scanner retains generic signatures, file-type/effect rules, bytecode,
uncertain logical signatures, and name groups that include a retained occurrence
or bytecode dependency. It excludes only selected terminal Target1 NDB/LDB name
groups and the PE section/import hash families. Custom rules never match an
official exclusion key; this generation builder currently rejects custom input.
The on-disk occurrence ledger is an inventory, not native semantic validation.
Activation also requires successful native validation of every original official
transport and compilation of the actual selected engine. Stock per-transport
validation is the default; the bounded alternative below handles an explicit
stock memory failure.

The source argument is that an omitted terminal signature can affect a scan only
through the audited PE matcher, PE logical evaluation, or PE hash consumers.
Each consumer sets a sticky per-original guard before inspecting whether its
signature root exists. If any such consumer is reached, the reduced scan cannot
return a releasable clean verdict. Generic parsing still follows the full engine
path. Cache reuse is disabled. Stable per-root source occurrence ordering removes
allocation-address-dependent ties among retained AC patterns. The assertion is
conditional on this pinned source, selector, options, successful native loads,
and the required parser modules; changing any of these requires requalification.

The evidence includes source inspection, actual recursive matcher tests,
consumer-entry probes with absent roots, deliberate guard-removal mutations,
and full/reduced differential observations on a historical authenticated official
snapshot. A finite test corpus supports the argument; it does not prove parser
completeness for every possible input. Notably, appended PE bytes in a JPEG can
remain guard-free if the full engine does not dispatch a PE consumer. This is
consistent with the relative claim and must not be described as an absolute
proof that those bytes are harmless.

The compiled qualification constant and a matching generation manifest are both
required for reduced release. An editable manifest alone cannot enable the
capability. Full scanning remains available when its resource policy fits;
unsupported roots, reached guards, incomplete scans, stale generations, changed
bytes, missing parsers, and resource failures are held or failed.

## Reproduction

Use the pinned upstream commit and patch sequence from `../manifest.json`.
`SRC` denotes the patched disposable source, `BUILD` its matching configured
build, `INTEGRATION` the `compact-integration` directory, and `REPORT` a fresh
private test directory. Set the loader path to the matching build's own parser
libraries when invoking diagnostic probes:

```sh
export LD_LIBRARY_PATH="$BUILD/libclamav:$BUILD/libclamunrar:$BUILD/libclamunrar_iface"
sh "$INTEGRATION/tests/run_guards.sh" "$SRC" "$BUILD" "$REPORT/guards"
sh "$INTEGRATION/tests/test_prepare.sh"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$SRC/libclamav" -I"$BUILD" $(pkg-config --cflags json-c openssl sqlite3) \
  "$INTEGRATION/tests/prepare_crypto_probe.c" \
  -L"$BUILD/libclamav" -Wl,-rpath,"$BUILD/libclamav" -lclamav \
  $(pkg-config --libs json-c openssl sqlite3 zlib) -o "$REPORT/prepare-crypto-probe"
python3 "$INTEGRATION/tests/test_prepare_pki.py" \
  --probe "$REPORT/prepare-crypto-probe" --source "$SRC" --output "$REPORT/pki.json"
```

The PKI probe uses a stricter authentication mode with legacy RSA disabled.
Only that test process trusts the upstream **TEST** CA. Production verification
continues to use the packaged official trust root. The test pins matching
detached-signature bytes beside the transport alias and rejects a changed
sidecar without publishing a profile.

For the official-snapshot differential, obtain the original database bytes with
the OCI provenance and hashes recorded in `coverage.json`, authenticate them with
the packaged official trust root, and run the normal updater preparation and
native validation stages. No database contents are distributed in this report.
`GENERATION` below is that prepared generation; native scan freshness overrides
used for the archived historical snapshot are test inputs only.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$SRC/libclamav" -I"$BUILD" $(pkg-config --cflags json-c openssl sqlite3) \
  "$INTEGRATION/tests/signed_batch_probe.c" "$INTEGRATION/native/prepare.c" \
  -L"$BUILD/libclamav" -Wl,-rpath,"$BUILD/libclamav" -lclamav \
  $(pkg-config --libs json-c openssl sqlite3 zlib) -ldl -o "$REPORT/signed-batch-probe"
python3 "$INTEGRATION/tests/test_signed_differential.py" \
  --probe "$REPORT/signed-batch-probe" --generation "$GENERATION" \
  --certs "$SRC/certs" --upstream-inputs "$BUILD/unit_tests/input/clamav_hdb_scanfiles" \
  --engine "$BUILD/libclamav/libclamav.so.14.0.0" --output "$REPORT/signed"
```

The recorded stock per-database memory test used an explicit 640 MiB address-space
cap and one child at a time. It performed upstream `cl_load` and bytecode
preparation, not simultaneous full-database AC compilation. Its daily peak was
625,820 KiB address space and 555,224 KiB resident memory. The production policy
comes from actual site constraints. Larger future snapshots may fail validation;
the updater preserves the last generation instead of accepting an unvalidated
one.

## Bounded native validation

`compact-scan validate-bounded` accepts the same required private state, generation,
certificates, inherited lock, and AS/CPU/wall/file limits as the other native
staging commands. It runs after authenticated profile preparation, before the
manifest and selected-engine self-test. The updater invokes it only for an
explicit stock memory failure; authentication and arbitrary semantic failures
cannot silently opt into a weaker path.

The coordinator has no loaded scanner engine. It forks one native batch child at
a time. Every child uses the original signed database directory, normal native
loaders, bytecode, stock PUA/enhanced validation options, and native compilation.
The baseline skips all eligible terminal occurrences while retaining the whole
common rule/dependency set. Subsequent passes admit contiguous windows of physical
eligible callback occurrences, preserving whole logical signatures and repeated
names as separate occurrences. A SHA256 transcript of every callback's format,
name, official/custom flag, and selection class must match the baseline, together
with total and included event counts. Original files and prepared inventory bytes
are fingerprinted before, between, and after passes.

Memory failures split a window in two. A retained baseline failure, an unsupported
indivisible record, a native grammar failure, changed transcript/source, an
incomplete window cover, or an unsafe aggregate counter rejects the generation.
The aggregate is the baseline plus each successful window's delta; shared trie
prefixes can be counted repeatedly, making node totals conservative upper bounds.
BM pattern totals are bounded by `UINT16_MAX` to protect the native suffix-chain
counter; other totals are bounded by `INT_MAX - 1024`. The read-only counter API reports,
in order: BM patterns/relative/absolute offsets; AC parts/nodes/lists/patterns/
logical signatures/relative/absolute offsets; PCRE metas/relative/absolute offsets;
byte-compare metas; linked bytecodes; section offsets; logical-state slots;
section/import hash totals; and loaded signatures. The last counter is supplied
by the native loader. Each batch's exact Linux `wait4` peak RSS is recorded.

The durable files are `profile/bounded-batches.jsonl` (every attempt) and
`profile/bounded-validation.json` (final receipt). The updater hashes both and
sets manifest validation mode `bounded-native-records` only after native success.
The scanner independently verifies their file hashes and binds the receipt to
the actual engine, scanner options, stock validation flags, and original/inventory
fingerprint. The actual selected scanner is still loaded and compiled as the
final staging gate. This demonstrates native validation of all applicable records
and dependency sets within qualified batches; it does not claim that the complete
omitted PE matcher was compiled simultaneously.

The historical official snapshot passed this path under an explicit 640 MiB AS
test cap: 3,040,530 eligible occurrences, ten attempts, and approximately 51 seconds.
The actual updater also passed a genuine stock-allocation-failure fallback under
a 512 MiB AS test cap, including preparation, bounded validation, selected compile,
receipt hashes, and atomic promotion (77.1 seconds). Only download transport was
mocked for that historical-cache integration test. Neither cap is a shipping
default or a certificate for an actual hosting account.

The standalone native-parser fault suite uses diagnostic raw signatures and
clearly labeled injected allocation failures. It checks duplicate occurrences,
whole logical signatures, malformed omitted/retained records, singleton/baseline
resource failure, overflow, and changed source/transcripts. Authentication is
tested separately with real signed official originals and the isolated PKI test.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$SRC/libclamav" -I"$BUILD" $(pkg-config --cflags json-c openssl sqlite3) \
  "$INTEGRATION/tests/bounded_native_probe.c" "$INTEGRATION/native/prepare.c" \
  -L"$BUILD/libclamav" -Wl,-rpath,"$BUILD/libclamav" -lclamav \
  $(pkg-config --libs json-c openssl sqlite3 zlib) -ldl -o "$REPORT/bounded-native-probe"
python3 "$INTEGRATION/tests/test_bounded_native.py" \
  --probe "$REPORT/bounded-native-probe" --certs "$SRC/certs" --output "$REPORT/bounded-native.json"
python3 "$INTEGRATION/tests/test_bounded_official.py" \
  --scanner "$BUILD/compact-scan" --generation "$GENERATION" --certs "$SRC/certs" \
  --as-bytes 671088640 --cpu-seconds 240 --wall-seconds 300 --file-bytes 1073741824 \
  --output "$REPORT/bounded-official.json"
```

Persistent-worker and authenticated ASGI tests additionally observed guard reset,
unchanged input hashes, per-request generation verification, worker reuse, and
private scratch cleanup. These do not qualify live HTTP/TLS, live CDN behavior,
or an actual hosting account's process and aggregate resource limits.
