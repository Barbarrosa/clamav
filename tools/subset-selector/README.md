# Conservative subset selector (hardened, still experimental)

**Production release remains blocked.** The [readiness review](../../docs/production-readiness.md) documents fixed intake failures, current tests, resource/freshness flags and unresolved release gates. Run `python3 tools/subset-selector/readiness.py`; exit 3 means this build is not approved for production.

Use **`--database-profile=legal-redress`** on `scan.py` or `intake.py` to opt in to the reduced database. **`--database-profile=full` is the default** and loads every rule enabled by the retained configuration. The restricted flag forces all-match scanning with accepting callbacks. Detection multisets and severity must match; alert order and the selected final name may differ. Read [the configuration and validation report](../../docs/subset-selector-configuration.md).

**Reduced automatic clean release remains disabled because parser completeness is unproven.** A no-detection result is still available in `candidate_outcome`, with `outcome=held` for the evidence workflow. This flag does not change the existing scanner service, engine defaults or evidence policy.

The [fresh three-way performance report](../../docs/three-way-performance.md) compares pinned original ClamAV, this full-database engine and Legal Redress with the same build and workload. It includes empty/hydrated OS and clean-result caches, CPU time/utilization, RSS/PSS/USS, reload/update peaks, database percentages and exact text/image tables. Reproduce it with [the performance tools](performance/README.md). Historical figures below remain labeled as earlier observations; use the fresh report for current comparisons.

The [PE boundary and release-backport report](../../docs/boundary-backports.md)
records 65 boundary cases per engine, mutation controls and separate stable/LTS
source backports. This closes the exercised PE exclusion regression test; it does
not authorize automatic release or establish universal first-hit equivalence.

## Configure the reduced database profile

After preparing a generation using the instructions below, make a newline-separated list of absolute paths to private, immutable original files, then run:

```sh
python3 tools/subset-selector/scan.py \
  --database-profile=legal-redress \
  --generation ../generation-001 --probe ../scan_probe \
  --lib ../build/libclamav/libclamav.so.14.0.0 --certs certs \
  --files ../files.txt
```

Change only the flag to **`--database-profile=full`**, or omit it, to load the full database and use the original first-hit behavior. Add `--allmatch` in full mode for an all-match comparison. Full mode also accepts `--database /path/to/original-databases` instead of `--generation`; this route does not depend on a reduced selector manifest. The flag belongs to this adapter, **not** to upstream `clamscan` or `clamd`.

`--reload-overlap` measures construction of a replacement while the old engine remains alive. The earlier pinned measurement was about **130 MiB compiled / 161 MiB construction / 303 MiB old-plus-new peak** for reduced scanning. These are measured process values, not a hard memory ceiling. Scan complexity, concurrency, file cache and other services need separate allowance. See the follow-up report for the flag's fresh measurements.

**Keep full-database preparation and update validation on a separate worker with sufficient memory.** `select_db.py` deliberately full-load-tests every generation; do not run it inside a 303 MiB scanner budget. Transfer the complete verified generation through an operator-controlled path, validate it at startup, then switch the generation path or restart the scanner. The measured FreshClam daily validation plus two reduced engines reached about **819 MiB** when co-located. The scan flag never starts an updater or a full-load validation child. Signed inputs and manifests remain mandatory. No hard memory limit is imposed by this flag.

The scan adapter writes JSON lines; process exit 0 means execution completed, not that all inputs were clean. The hardened intake CLI separately returns 0 clean / 1 detected / 2 failed / 3 held. Inspect every scan's `outcome`, `candidate_outcome`, `verdict`, `hold_bits` and `events`. Restricted scans retain weak/PUA evidence in legacy callback events as well as alerts. No ignore, stop or trust callback override is exposed through this flag.

## Build and prepare

Dependencies: the retained ClamAV build and its normal dependencies, Python 3.10+, a C compiler, json-c/OpenSSL headers and `pkg-config`. Fixture generation additionally uses Pillow, reportlab and the `zip` command. SQLite, tar, hashing and transfer logic use Python's standard library. No network framework or WordPress plugin is added.

Run from the archive's `source` directory, after building the retained engine as described in the project documentation:

```sh
python3 tools/subset-selector/build_probe.py --build ../build --output ../scan_probe
python3 tools/subset-selector/test_selector.py
python3 tools/subset-selector/select_db.py \
  --lib ../build/libclamav/libclamav.so.14.0.0 \
  --probe ../scan_probe --certs certs --output ../generation-001 \
  /path/to/pinned/main.cvd /path/to/pinned/daily.cvd /path/to/pinned/bytecode.cvd
```

The selector requires an absent output destination; it does not overwrite a generation. It verifies copied signed inputs, full-load-tests them, then writes `manifest.json`, `decisions.sqlite`, `skip.tsv`, and unchanged signed inputs in `databases/`. **Full-load validation needs the full engine's memory**, even though the eventual candidate scanner is smaller. Run preparation/update workers where that memory is available and include them in overall resource accounting.

The certificate path must contain the expected ClamAV trust root. Do not use verification bypasses or permit unsigned bytecode. A compatible CLD can also be supplied; it must pass the same engine verifier. Do not mix main.cvd/main.cld or daily.cvd/daily.cld generations. The full loader validates the final directory as a set. Inputs and generations are trusted-operator configuration; protect them from mutation by upload users.

The probe links against the requested library directory with an rpath. If a custom SDK is used, supply `--include` and `--library-path` and set the appropriate runtime library path. Record the exact compiler/build-cache and shared-library hashes. The measured library is the retained defaults, including flat hashes OFF.

## Differential tests and measurements

The normal ClamAV build generates harmless binary fixtures under `BUILD/unit_tests/input/clamav_hdb_scanfiles`; the source archive retains their encoded source forms. Run the regular retained tests and then:

```sh
ctest --test-dir ../build -R '^(libclamav|libclamav_rust|clamscan)$' --output-on-failure
python3 tools/subset-selector/test_configuration.py
python3 tools/subset-selector/test_integration.py \
  --probe ../scan_probe --certs certs --output ../synthetic-gates --require-detections
# --require-equivalence retains the stricter historical name/order gate (exit 3).

python3 tools/subset-selector/make_fixtures.py \
  ../fixtures ../build/unit_tests/input/clamav_hdb_scanfiles
python3 tools/subset-selector/extra_fixtures.py ../extra-fixtures ../fixtures
python3 tools/subset-selector/accepted_fixtures.py ../accepted ../fixtures
python3 tools/subset-selector/benchmark.py \
  --probe ../scan_probe --generation ../generation-001 --certs certs \
  --lib ../build/libclamav/libclamav.so.14.0.0 \
  --fixtures ../accepted.txt --output ../accepted-results --configured-profiles
```

`benchmark.py` performs F/R/R/F/F/R fresh-process runs, three repetitions per mode, then one full and one reduced old/new overlap observation. `--configured-profiles` runs the documented adapter flags with all-match on both sides; without it the historical two-mode probe benchmark remains available. Use `--freshclam ../build/libfreshclam/libfreshclam.so.4.0.0` to measure actual `fc_test_database_ex()` overlap for the three pinned DBs and an extra whole-directory test. `--positive PATH` is available in the historical benchmark; use `test_flags.py` for configured positive/held comparisons. For the mixed/adverse corpus use `../fixtures.txt`; do not label its omitted-PE/held speed difference coverage-equivalent throughput.

The standalone probe interface is:

```text
scan_probe DATABASE_DIRECTORY CERTIFICATE_DIRECTORY SKIP_TSV_OR_DASH FILE_LIST REPEATS BROAD ACTION OVERLAP [both|first|all]
```

`-` means full database. `BROAD=0` selects the initial root profile; `1` permits broader document roots. `ACTION=0` accepts alerts; 1/2/3 exercise ignore/stop/trust behavior in tests only. `OVERLAP=1` retains the old engine while constructing a replacement. Test-only `SUBSET_TEST_MAX_FILESIZE` supplies a size ceiling; it is not set for performance measurements. The FreshClam test environment knobs are only for lifecycle experiments. The trusted local file list is not a public upload API.

The optional final probe argument selects one scan mode; omitting it preserves the previous two-mode diagnostic interface. Prefer `scan.py` for the validated profile flag. The probe copies no submissions and has no network access. It emits diagnostic JSON and performs explicit original-byte checks. Its raw `candidate_outcome` cannot authorize release. Reduced `outcome` never becomes clean. Existing signed databases are not modified.

For a read-only compiled census, build `census_probe.c` against the exact source/build headers and a diagnostic library produced by `tools/compact-memory/relink_internal.py`. Include `libclamav`, `libclamunrar_iface`, `libclamav_rust`, generated build headers, json-c and libxml headers. It reuses the existing engine census and new callback; its extra arrays mean its RSS is not a scanner benchmark.

## Intake, generations and explanation

```sh
python3 tools/subset-selector/intake.py \
  --database-profile=legal-redress \
  --source /path/to/synthetic.pdf --quarantine ../private-intake \
  --generation ../generation-001 --probe ../scan_probe \
  --lib ../build/libclamav/libclamav.so.14.0.0 --certs certs

python3 tools/subset-selector/explain.py ../generation-001 ldb 'Rule.Name'
```

The quarantine directory must be private (0700). The hardened local intake saves original bytes read-only and durable separate records, enforces process/output limits and serializes scanner access per quarantine root; derivative verdicts never clear the original. The complaint narrative must be submitted independently; no live form integration exists. Detections remain in the record even when the policy outcome is held. Unknown types, encryption, limits, errors and integrity changes never become clean. Every reduced candidate clean result is held for parser completeness. Intake also defaults to full mode if the flag is omitted.

`generations.switch_shadow(state, generation, library)` validates provenance and atomically changes a shadow pointer; `rollback_shadow()` restores the previous generation. `activate_for_release()` explicitly refuses because qualification failed. These functions never alter the full-database service. Protect the state directory and serialize administrative updates. Production crash/concurrency orchestration is not qualified.

The 1.4 manifest binds the full-load-tested probe binary. Regenerate all earlier generations for this version. Rebuilding a probe or changing the engine requires regenerating the profile. That conservative binding is intentional; a matching signature count alone is not sufficient.

## Result interpretation

Raw fields retain ClamAV status, severity/verdict, final names, ordered callback events, layer depth/object/attributes and policy holds. Hold bits: 1 PE, 2 unsupported root, 4 unsupported/unknown child, 8 policy heuristic, 16 encrypted metadata, 32 ParseErrors, 64 callback/metadata failure, 128 test callback stop, 256 test callback trust, 512 original/file-integrity issue. Ordinary malware detection is not synonymous with a policy heuristic; the original detection evidence remains in either case.

The new `_ex` API's documented status convention differs from this retained development runtime for some detected files. The adapter recognizes CL_VIRUS only alongside a detected verdict; all other non-success statuses fail closed.

The delivered gzip files contain callback names/decisions, not official signature bodies or CVDs. They are evidence of this experiment, not independently deployable databases or Talos-signed transformed files. Regenerate from verified original signed files.
