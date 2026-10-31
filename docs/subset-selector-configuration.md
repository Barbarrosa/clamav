# Configurable restricted database profile

**Current hardening revision:** see [production readiness](production-readiness.md) for selector 1.3, required regeneration, intake exit codes, resource/freshness limits and release blockers. The figures below remain historical measurements of 1.2.

29 October 2026 (UTC). This follow-up implements the user's acceptance of changed alert order when all applicable detections remain present, with exact original results when all database families are enabled. The earlier experiment and its stricter failed ordering gate remain preserved in [the original report](subset-selector-implementation.md).

## Configuration

The opt-in flag is **`--database-profile=legal-redress`** on `tools/subset-selector/scan.py` and `intake.py`. The default is **`--database-profile=full`**. This is a standalone public-API adapter flag, not an upstream `clamscan` command or `clamd.conf` setting. No existing engine/service default was changed.

From `source/`, after building `scan_probe` and preparing a generation:

```sh
python3 tools/subset-selector/scan.py \
  --database-profile=legal-redress \
  --generation ../generation-001 --probe ../scan_probe \
  --lib ../build/libclamav/libclamav.so.14.0.0 --certs certs \
  --files ../private-original-files.txt
```

The file list contains one absolute path per line. For original-byte preservation and metadata records, use `intake.py` with the same profile flag, replacing `--files` with `--source ORIGINAL --quarantine PRIVATE_DIRECTORY`. The quarantine directory must be private (0700). Narrative submission proceeds independently of attachment disposition. Originals, including executable evidence, are retained for authorized full-scan/manual review; derivatives have separate verdicts.

Changing the flag to `--database-profile=full` restores all rules enabled by the existing full configuration and the original first-hit behavior. Omitting the flag does the same. Add `--allmatch` to full mode when comparing with the reduced mode. An independent full-database fallback accepts `--database ORIGINAL_DATABASE_DIRECTORY` instead of `--generation`, without depending on a reduced selector manifest.

Restricted mode requires a validated generation, forces all-match and accepting callbacks, rejects the broader experimental root allowlist, and exposes no stop/ignore/trust callback action. It never silently falls back to a different database on a validation failure. Unsupported configuration or changed input/probe hashes fail before scanning. The reduced and full engine use the same pinned shared library and parser/heuristic/limit settings.

The C probe gains an optional final `both|first|all` argument. Omitting it preserves its old two-mode diagnostic interface. The adapter selects `all` for restricted scans and `first` for full scans unless `--allmatch` is requested. `scan.py` validates hashes and replaces itself with the native process using `exec`; it does not leave a Python parent behind or compile a full engine at scan time.

Exit 0 means execution completed. Every scan row carries its own `outcome`, `candidate_outcome`, verdict, holds, detection events and byte-integrity hashes. Treat a missing row or process failure as a failed scan. Intake rejects missing/wrong-mode results and preserves the original on failure.

## Detection contract and evidence holds

Reduced acceptance compares complete **multisets**, not just a final label or unique set. Duplicate counts matter. Both `alert` and `legacy_virus` events are compared: in this runtime, weaker or PUA evidence may appear in legacy callbacks even when a strong verdict supersedes it. Alert layer/depth/object/attribute fields, final severity, return code, scanned byte count, original hashes, policy holds and non-alert layer traversal must match. Only alert ordering, the selected final name and the last-name field exposed on other callbacks may differ.

This contract is for accepting all-match scans. First-hit can select a different overlapping signature, and early-stop/trust callback behavior depends on order; those are excluded from the reduced configuration. Full mode retains exact ordered behavior. "All enabled" means the existing `CL_DB_STDOPT` configuration, including its existing optional-PUA policy; this follow-up does not enable additional optional databases.

The change relaxes the name/order gate only. **Automatic clean release from a reduced database remains held.** A malformed PDF or ZIP can still produce a no-detection candidate without a reliable incompleteness signal. The result now identifies `parser-completeness-unproven` as the release blocker. PE reachability, unknown types, encryption, limits, explicit parser errors and file-integrity changes retain their holds/failures. No finite corpus establishes universal detection or parser coverage; comparisons below are scoped to their fixtures and pinned database.

## Memory and update placement

The previously measured reduced scanner used 129.724 MiB compiled RSS, 160.461 MiB construction high water and **302.957 MiB** with old and replacement engines simultaneously alive. This is the approximately 303 MiB configuration selected by the flag. `--reload-overlap` reproduces that lifecycle experiment. It is a measured value, not a cap or a worst-case service guarantee.

Keep generation preparation and full-database update validation on a separate worker with sufficient memory. Preparation verifies signed inputs and compiles the **full** database before deriving exclusions; suppressing that step would let invalid excluded signatures escape validation. The prior normal daily FreshClam load test with two reduced engines reached **818.977 MiB**, and an extra whole-directory test reached 1112.887 MiB. These operations do not fit a 303 MiB scanner budget when co-located.

Transfer a complete prepared generation over an operator-controlled path, keep it immutable to upload users, validate it on startup, and select its path for the scanner. The normal adapter invocation starts no updater and performs no full-engine load test. Test-only FreshClam environment hooks belong solely to lifecycle measurements. Generation versions bind selector code, profile, signed inputs, exclusions, engine and probe; regenerate 1.1 generations for this 1.2 adapter. Changing database, engine or probe requires fresh validation.

Allow separately for concurrency, complex input expansion, retained event history, file cache and the surrounding application. The existing measurements do not establish an isolated cgroup/service ceiling. `--reload-overlap` is a diagnostic, not a production queue or daemon reload controller.

## Validation and reproduction

The new configuration tests exercise default/explicit full selection, enforced all-match, unsupported profiles, broad-profile rejection, stale probe/generation rejection, duplicate/name/severity/layer/integrity differences, missing/wrong-mode intake results and original preservation. The existing selector tests remain in use.

`test_integration.py --require-detections` uses 10,000 applicable generic signatures per fixture with interleaved excluded PE allocation distractors. It covers strong, mixed weak/strong, mixed PUA/strong, weak-only and PUA-only matches. It also retains handler reclassification, trust, limits, missing-file and malformed-excluded-rule checks. The historical `--require-equivalence` still fails when exact alert order differs; that failure is retained rather than relabeled as exact equivalence. Stop/trust callback cases remain diagnostic only.

`test_flags.py` compares the actual CLI flags with the pre-change full probe, including ordered events, selected names, severity, hashes, holds and result fields (only elapsed time is excluded). It tests omitted and explicit full flags and full all-match, then verifies reduced all-match equivalence for policy-eligible cases and retained holds for the rest. Rebuild the previous probe from commit `23d84707b1f5e988e4dcb98ddd5f2c0d543a2809` against the same retained engine to reproduce the baseline.

```sh
python3 tools/subset-selector/test_selector.py
python3 tools/subset-selector/test_configuration.py
python3 tools/subset-selector/test_integration.py \
  --probe ../scan_probe --certs certs --output ../integration \
  --require-detections
python3 tools/subset-selector/test_flags.py \
  --baseline-probe ../scan_probe-v12 --probe ../scan_probe \
  --generation ../generation-001 --lib ../build/libclamav/libclamav.so.14.0.0 \
  --certs certs --fixtures ../all-fixtures.txt --output ../flag-regression
python3 tools/subset-selector/benchmark.py \
  --configured-profiles --probe ../scan_probe --generation ../generation-001 \
  --lib ../build/libclamav/libclamav.so.14.0.0 --certs certs \
  --fixtures ../accepted.txt --output ../configured-benchmark
```

The accepted benchmark uses the same 28 valid PDF/JPEG/PNG files (14,846,009 bytes), six F/R/R/F/F/R fresh processes, three repetitions, concurrency one and one pinned CPU. Both sides use all-match and identical engine options. Held PE/container work is excluded from throughput claims. The retained engine C/Rust/scanner suites are unchanged from the preceding validated archive; this follow-up specifically tests the adapter and probe changes.

Fresh results and exact provenance are recorded in [the configuration result summary](subset-selector-results/configuration/summary.json), with raw native logs and a bound final generation manifest. Original official database bodies and machine-specific binaries are not redistributed.

## Fresh results through the flag

| Measurement | Full (`--allmatch`) | Legal Redress |
|---|---:|---:|
| Compiled RSS, mean | 790.085 MiB | 129.654 MiB |
| Construction / observed scan high water, max | 823.570 MiB | 160.617 MiB |
| Old/new reload overlap high water | 1611.691 MiB | **303.156 MiB** |
| Database load, mean | 6.270 s | 3.408 s |
| Engine compile, mean | 1.719 s | 0.105 s |
| 28-file all-match batch, mean | 1.664 s | 1.712 s |
| Per-file median | 10.699 ms | 10.748 ms |
| Per-file p95 | 345.068 ms | 366.317 ms |

Compiled RSS falls **83.590%**. The restricted all-match batch is **2.884% slower** in these trials. All 252 scans per variant (504 total) satisfy the detection comparison on the valid corpus. These measurements include the actual adapter selection path; the adapter hashes files before replacing itself with the native scanner. Engine load and batch timings exclude that startup hashing, while raw process wall-time records include it. The shared cgroup samples are not isolated service charges.

Correctness results: **32 selector tests and 18 configuration/contract tests pass**. Five synthetic families with 10,000 applicable signatures each pass the all-match multiset/severity gate in native and ASan/UBSan probe runs. Only the probe is instrumented; its linked retained engine is unchanged, and leak detection was disabled as in the previous experiment. The stricter historical order gate still fails as expected.

The documented full configurations match **414 of 414** prior full-probe scan records exactly apart from elapsed time. The 138-fixture mixed corpus gives **30 policy-eligible reduced comparisons**, all passing, plus **108 held cases**, all remaining held. The held cases do not count as coverage-equivalent successes. The native intake check preserves the original and records `candidate_outcome=clean` with `outcome=held`, reason `parser-completeness-unproven`. There is no automatic-release override.
