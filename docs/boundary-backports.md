# PE boundary test and maintained-release backports

29 October 2026. The requested PE exclusion boundary test passes on the retained
engine and custom backports onto **ClamAV 1.5.4 stable** and **1.4.6 LTS**.
**Production approval is still blocked.** The test establishes the exercised
exclusion boundary, not universal parsing completeness. Full database configuration
is preserved; `--database-profile=pdf-jpeg-png-pe-exclusions` remains an explicit adapter opt-in.
Reduced no-detection results remain held, and evidence retention is unchanged.

## Release baselines and compatibility

| Build | Exact source base | Scope |
|---|---|---|
| Retained engine | `777cba95f55563f0b93d814d5eb86697d8c2ac87` | Existing 1.6 development project; engine bytes unchanged in this revision |
| Stable backport | `fa59fca15872bb8a914ba4c68188bcc8a502cbdf` (`clamav-1.5.4`) | Release source plus retained memory changes, selector, hardened intake and tests |
| LTS backport | `5853e1396777bae4d909cd3dd44f58352e7cf9b3` (`clamav-1.4.6`) | Same scoped features with an adapter for the 1.4 public API |

Official release status was checked at https://www.clamav.net/downloads and
https://docs.clamav.net/faq/faq-eol.html. Custom modifications are not vendor
certification or proof of future security maintenance. Each backport includes a
patch against its exact tag, complete source and revision/hash metadata.

The backports retain compact logical match-state rows, 32-bit AC transition IDs,
flat compiled AC nodes and pool reclamation. Experimental disposable construction
remains OFF. Stable retains the borrowed-key Rust evidence change and leaves
experimental flat hashes OFF. LTS keeps its original hash loader and Rust evidence
representation; `ENABLE_FLAT_HASH_STORE=ON` is explicitly unsupported. Build-generated
Rust bindings match each release's C layout. Release-specific source conflicts were
resolved without importing newer unrelated parser code.

**Synthetic first-hit compatibility is not exact.** On stable, 10,000-rule duplicate
stress cases can select different names; mixed weak/strong cases also change raw
status and severity selection. The retained matcher fixes continue through weak
indicators and can reach a strong detection that the unmodified release's first-hit
path does not reach. All-match named detection multisets, multiplicity, severity,
layers and holds pass. Alert order and the selected final name can differ. The
138-file official/synthetic corpus has exact results in all tested full modes, but
that does not establish universal first-hit equivalence. Do not describe these
backports as byte-for-byte semantic drop-ins for every possible signature database.

LTS does not expose the modern severity/verdict or object-ID API. Its adapter
explicitly emits null for those fields, keeps return codes and named detection
callbacks, and records the legacy 4096-byte scan-count precision. It rejects
modern diagnostic callback overrides; it never invents unsupported severity values.
Its verifier uses the release's built-in trust mechanism. Full remains the default;
the PDF/JPEG/PNG profile with PE exclusions always uses accepting all-match.
Both public API paths pass supervised
intake validation and fail closed on contradictory results.

## Validation

| Check | Retained | Stable 1.5.4 | LTS 1.4.6 |
|---|---:|---:|---:|
| Boundary cases | 65 passed | 65 passed | 65 passed |
| PE-hold mutation correctly rejected | Yes | Yes | Yes |
| Handler reclassification / PE-in-PE size-limit check | Passed | Passed | Passed |
| Exact full corpus comparisons | 414 | 414 | 414 |
| Eligible reduced detection comparisons | 30 | 30 | 30 |
| Mixed/adverse corpus cases held | 108 | 108 | 108 |
| Real supervised intake scans; originals preserved | 12 | 12 | 12 |
| Signed CVD + equivalent CLD accepted; tamper rejected | Passed | Passed | Passed |
| Rebuilt probe identical; no diagnostic witness in shipping engine | Passed | Passed | Passed |
| C / Rust / clamscan / sigtool suites | Prior engine validation retained | Passed | Passed |
| 10,000-rule synthetic all-match families | Prior results retained | 5 passed | 5 passed |

The shared Python selector/configuration/intake suite passes **88 tests**, including
new legacy protocol acceptance/rejection cases. Each backport's full corpus is
compared against a separately built, unmodified copy of that same release; the
retained engine is compared against its previous probe. The 414 count is 138 files
in default full, explicit full and full-all-match modes. The reduced 30/108 split
uses specific policy holds, not a fabricated detection-equivalence claim for held
content. LTS's synthetic test also compares its named evidence against the original
LTS engine, without asserting modern severity equivalence.

The LTS full CTest run reports daemon and FreshClam failures: local socket creation
returns `Operation not permitted`, and FreshClam cannot call `initgroups()` to
switch user. Core engine, Rust, scanner and sigtool suites passed. These environment
failures are retained in the logs; daemon/update operations have not been qualified.
No checks were weakened to turn them green.

Initial adaptation failures are also retained: the older hash-loader ABI required
keeping the LTS hash implementation; modern-only callback tests and an unrelated
newer borrowed-name test were not applicable to the old releases. The first JPEG
fixture incorrectly assumed full mode would detect its appended PE. A reused test
output directory subsequently retained a handler rule; the harness now requires
an absent output directory. An unexpected extra file in a stable test generation
was rejected and isolated; the unchanged signed members were revalidated. A broad
Python discovery command tried to import an argument-parsing CLI; the three actual
unit modules pass when invoked directly. These are documented harness/adaptation
failures, not hidden successful runs.

## What the boundary test proves

The test recompiles diagnostic copies of three engine objects and links a separate
library. Independent entry witnesses observe the adapter's sticky PE hold before
Target:1 fmap matching, PE parser dispatch, section hashes and import hashes. The
same input must be detected by the full database's synthetic PE rule, omitted by
the reduced database, and already held at each reached boundary. A negative control
disables only the PE hold, reaches the same matcher path and must fail the assertion.
Missing/reordered result rows, missing witness sites or the blanket release hold
cannot satisfy the test. Shipping libraries/probes contain no PE-hold override.

Five rule families (NDB, LDB, MDB, MSB, IMP) each run nine positive and four control
fixtures. Positives cover renamed PE roots, PDF raw/Flate/ASCIIHex streams, nested
PDF/ZIP, appended PNG, root ZIP and embedded PE. Additional checks exercise generic
HandlerType reclassification and the PE-in-PE MaxEmbeddedPE skip. The fixtures are
synthetic data and are never executed. Source hashes and caller inventories
complement the dynamic test; see the boundary README for the reviewed paths.

The `cli_scan_buff` PE witness is not naturally exercised: active callers in the
reviewed sources supply OLE/text targets. It is source-audited, not counted as a
covered runtime site. Hash entry checks are exercised with full mode even where the
reduced engine has no PE hash matcher to call. The source audit is revision- and
configuration-specific and must be revisited after parser/caller changes.

Two controls remain shared baseline limitations: appended PE in the JPEG fixture
is not reached by either mode, and the malformed PDF does not produce a parse-error
hold. Therefore this work does not enable automatic reduced clean release. The
native parser still needs separate-principal/read-only evidence isolation and
qualified deployment, queue, update, rollback and recovery operations.

## Integration memory observations

These are means of six supervised intake processes per profile, including clean
and harmless-positive files. They ran under concurrent regression load with an
uncontrolled, mostly hydrated OS cache and a fresh disabled ClamAV clean cache.
They are **integration telemetry**, not a new controlled performance comparison,
a cache matrix, a hard RSS cap or a replacement for the earlier 78-process report.

| Build/profile | Loaded signatures | Loaded/full | Compiled RSS mean (MiB) | Child CPU mean (s) |
|---|---:|---:|---:|---:|
| Retained / full | 3,628,192 | 100.00% | 791.34 | 11.32 |
| Retained / PDF/JPEG/PNG with PE exclusions | 601,004 | 16.56% | 131.02 | 4.64 |
| Stable / full | 3,628,192 | 100.00% | 824.30 | 8.22 |
| Stable / PDF/JPEG/PNG with PE exclusions | 601,004 | 16.56% | 135.51 | 3.69 |
| LTS / full | 3,628,192 | 100.00% | 822.56 | 10.86 |
| LTS / PDF/JPEG/PNG with PE exclusions | 601,004 | 16.56% | 134.00 | 4.33 |

Signature counts are the engine loader's counts, not the count of lines in the
archive or a percentage of RAM. The profile retains **100% of signed input bytes**
and all three signed files; it skips selected records during engine loading. The
pinned public snapshot contains 112,798,155 bytes (main 63, daily 28164, bytecode
339). It is deliberately permitted only by the intake test's 168-hour age override;
the unchanged shipping 48-hour limit rejects it. Production needs a fresh verified
generation. The old ~303 MiB reload observation is not a cap or a measurement of
these backports. Keep full-load preparation on a separate suitably sized worker.

## Reproduce and inspect

See `tools/subset-selector/README.md` and `tools/subset-selector/boundary/README.md`.
Run the three Python unit modules directly, the core CTest suites, the instrumented
boundary test, same-release full comparison, signed-input tests and real intake.
Stable uses `test_integration.py --require-detections`; LTS uses
`test_legacy_integration.py` with its unmodified-release baseline probe. Synthetic
first-hit/order diagnostics are reported separately from the all-match contract.

Selector version is `1.4.1-profile-named-experimental`. Regenerate all prior
profiles because the selector/probe hashes are bound to the signed generation.
Raw logs, compressed JSON traces, source-call inventories, instrumentation/build
commands, generation manifests, library/probe hashes and native intake records are
under [validation evidence](subset-selector-results/boundary-backports/summary.json).
No official signature bodies or real complaint data are included in this evidence.
Earlier benchmark tables, images, measurements and history remain unchanged.
