# Production readiness review

Update: the [boundary test and maintained-release backports](boundary-backports.md)
are implemented and locally validated. The narrow PE exclusion gate now has a
mutation-sensitive regression test. Reduced automatic release remains disabled;
shared parser limitations, synthetic first-hit differences and deployment gates
remain. Historical results below describe the earlier intake-hardening pass.


29 October 2026. **Release decision: NOT production-ready.** This hardening pass
fixes concrete intake failures and validates the resulting local workflow. It does
not promote the experimental selector to a production release. The user's original
requirement to mark unqualified code experimental remains in force.

Run `python3 tools/subset-selector/readiness.py` for the machine-readable decision.
Exit 3 means release is blocked. There is no flag that turns failed qualification
into approval. This file records a release decision, not a target-host audit.

## Fixed in this revision

- Intake no longer defaults unknown or contradictory scanner results to clean.
  The result protocol must contain exactly one runtime, engine, scan and batch
  record. Path, before/after hashes, scan mode, status, verdict, holds and outcome
  must agree. Duplicate JSON keys, malformed/nonfinite values, missing results,
  wrong loaded engines, missing RAR modules and inconsistent detections fail.
- A pending/held record is durably written before copying or scanning. Originals
  use exclusive creation and end at mode 0400. Records use mode 0600, unpredictable
  temporary names, atomic replacement, file fsync and directory fsync. A failed or
  interrupted reassessment revokes the prior clean disposition before scanning.
  Previous findings remain in separate attempt records.
- A no-follow lock serializes assessment of each attachment. Another no-follow
  lock bounds scanner concurrency to one per private quarantine root; contention
  returns held/retry. This is not a distributed queue or a multi-host lock.
- The child has wall-time, CPU, address-space, file-size and descriptor limits,
  disabled core dumps and Linux no-new-privileges. Output is bounded to 16 MiB.
  Timeout/overflow/crash never clears an attachment, and the entire child process
  group is terminated. Intake removes inherited diagnostic hooks and loader
  injection variables. Operator-controlled library paths remain necessary.
- Intake requires one signed daily database, defaults to a maximum age of 48 hours,
  rejects timestamps over five minutes in the future, and records generation and
  actual runtime-library hashes. It rechecks the original and manifest after scan.
- The selector now validates the decision database checksum, rejects symlinked
  generation members and duplicate/unsafe manifest database names, records actual
  loaded engine identity, requires RAR modules during full-load validation, and
  fsyncs generation files/directories before publication. Selection rules are
  unchanged. Full validation still runs separately from the reduced scanner.

These protections assume service-owned, trusted ancestor directories and immutable
operator-controlled generation, executable, certificate and library files. Hashes
are provenance checks, not authentication against an attacker who controls both
files and manifests. Native parser isolation remains a deployment requirement.

## Release blockers

| Gate | Status | Work still required |
|---|---|---|
| Reduced detection contract | Local regression passed | Continue differential qualification for each new signed generation; retain generic, uncertain and effect-bearing rules. |
| Complete parsing before reduced automatic release | **Blocked** | Reliable recursive completeness/limit gates are missing. Silent parser skips remain possible. Reduced clean candidates stay held. |
| Engine/security maintenance | **Blocked** | The retained code is a custom 1.6 development build. Establish a maintained release baseline, security-update parity and qualification of the retained engine changes. |
| Production evidence isolation | **Blocked** | Run the native parser as a separate principal or in an enforced sandbox with originals mounted read-only. Mode 0400 and after-scan hashes cannot stop a compromised same-UID scanner from changing permissions and destroying evidence. |
| Operational deployment | **Blocked** | Validate durable queue recovery, quotas, access controls, backups, retention, monitoring, service-account boundaries, concurrency and target-host memory limits. No live form/service deployment was supplied or changed. |
| Database update operations | **Blocked** | Exercise authenticated transfer, generation promotion/rollback and crash recovery on the actual deployment; monitor freshness and route failures to review. Existing shadow pointers are still diagnostic. |

ClamAV's official download page lists **1.5.4 stable** and **1.4.6 LTS** and
recommends a latest stable/LTS version for production. The retained project declares
`VERSION "1.6.0"` with a development suffix. That distinction does not prove it is
missing a specific security fix; no such claim is made. It does mean the benchmark
is not evidence of vendor-supported release status. Replacing the library alone
would invalidate the selector's ABI/probe binding and all prior qualification.

Primary sources checked on 29 October 2026:
- https://www.clamav.net/downloads
- https://docs.clamav.net/faq/faq-eol.html

## Configuration and operating contract

The documented selector flag remains **`--database-profile=legal-redress`**.
Omitting it retains **full** mode and its existing first-hit behavior. The reduced
profile forces accepting all-match and never releases a no-detection original.
The low-level `scan.py`/native probe are diagnostic scanning interfaces. Use
`intake.py` for the hardened local evidence workflow; neither is a public upload
service or a complete production sandbox.

The selector version is `1.4.0-boundary-tested-experimental`. **Regenerate earlier
generations** after rebuilding the probe; the old probe/selector hashes must fail.
Use the exact requested engine and its matching RAR libraries. For a build tree:

```sh
export LD_LIBRARY_PATH="/absolute/build/libclamav:/absolute/build/libclamunrar_iface:/absolute/build/libclamunrar${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python3 tools/subset-selector/build_probe.py --build /absolute/build --output /absolute/scan_probe
python3 tools/subset-selector/select_db.py \
  --lib /absolute/build/libclamav/libclamav.so.14.0.0 \
  --probe /absolute/scan_probe --certs certs --output /absolute/new-generation \
  /absolute/main.cvd /absolute/daily.cvd /absolute/bytecode.cvd
python3 tools/subset-selector/intake.py \
  --database-profile=legal-redress \
  --source /private/upload/original.pdf --quarantine /private/quarantine \
  --generation /absolute/new-generation --probe /absolute/scan_probe \
  --lib /absolute/build/libclamav/libclamav.so.14.0.0 --certs certs
```

The module loader explicitly searches `LD_LIBRARY_PATH`/its configured install
directory; a probe rpath alone is insufficient in a non-installed build tree.
Intake adds the requested library directory and matching sibling module directories
to the child environment. Full-load preparation requires the paths above as well.

`intake.py` defaults: `--max-source-mib=100`, `--timeout=180` seconds,
`--cpu-seconds=120`, `--address-space-mib=2048`,
`--max-database-age-hours=48`. The address-space limit is **virtual address space,
not RSS or a cgroup memory cap**. Larger original evidence must remain in the
upstream private upload store and use the authorized exception route; intake never
deletes the source. Snapshot failures may leave a partial private object with a
non-releasable record. Do not delete the upstream original until durable successful
preservation is acknowledged. An oversize rejection is not a malware verdict.

Intake CLI exit codes now distinguish **0 clean / 1 detected / 2 failed / 3 held**.
This is an intentional adapter-level change. Native scan/probe exit 0 still means
execution completed; inspect each row. Complaint narrative submission remains
independent. A derivative cannot clear the original. Detected content and executable
evidence remain available for authorized review; no deletion/quarantine-cleanup
policy or notification is added.

Resource limits are not a security sandbox. A production service must enforce its
own aggregate cgroup limit and isolate the scanner from writable evidence. The
previous measured 304.6 MiB reload peak exceeds a hard 303 MiB budget even before
parent processes, file cache and input-dependent growth. Do not set a 303 MiB hard
cap from that measurement. Preparation/full update validation needs a separate
worker budget. The prior performance tables remain measurements of the prior
revision; this pass adds no claimed new throughput or RAM improvement.

## Validation

Final results: **85 unit/fault tests passed**, **414 exact full-mode scan comparisons**, **30 eligible reduced detection matches**, **108 cases held**, and **12 real supervised intake scans** with preserved bytes. Five synthetic signature families pass the accepting all-match detection contract. Signed CVD/CLD verification passed, tampered input was rejected, and rebuilding the final probe produced identical bytes.

Exact logs and a generated summary are under
[production-readiness results](subset-selector-results/production-readiness/).
The tests cover malformed/contradictory output, unknown outcomes, source and runtime
mismatches, stale/future databases, symlinks/hardlinks, private permissions, storage
failure, interrupted reassessment, retained prior detections, scanner concurrency,
wall/CPU/address-space/output limits and descendant cleanup. Real-engine tests
compare default and explicit full/first/all-match results against the previous
probe and exercise reduced detection equivalence. Harmless upstream test signatures
and synthetic files are used; no complaint submissions are processed.

Native intake testing deliberately uses the historical signed benchmark snapshot
with a **test-only 168-hour age limit** and separately checks that the unchanged
48-hour default rejects it. It does not relax the shipping default. Its timing
fields are integration telemetry under concurrent regression load, not a replacement
for the controlled three-way performance analysis. Existing engine code is unchanged;
this pass rebuilds and tests the native adapter and Python integration.

Initial failures are retained: missing RAR runtime paths were rejected during
preparation, and a tampering unit test needed to explicitly chmod the newly read-only
skip file before attempting corruption. The final tests must pass before packaging.
Neither correction weakens the production fail-closed checks.
