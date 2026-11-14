# Native direct updates

compact-update is a one-shot, unprivileged libfreshclam client. It downloads
official main/daily/bytecode content directly from database.clamav.net; there
is no secondary database publisher and no compilation on the website host.

[Native resource limits](RESOURCE_LIMITS.md) describe inherited/cumulative CPU
accounting, nonblocking fatal output, parent binding and lock lifetime through
process cleanup. These controls also apply to updater helper processes.

The entry point is:

    compact-update update \
      --state ABSOLUTE_PRIVATE_STATE \
      --scanner ABSOLUTE_MATCHING_COMPACT_SCAN \
      --certs ABSOLUTE_MATCHING_CERTS \
      --engine-sha256 DOCTOR_ENGINE_SHA256 \
      --options-sha256 DOCTOR_OPTIONS_SHA256 \
      --expected-current-sha256 EXACT_POINTER_SHA256_OR_absent \
      --as-bytes POLICY_VALUE --cpu-seconds POLICY_VALUE \
      --wall-seconds POLICY_VALUE --file-bytes POLICY_VALUE \
      --max-line-bytes POLICY_VALUE --disk-reserve-bytes POLICY_VALUE \
      --max-state-bytes POLICY_VALUE --max-state-inodes POLICY_VALUE \
      --connect-seconds POLICY_VALUE --low-speed-seconds POLICY_VALUE \
      --max-attempts POLICY_VALUE --max-age-seconds POLICY_VALUE

All workload ceilings come from the site's typed resource policy. These are
required arguments, not fixed 640 MiB/45 second defaults. Address space differs
from resident RAM; a PHP memory limit is not a native-child budget. CPU and wall
budgets apply to the update operation; children also receive CPU/address-space/
file limits. A monotonic supervisor and whole-job alarm prevent a child or blocked
orchestration step from outliving its lease. A killed parent kills its child on
Linux. Resource failures never promote a generation.

The state ceilings are absolute allocations for the whole STATE tree, including
cache, temporary work, logs, pointers and every retained generation. They are not
additional free space. Native accounting charges both files and directories,
using the greater of logical size and allocated blocks, and counts entries as
inodes. An owned directory walk has a depth bound and stops at the configured
inode budget. Links are never traversed: persistent/unexpected links fail;
prepare's exact, owned temporary /proc/self/fd/N pins are counted themselves.

Checks stop at 80% of either allocation, reserving 20% for writes between monitor
samples. The per-file write cap must fit within one fifth of the state byte
allocation. Checks run before fetching and known copies, while children run
(approximately every 100 ms), after children exit and before activation. Exceeding
either watermark defers and preserves the old pointer; no published generation
is deleted. This is a conservative application monitor, not a kernel quota:
multiple writes or filesystem allocation between samples can overshoot it. A
confirmed filesystem/account quota remains the final enforcement boundary.
The disk-reserve argument independently means minimum available filesystem space;
it must not be filled with the updater's own working-state allocation.

An optional --program-id pkg-<64 lowercase hex> binds a staged, authenticated
native code package. The website installer supplies it only after authenticating
that package. The updater does not fetch code. The final current pointer switches
the package and matching database generation together. Ordinary database updates
preserve the current program ID. Scanner manifests independently bind the loaded
engine and scan options. The caller supplies the SHA256 of the exact current.json
bytes used to select that runtime, or absent for first installation. Under
job.lock, the updater checks that expectation before inheriting a program ID or
fetching anything. A changed pointer defers with current_pointer_changed, so an
older queued runtime cannot publish a generation under a newly active program.

## Staging and validation

The private state directory must be owned by the current UID and mode 0700.
Its layout is:

- job.lock: exclusive shared scanner/updater lock; contention defers.
- cache/: mutable official FreshClam files and persistent freshclam.dat.
- freshclam-tmp/: FreshClam's own temporary workspace.
- generations/gen-<tuple SHA256>/: immutable complete database/profile manifest.
- current.json: protocol 1 with generation and optional program ID.
- previous.json: the previous complete pointer, preserved before activation.

The updater retains normal upstream TLS, CVD/.sign, internal signed .info
and CDIFF authentication. It never enables unsigned bytecode or custom download
URLs. CDIFF-created CLDs are local containers, not signed outer CVD containers.
Persistent FreshClam cooldown/UUID state is never deleted to force a retry.
Unknown or corrupt state formats stop updates for diagnosis.

The fetch operation writes only its private cache. Each completed snapshot is
copied to a new staging generation with exactly one main/daily/bytecode file
per family, plus applicable detached signatures. Every family is verified and
stock-load-tested in a separate fresh executable process using
fc_test_database_ex(). No reduced scanner engine is resident during those
tests. Then compact-scan prepare creates the bounded profile inventory, the
updater binds every database/profile file in manifest.json, and
compact-scan self-test loads/compiles the actual selected generation.

Only explicit stock allocation failure (FC_EMEM, preserving CL_EMEM or a failure
with errno ENOMEM cleared before the load) permits a bounded retry. Authentication,
feature, syntax, crash and deadline failures never request that fallback. After
all sources have been independently authenticated by prepare, validate-bounded
uses native parser loads in deterministic batches, retaining the required common
baseline. Every eligible occurrence must be covered by its native validation
receipt; unsupported or failing singleton/baseline loads reject the generation.
The updater hashes both bounded-batches.jsonl and bounded-validation.json into
the manifest and identifies mode bounded-native-records. This is distinct from
stock-per-database validation and does not claim a combined full PE-engine compile.

An unrecovered stock test failure, unknown feature level, stale/future daily database,
preparation/self-test error, missing resource policy, or integrity failure
preserves the old pointer. There is no TestDatabases bypass that makes failed
qualification count as passed. A future snapshot that exceeds its budget stays
unactivated; no assumption is made that all future signatures fit.

The entire generation is synced, made read-only and renamed before the current
pointer changes atomically. Existing generations are never overwritten. A repeated
identical tuple is rechecked and reports up_to_date. Failed orchestration scratch
and interrupted scratch from this updater's own namespaces can be removed under
the lock; accepted submitter data and published generations are never purged.
The complete prior pointer is available to the site application's rollback path;
rollback must validate the old generation with its matching program first.

Private mode bits and read-only files are not isolation from a compromised process
running under the same UID. Shared-host deployment must describe that limitation.

## Output

The final JSONL protocol 1 record has status updated, up_to_date, deferred
or failed; successful updates include the generation ID. Failures include a
stable reason and phase. next_attempt_after is an epoch timestamp only when
the actual persistent upstream cooldown supplies one; otherwise it is null.
The website scheduler applies its own computed next eligible time and honors the
upstream value. It must not infer success from process exit alone.

The internal fetch and test-db subcommands require an inherited descriptor
holding the exact state lock and explicit internal policy. They are not
standalone public update bypasses.

## Streaming patch and validation scope

Patch 020 removes full CVD copies from legacy hashing, POSIX detached-file PKCS7
verification and tar extraction. OpenSSL consumes a file BIO and discards verified
output. Signature/certificate flags and invalid-signature handling are preserved.
Extraction rejects duplicate/non-regular/path-escaping members and propagates
read/write errors.

CDIFF edit windows spill sorted runs to disk, merging with last-command-wins
semantics. Additions spill in arrival order. Only the current bounded line and a
fixed implementation window remain in memory; the policy supplies the maximum
line size. Hashing rejects unexpected EOF instead of looping forever. A server
ignoring the 512-byte header Range request cannot allocate an unlimited metadata
buffer. The callback retains at most the first 512 bytes and deliberately stops
an excessive body. Only that explicit complete-prefix write abort is accepted;
allocation/overflow/other transfer failures remain failures, and HTTP/header
validation still runs. HTTP 403/429 responses retain their upstream cooldowns.
The seven metadata regressions cover callback bounds, fragmented/513-byte/large
bodies, bad headers and CVD-looking error bodies; the upstream FreshClam mirror
suite also passes, including its forbidden-response daemon case.

Six added Rust tests exercise trusted/tampered/untrusted detached verification,
duplicate/truncated extraction and CDIFF spill/order/EOF behavior. The complete
73-test Rust suite passed in the qualified build. The Python updater fault suite
uses a clearly labeled fake transport to test orchestration only; it does not
pretend to authenticate its fixtures.

The historical official snapshot was also stock-tested with the real helper in
three isolated processes under an explicitly selected 640 MiB address-space test
cap. Daily peaked at approximately 611 MiB virtual / 542 MiB resident; main at
422/343 MiB and bytecode at 84/23 MiB. These observations are test evidence, not a
shipping default or a bound on future generations. The complete native pipeline
also passed with those authentic originals: verification, three isolated stock
loads, profile preparation, selected-engine compile, all manifest hashes and the
atomic pointer. Its transport-only test shim supplied the seeded cache instead
of fetching from the CDN; the measured run took 17.7 seconds. This does not test
live official downloads. The historical database freshness allowance was an
explicit test input and must not become the production freshness policy.
The final allocation-fallback pipeline also passed under an explicit 512 MiB
address-space test cap in 77.1 seconds: a genuine stock allocation failure
triggered bounded native validation, its two receipts were hashed, the selected
engine compiled, and the exact generation activated. Its validation mode is
bounded-native-records, not a stock full-database success. Only network transport
was mocked. These measurements do not set production memory or time limits.
New live CDN availability and the actual site's limits still require deployment
validation.

A manifest's successful stock-load validation is separate from reduced-profile
release qualification. The coverage field comes from the compiled, versioned
qualification header, not an editable override. It records the pinned relative
coverage proof separately from the overall deployment qualification. A changed
guard/order/profile contract requires new qualification.

Run orchestration tests in the configured build environment:

    python3 compact-integration/tests/test_update.py -q

The test needs a C compiler, json-c/OpenSSL development files and Python for the
test harness only. The deployed website does not need Python or a compiler.
