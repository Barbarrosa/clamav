# Optional remote scanning gateway

The ASGI service accepts authenticated original bytes and passes only private,
service-created paths to compact-scan. WordPress retains the accepted original;
the gateway deletes its temporary copy before a successful response. Cleanup
failure is an explicit error. Use one service process behind the supplied TLS
proxy configuration. Run it as an unprivileged dedicated account with a private
persistent state volume and a separate private scratch directory.

Install the pinned service requirements into the deployment image, then launch
uvicorn with service.app:create_app and --factory, bound to 127.0.0.1:8080.
The native package and its matching certificate directory must already exist.
No database, code, compiler or Python dependency is downloaded by an upload
request. Automatic code/database maintenance uses the separately authenticated
administrative update operation. The WordPress installation does not need Python.

## Explicit configuration

All values are operator inputs calculated from the remote service's measured
resource policy; the service supplies no site quota or memory guesses.

- COMPACT_SCANNER, COMPACT_STATE, COMPACT_SCRATCH and COMPACT_CERTS are absolute
  paths. Scratch is owned by the service UID, mode 0700 and not a symlink.
- COMPACT_TOKEN is a random scan credential of at least 32 characters. Optional
  COMPACT_ADMIN_TOKEN is a distinct random credential of at least 32 characters.
  Keep credentials in the secret environment and the Authorization header.
- Required positive ceilings are COMPACT_MAX_INPUT_BYTES,
  COMPACT_DISK_RESERVE_BYTES, COMPACT_AS_BYTES, COMPACT_CPU_SECONDS,
  COMPACT_WALL_SECONDS, COMPACT_FILE_BYTES, COMPACT_OUTPUT_BYTES,
  COMPACT_MAX_REQUESTS and COMPACT_MAX_AGE_SECONDS.
- Automatic database updates additionally require absolute COMPACT_UPDATER and
  positive COMPACT_LINE_BYTES, COMPACT_CONNECT_SECONDS,
  COMPACT_LOW_SPEED_SECONDS and COMPACT_MAX_ATTEMPTS. Missing update settings
  leave scanning available and make database update attempts fail closed.
- Automatic native code updates additionally use COMPACT_PROGRAMS, an absolute
  private directory; COMPACT_RELEASE_PUBLIC_KEY, the canonical base64 32-byte
  Ed25519 public key for the selected channel; and COMPACT_RELEASE_CHANNEL,
  stable by default or explicitly opted-in preview. Supply positive policy values
  for COMPACT_CODE_STAGING_BYTES, COMPACT_CODE_UPDATE_SECONDS and
  COMPACT_CODE_CHECK_SECONDS. The code check has its own bounded lease, followed
  by the database update lease. Include both in the admin proxy deadline.
  OpenSSL with Ed25519 support must be installed in the service image. A missing
  key disables only code fetching. Invalid signatures, unavailable releases,
  code allocation failures or failed candidate validation retain the active code
  and still attempt database maintenance with the active runtime.
- Set COMPACT_PUBLIC_HOST and COMPACT_PROXY_BODY_LIMIT for Caddy. Configure TLS,
  ingress connection/concurrency limits, disk/account quotas and process memory
  accounting from the actual deployment policy. The proxy body limit must agree
  with the gateway input ceiling. Request deadlines include upload and scanning.

Native address-space ceilings are per process; the service/container budget must
also account for Python, the proxy, transport buffers and other processes. The
native worker retains one engine and is recycled at its configured request or
native lifetime limit. Profile or active-generation changes replace the worker.
The gateway stops the resident worker before updating. Its asynchronous lock and
the native state/job.lock serialize scans and updates.

## HTTP protocol

Every endpoint requires Authorization: Bearer <credential>. Duplicate headers
are rejected. All responses are JSON and are marked no-store.

- POST /v1/scan?profile=full or profile=pdf-jpeg-png-pe-exclusions uses the scan
  credential, a decimal Content-Length and the lowercase SHA256 of the exact
  request bytes in X-Content-SHA256. Omitting profile selects full. The original
  hash, size, generation, requested/effective profile, completion and native
  request ID are checked before returning a result. Qualified clean, detected
  and held are distinct outcomes; HTTP 200 alone does not mean clean.
- GET /v1/status uses the scan credential and reports busy state.
- POST /v1/update uses only the separate admin credential and accepts no query
  options. All update arguments come from configured policy. The native updater
  retains upstream cooldown state. A transport timeout can happen after atomic
  activation, so an unconfirmed response requires checking the active generation
  rather than assuming that the old generation is still current.

Busy operations return 503, malformed identities/queries return 400, oversized
inputs return 413 and authentication failures return 401. Input, output,
subprocess diagnostics and deadlines are bounded. Subprocesses are killed and
reaped on failure, timeout, cancellation and service shutdown.

## Deployment and verification

The administrative update checks the fixed Barbarrosa/clamav GitHub release
channel, authenticates the exact manifest bytes with the configured Ed25519 key,
and downloads only individually hashed files from that release. It accepts the
linux-x86_64-glibc2.36 target on a compatible Linux host, validates file paths,
modes, sizes, SHA256 identities and package requirements, and stores immutable
programs/releases/pkg-<manifest SHA256> directories. It persists accepted sequence
floors, expiration checks, poll scheduling and GitHub rate-limit retry times.
Preview discovery pages three releases at a time, at most 20 pages, within the
same configured deadline and per-response metadata ceiling.
A trust root is never fetched beside the release. Channel/key rotation is an
operator configuration change. Absent configured publisher keys, releases remain
unsigned pending CI artifacts and are not installable by this client.

Staging a program does not activate it. The candidate scanner and updater verify
and build the matching database generation, passing its program ID to the native
atomic current.json switch. Subsequent workers derive both their executable and
certificate directory from that pointer. Failed or interrupted code work leaves
the active tuple usable; database updates continue with the active runtime.
The status endpoint and administrative result report the code-update state
separately. No accepted original or published release is purged to make space.

Schedule a fixed administrative POST from the operator's cron at the interval
chosen by the deployment policy. Keep its distinct admin credential in an owned
0600 curl configuration outside the document root, containing a fixed HTTPS URL,
request = "POST", and header = "Authorization: Bearer <admin secret>". A reference
cron command is:

    /usr/bin/curl --config /private/compact/admin-update.curl --proto '=https' --fail-with-body --silent --show-error

Do not put the secret in a URL or the cron command line. Configure its deadline
from the combined code/database leases. GitHub code polling and FreshClam
cooldowns remain persistent even if cron calls more often. Signed publication is
still an operator-controlled release workflow; the service automatically consumes
those authenticated releases and never builds code on the deployment host.
Live TLS, CDN reachability, provider quotas and process limits must be checked on
the actual deployment.

Run python3 compact-integration/tests/test_gateway.py. The 13 tests cover
credentials, streaming identities, malformed queries, disk and size envelopes,
private temporary cleanup, contention, worker request IDs/profile rotation,
stdout/stderr floods, timeouts, cancellation and process-group fallback cleanup.
A separate authentic signed/native probe passed clean PDF, held PE and clean PDF
in one reused worker, with matching request IDs and deletion after every request.
That is ASGI/native integration evidence; it does not claim live HTTP/TLS testing.
Run python3 compact-integration/tests/test_release_client.py for actual ephemeral
Ed25519 signature checks, path/identity/expiry/replay and allocation failures,
HTTP parser bounds/rate limits, candidate tuple activation and failed-code
fallback to active-code database maintenance. GitHub transport and native tuple
operations in that focused suite are explicit fixtures.
