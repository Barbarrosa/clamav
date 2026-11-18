# Native builds and releases

The fork's `upstream-optimized` default branch holds upstream source plus the
additive `compact-integration` controls. The build materializer archives the full
upstream commit recorded in `manifest.json`, checks every patch checksum and
original Git blob, and applies the ordered queue in a disposable tree. A changed
preimage is an adaptation failure, even when Git could apply a patch at an offset.
The tracking checkout is never patched by the build.

`compact-upstream.yml` checks upstream daily and proposes a pin update. Its bot
explicitly dispatches qualification because PRs created with `GITHUB_TOKEN` do
not generate another ordinary PR run. The tracker does not resolve conflicts,
merge its PR, publish databases, or deploy anything. On drift, qualification also
builds a separate unmodified upstream control. That control does not certify the
optimized adapter or reduced profile and cannot become an optimized release.

Tracking is resumable after a permissions or dispatch failure. If a previous run
pushed its proposal but could not open the PR, the next run reuses that exact
commit after verifying the intended upstream pin, unchanged patch inventory,
pending qualification and manifest-only changes. It never force-pushes over an
existing branch; unexpected orphan-branch edits require manual review. Existing
open PRs may contain deliberate adaptations and are preserved.

The tracker checks native qualification for the exact proposal head. An active
or successful run is reused; a missing, failed or cancelled run can be dispatched
again, including when the PR already exists. The workflow tests these recovery
paths before creating or resuming a proposal. Repository Actions settings must
permit PR creation; the workflow already requests the scoped content, PR and
Actions permissions and uses `GITHUB_TOKEN`, without an additional personal token.

## Qualification and pending artifacts

`compact-native.yml` builds with the recorded Rust 1.90.0 Bookworm image digest
and exact Debian package versions. The lock records the successful development
container; unavailable package versions fail the build instead of drifting to
another dependency. Dependency updates need their own reviewed lock change.

The workflow runs the C and Rust suites, scanner/sigtool tests, C/Rust layout
checks, source-order regression, preparation and production-guard tests, and a
paired pristine upstream build. The updater phase disconnects external networking
and enforces a 512 MiB container limit while running synthetic orchestration,
signed local FreshClam mirror, and real streaming-parser tests. These fixtures do
not establish a worst-case memory bound for future production databases.

The initial integration is experimental. `qualify.py` does not set stable,
SiteGround, or reduced-disposition qualification merely because regressions pass.
The corresponding deployment and profile gates remain explicit.

Packaging includes the native scanner/update commands, recursive non-platform
shared libraries, matching Debian source archives, copyright notices, the complete
modified ClamAV source, vendored Cargo sources, the build recipe, an SPDX SBOM,
and provenance. Source collection uses the same official Debian repositories
inside the disposable builder. If an exact installed dependency source is no
longer available, packaging fails; do not substitute a different source version.

No database snapshot is part of a release. Installations use FreshClam directly;
CI uses local fixtures rather than requesting daily databases repeatedly.

The installer consumes individual signed-manifest files. It never extracts the
CI transport tar. The two small `bin/` launchers resolve their own absolute bundle
directory, set its library path, and execute the corresponding immutable native
program in `lib/`. Platform libraries (glibc/loader, libgcc, libstdc++) remain host
requirements. The first target is **linux-x86_64-glibc2.36**; it is a tested build
target, not a claim that every SiteGround plan can execute it. Failed preflight,
missing runtime capabilities, or budget failures retain the remote/hold route.

Launchers also set `CURL_CA_BUNDLE` to `lib/tls-ca-bundle.crt`, assembled only from
public Mozilla roots in the pinned Debian `ca-certificates` package. Its exact
source package and notice accompany the release. TLS roots are kept outside the
`certs/` directory used for ClamAV database signing trust; local builder/proxy
certificates are excluded.

## Manifest and trust

Native tags are `compact-v<SemVer>`; the initial candidate is
`compact-v0.1.0`. Every published rebuild gets a new version, including an
upstream-only rebuild. The exact upstream and integration commits are in the
manifest. Tags and published release assets must be immutable.

Both channels use assets named `manifest.json` and `manifest.sig`. The latter is
the raw 64-byte Ed25519 signature of the exact manifest bytes. The protocol is:

```json
{
  "protocol": 1,
  "sequence": 1,
  "expires_at": 1900000000,
  "version": "0.1.0",
  "channel": "preview",
  "platform": "linux-x86_64-glibc2.36",
  "repository": "Barbarrosa/clamav",
  "files": [
    {
      "path": "bin/compact-scan",
      "size": 123,
      "sha256": "full-lowercase-SHA-256",
      "mode": "0500",
      "url": "https://github.com/Barbarrosa/clamav/releases/download/compact-v0.1.0/<sha-prefix16>--compact-scan"
    }
  ]
}
```

The package also requires `bin/compact-update`. Libraries, certificates and
notices use mode `0400`, with executable programs using `0500`. Extra signed
metadata binds the source archives, SBOM, qualification report and provenance.
The monotonic sequence and expiration are independently checked by the updater.
Manifests must not be parsed and reserialized before signature verification.

GitHub authentication grants access to release assets. It does not replace the
bundled Ed25519 public-key trust root. GitHub build attestations additionally bind
the candidate and manifest to the expected qualification workflow and original
source commit. The promotion workflow verifies both identities before signing.

## Protected promotion

Create `compact-preview` and `compact-stable` environments restricted to protected
branches; stable additionally needs required reviewers. Store each channel's
separate sodium secret key as the environment secret `COMPACT_SIGNING_KEY_B64`
(base64 of the 64-byte secret key) and its public key as the environment variable
`COMPACT_RELEASE_PUBLIC_KEY_B64`. Do not put private keys in source, logs, release
assets, repository-wide secrets, or chat. Install matching channel public keys in
the plugin through the reviewed trust-root mechanism; key rotation requires a
trusted update, not an unsigned key downloaded beside a package.

Release keys and environments are not configured by these files. Without them,
CI produces **pending unsigned Actions artifacts** only. The signer exits without
creating a signature when its key is absent. Stable promotion also rejects an
incomplete stable qualification report.

To promote, select the successful default-branch qualification run, its exact
candidate archive SHA-256, version and channel in `compact-promote.yml`. Promotion
downloads and verifies that exact artifact; it does not rebuild it. After signing,
it creates the version tag, uploads all assets into a draft, then publishes the
signed preview/stable release. An interrupted draft can resume against the same
commit. A published version is never overwritten or retargeted.

The workflows contain no WordPress/site deployment. Publishing a GitHub release,
installing a package, preparing a database generation, and activating the paired
program/generation are separate operations.
