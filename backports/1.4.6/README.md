# ClamAV 1.4.6 PDF/JPEG/PNG with PE exclusions backport

This directory contains the source patch and revision metadata against official tag `clamav-1.4.6`.
Apply `backport.patch` to a checkout of the exact upstream revision below.
The resulting tree contains `tools/subset-selector/README.md` and
`docs/pdf-jpeg-png-pe-exclusions-backport.md`. See also the combined
[validation report](../../docs/boundary-backports.md).

Full database mode is the default; opt in with `--database-profile=pdf-jpeg-png-pe-exclusions`.
Reduced no-detection results remain held. This is experimental, not production
approval. Synthetic first-hit results can differ, including weak/strong selection
on stable; accepting all-match detection equivalence is the tested contract.
LTS exposes its legacy return-code/named-evidence API without invented severity.

Validation: 65 boundary cases plus mutation, handler and PE-in-PE limit controls;
414 exact full comparisons on the 138-file corpus against this unmodified release;
30 eligible reduced comparisons and 108 held cases; 12 real intake scans with original
bytes preserved; signed-input and tamper tests; 88 shared Python tests; core engine,
Rust, scanner and sigtool suites. Daemon/update operations remain unqualified here.

Apply `backport.patch` with `git apply --index` to an
unmodified checkout of `5853e1396777bae4d909cd3dd44f58352e7cf9b3`. The original, pre-rename patch was applied to a fresh Git index and
its resulting tree verified as `a5ee208455c4ffd19eba322605e386a5d63916a8`. Backport commit: `a5aa6b77ed582cd056b95aba246ed922dc78c94e`.
The separately supplied release archive includes `source-manifest.json`;
`archive.json` here records its identity and checksum. Official databases and native
binaries are not bundled; prepare a fresh signed generation using your built engine.
Earlier 1.6 performance images are not measurements of this release backport.

## Profile-name update

The current patch uses `--database-profile=pdf-jpeg-png-pe-exclusions` and the
`pdf-jpeg-png-pe-exclusions-hold-v1` profile identity. This describes the allowed root
file types and the conservative omission of eligible PE-specific rules. The full
database default, accepting all-match behavior and held no-detection policy are
unchanged. Regenerate prepared generations after rebuilding the probe/library.

`archive.json` and `revision.json` describe the original release archive and
pre-rename patch, including their original names, checksums and source-tree IDs.
They do not describe the rewritten patch. Embedded `docs/backport-results/`
measurements are also preserved as historical evidence.
[Current patch identity and validation scope](profile-rename.json) records the
new checksum. The option rename has not rerun the full release-engine matrix.
