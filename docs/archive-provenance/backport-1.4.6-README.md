# ClamAV 1.4.6 Legal Redress backport

Complete custom source plus a patch against official tag `clamav-1.4.6`.
Read [build/configuration instructions](source/tools/subset-selector/README.md) and
[validation, compatibility limits and measurements](source/docs/legal-redress-backport.md).

Full database mode is the default; opt in with `--database-profile=legal-redress`.
Reduced no-detection results remain held. This is experimental, not production
approval. Synthetic first-hit results can differ, including weak/strong selection
on stable; accepting all-match detection equivalence is the tested contract.
LTS exposes its legacy return-code/named-evidence API without invented severity.

Validation: 65 boundary cases plus mutation, handler and PE-in-PE limit controls;
414 exact full comparisons on the 138-file corpus against this unmodified release;
30 eligible reduced comparisons and 108 held cases; 12 real intake scans with original
bytes preserved; signed-input and tamper tests; 88 shared Python tests; core engine,
Rust, scanner and sigtool suites. Daemon/update operations remain unqualified here.

Build `source/` directly, or apply `backport.patch` with `git apply --index` to an
unmodified checkout of `5853e1396777bae4d909cd3dd44f58352e7cf9b3`. The patch was applied to a fresh Git index and
its resulting tree verified as `a5ee208455c4ffd19eba322605e386a5d63916a8`. Backport commit: `a5aa6b77ed582cd056b95aba246ed922dc78c94e`.
`source-manifest.json` covers every source file. Official databases and native
binaries are not bundled; prepare a fresh signed generation using your built engine.
Earlier 1.6 performance images are not measurements of this release backport.
