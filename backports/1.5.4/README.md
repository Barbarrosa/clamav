# ClamAV 1.5.4 Legal Redress backport

This directory contains the source patch and revision metadata against official tag `clamav-1.5.4`.
Apply `backport.patch` to a checkout of the exact upstream revision below.
The resulting tree contains `tools/subset-selector/README.md` and
`docs/legal-redress-backport.md`. See also the combined
[validation report](../../docs/boundary-backports.md).

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

Apply `backport.patch` with `git apply --index` to an
unmodified checkout of `fa59fca15872bb8a914ba4c68188bcc8a502cbdf`. The patch was applied to a fresh Git index and
its resulting tree verified as `51e985888344c2e7964538ad458289b590a2984c`. Backport commit: `ef83184a457e762f95cc7807ed678020497cea33`.
The separately supplied release archive includes `source-manifest.json`;
`archive.json` here records its identity and checksum. Official databases and native
binaries are not bundled; prepare a fresh signed generation using your built engine.
Earlier 1.6 performance images are not measurements of this release backport.
