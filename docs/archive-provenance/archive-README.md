# ClamAV boundary test and Legal Redress backports

The PE exclusion boundary test is implemented and passes on the retained engine
and custom stable 1.5.4 / LTS 1.4.6 backports. Read
[the report](source/docs/boundary-backports.md) and
[raw validation summary](source/docs/subset-selector-results/boundary-backports/summary.json).
The [build instructions](source/tools/subset-selector/README.md) retain the opt-in
`--database-profile=legal-redress` flag; full remains the default.

Validation: 65 boundary cases per engine plus mutation, handler and PE-in-PE limit
controls; 88 shared Python tests; 414 exact full corpus comparisons per engine;
30 eligible reduced comparisons and 108 held cases per engine; 12 real intake scans
per engine with original bytes preserved; signed-input and tamper checks.

**Still experimental, not production approval.** Synthetic first-hit results can
differ, including weak/strong severity on stable; all-match detection contracts
pass. Shared parser limitations remain, reduced no-detection results stay held,
and daemon/update/deployment isolation and recovery require qualification.

Release patches and exact revision metadata are in `backports/1.5.4/` and
`backports/1.4.6/`. The separately supplied release archives contain their complete
source and evidence. The main `source/` remains the existing retained development
project. Its engine is unchanged in this revision. Rebuild the adapter and regenerate
signed generations for selector 1.4 before use.

The previous three-way performance tables/images and all history are preserved.
New integration CPU/RAM observations are explicitly scoped and are not a new cache
benchmark or a 303 MiB memory cap. No live service or real complaint data was changed.

Input v15 metadata is in `history/boundary-backports-input-v15/`.
`boundary-backports.patch` applies to `777cba95f55563f0b93d814d5eb86697d8c2ac87` and reproduces the main source tree.
Current main source: `b20af8340e37048864ad400735e25c3d083c8342`.
