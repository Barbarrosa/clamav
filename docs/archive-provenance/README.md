# Archived project provenance

This branch imports version 16 of `ClamAV-engine-foundations.zip`. Its retained
engine, Legal Redress adapter, tests and recorded performance results are unchanged.
The original Git bundle starts at a recovery snapshot rather than upstream history.
The recovery snapshot is attached to the fork's matching upstream base, and its
descendants' parent references are rewritten. Every imported commit retains its
exact tree, attribution, dates and message. `lineage.json` maps the old and new IDs.
The original source tip was `b20af8340e37048864ad400735e25c3d083c8342`, with tree
`c2092d7375743604be0636b9eac62439ec617a69`.

The final packaging commit adds archive research appendices, stable/LTS backport
patches and this provenance. It does not implement the proposed SAT-based optimizer
or change engine behavior. The archive's original `changes.patch` is retained in `patches/`, including
attribution predating the recovered history. Later incremental patch exports are
omitted because their changes are already preserved in the imported commits. Original archive metadata
and README are retained verbatim; their `source/` paths refer to the archive layout.
In this Git branch, the engine source is at repository root.

The archive's source manifest records raw archive bytes. Seventeen historical
Windows/resource files differ only in CRLF/LF normalization in the saved Git tree;
that pre-existing difference is recorded in `archive-preservation.json`.

The Legal Redress profile remains experimental: reduced no-detection results are
held, and the documented production gates remain in effect. See
[configuration](../../tools/subset-selector/README.md),
[release status](../production-readiness.md),
[boundary/backport validation](../boundary-backports.md), and
[measured performance](../three-way-performance.md).

Before preparing this branch, the 35 selector, 18 configuration/equivalence and
35 hardening tests were rerun. Existing native-engine, boundary and benchmark
evidence is preserved; those historical measurements were not rerun for publication.
