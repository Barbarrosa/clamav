# Top-six investigation evidence

These files record **separate, bounded investigations**. They are not a combined
proof that a new scanner configuration satisfies every requirement. Read the
[plain-language findings](../top-six-memory-investigation.md) first.

| Evidence | Meaning and limitation |
|---|---|
| [Directory correctness](directory-correctness/summary.json) | Original distinct-artifact comparison: all 23 cases and 92 observations match. It covers the named synthetic fixtures, not all possible databases or inputs. |
| [Rejected allocation classes](rejected-tight-classes/summary.json) | Four of 23 cases differ; the candidate was reverted. Sanitizers cannot repair these behavioral failures. |
| [Original nine-file screen](original-smoke/summary.json) | Preserves the initial ~29 MiB resident-memory reduction **and** slower warm-scan observation. It used an earlier measurement protocol and is not qualification. |
| [Final full-corpus screen and fresh correctness](final/README.md) | All 978 scan observations agree across three engines and targeted correctness passes 23/23. The candidate uses about 29 MiB less RAM, but observed startup/first-pass costs fail the performance gate. One round does not establish causation or complete qualification. |
| [Resource audit](source-audit/directory-resource-audit.json) | Source-relative ownership, scratch and complexity reasoning. It does not invent absolute zero-byte scan scratch or prove a timing bound. |
| [Query code audit](source-audit/query-code-audit.json) | Binds earlier retained/candidate artifacts and checked source/machine-code paths. Source unchanged and normalized control flow do not prove hardware time equality. |
| [Allocator sanitizer reports](allocator-tests) | Targeted reclaim, flush and rejected-class tests. These are component checks, not whole-engine speed or correctness qualification. |
| [Test audit](test-audit.json) | Records actual suite results, missing upstream fixtures and sandbox restrictions. An environmental failure is not a pass; see later restoration/retry evidence if present. |
| [Final default build](default-build/README.md) | The normal retention-ON build passes all four core test groups; no new memory saving is promoted. |
| [Restored-fixture tests](tests/README.md) | C library, scanner and signature-tool groups pass after exact missing upstream fixtures are restored; Rust passes 67 tests. Socket-dependent application checks remain blocked. |

The plans bind artifacts, source hashes, signed-input hashes, observed limits and
fixture manifests. They retain workspace paths for reproduction; those paths
are not portable installation defaults. Old reports refer to their **own**
library hashes rather than the final rebuilt library. The callback summaries
retain ordered and multiset digests; large synthetic callback transcripts remain
in the execution workspace.

`raw-observations.tar.gz` files contain only the corresponding top-level process
records, JSONL observations and stderr. `test-run-logs.tar.gz` keeps selected test
logs, including failed attempts. No signed databases, signature-name tables,
native-address captures, synthetic fixture directories or executable artifacts
are included. [The SHA-256 manifest](evidence-sha256.json) binds every included
file and archive member without rewriting the original reports.

The names, tokens and logical-directory investigations have their own linked
reports and artifact manifests alongside their explanatory documents.
