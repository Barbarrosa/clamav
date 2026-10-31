# Evidence scope

These are recorded observations for the repair and standalone representation
experiments described in `../regression-fix-and-memory-frontier.md`.

- `regression-memory.json`: three fresh-process official-database trials per
  build; binary hashes, database hashes, RSS and timing observations.
- `regression-performance.json`: 30 randomized pairs per synthetic input;
  full observations and bootstrap intervals. The source revision field reflects
  the working tree's base when the repaired binary was built; its hash identifies
  the tested binary. The repair was subsequently committed as `9c705c5`.
- `regression-severity.json` and `regression-order.json`: mixed-severity and
  ordered-output differential fixtures. Harmless input and generated local rules.
- `default-c-tests.log`, `native-c-tests.log`, `default-integration.log`,
  `asan-matchers.log`, `asan-regex.log`: successful validation transcripts.
- `encoding-census.jsonl`: compiled structure counts and encoding properties.
- `encoding-feasibility.json`: exact token deduplication and name front-coding
  calculations. Excludes integration overhead and stable decoded name storage.
- `name-codec.jsonl`: actual FSST/OptFSST encoding and full round-trip comparison
  for every exported name. Its single timing observations are not a release gate.
- `short-anchor-routing.jsonl` and `frontier-summary.json`: isolated exact
  routing table experiment, three longer PE streams, and paired microbenchmarks.
  These count table bytes, not whole-scanner memory, and do not integrate the
  representation into the scanner.

The snapshot contains main v63, daily v28164 and bytecode v339. See the earlier
`../demand-results/database-provenance.json` for retrieval provenance and the
earlier report for normal CVD verification. No raw official signature exports
are included. This is not a claim that the snapshot is the newest available
database or that another version has the same memory composition.

CPU and toolchain information are in the synthetic result. Tests used GCC 13.3
and Rust 1.90.0. The routing probe uses `-O3 -mpopcnt`, pinned CPU 2, no concurrent
local build/test job, and alternating timing order. Other host activity is not
under our control. Its results do not establish adversarial or end-to-end latency.
The OptFSST probe uses the author's repository commit
`be06199760288005e2ebdc11fbd0f087903c0476`, C++20 and
`-DFSST_DISABLE_AVX512=1`. Author code is not included in this fork.

Sanitizer coverage is limited to the indicated C suites with leak detection
disabled; Rust and every parser were not fully instrumented. The repaired
disposable-pool configuration has not been separately runtime-qualified.
