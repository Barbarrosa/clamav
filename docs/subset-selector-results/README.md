# Evidence index

- `summary.json`: consolidated measured results and qualification status.
- `database-manifest.json`: final selector 1.1 preparation, signed input hashes/versions, full-load test, per-member inventory and reasons.
- `benchmark-database-manifest.json`: generation used during the paired runs. Final 1.1 exclusions are byte-identical; 1.1 adds mandatory full validation and probe binding.
- `accepted-bench/`: 28 valid files, 504 scans per variant, three fresh processes each. Use these scan timings for the matched workload comparison.
- `bench/`: 40-file mixed/adverse set, lifecycle/FreshClam overlaps and 89 official positive fixtures. Held work is not a valid equivalent throughput optimization.
- `integration-gate/summary.json`: 10,000-rule selected-name/order/severity/callback comparison. `qualification_passed:false`; required-equivalence exit code is 3.
- `integration-asan/`: 300-rule instrumented harness tests, existing engine uninstrumented, leak detection disabled. Mechanical tests pass; exact order still fails.
- `census-*.jsonl`: paired current-default compiled payload inventories; do not use their diagnostic RSS as benchmark RSS.
- `extra-*.jsonl`: broad document compatibility, encrypted/malformed ZIP, audio hold, recursion-limit tests.
- `unit-tests-final.log`, `retained-ctest-fixed.log`: selector and retained suites. The first ctest invocation's missing pytest path is retained separately.
- `signed-input-tests.*`, `cld-verification.json`: actual CVD integrity rejection and CLD transport verification.
- `intake-output.json`: synthetic intake snapshot/result; `linux_process_high_water_kib` records separate parent/child maxima. Original bytes and metadata remain preserved.
- `intake-memory.json`: simultaneous descendant RSS sampling unavailable in this environment, never a zero-memory claim.
- `skip.tsv.gz`, `decisions.sqlite.gz`: deterministic exclusions and queryable per-name explanations, with no official signature bodies.
- `*-manifest.json`: generated fixture names, sizes and SHA-256; generators are in `tools/subset-selector/`.

Machine paths in raw observations identify the actual experiment, not a promise that those paths persist. Regenerate fixtures using the supplied code. CVDs, databases' signature bodies, local build dependencies, binaries and real submissions are excluded. Original project history/evidence is preserved.
