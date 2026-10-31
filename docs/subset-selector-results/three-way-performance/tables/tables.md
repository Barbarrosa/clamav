# Fresh three-way ClamAV measurements

Same host, pinned source revisions, signed database snapshot and 28-file workload. Means except where labeled.

## Database and lifecycle

| Metric | Original ClamAV | New · full DB | New · Legal Redress |
|---|---:|---:|---:|
| Engine-counted signatures loaded | 3,628,192 | 3,628,192 | 601,004 |
| Signatures loaded (% of full) | 100.00% | 100.00% | 16.56% |
| Signed database bytes retained | 107.573 MiB · 100% | 107.573 MiB · 100% | 107.573 MiB · 100% |
| Compiled engine RSS (MiB, mean) | 959.6 | 791.2 | 131.1 |
| Construction peak RSS (MiB, max) | 959.9 | 825.2 | 162.2 |
| Peak through accepted scans (MiB, max) | 974.4 | 825.2 | 162.2 |
| Two-engine reload peak RSS (MiB, max) | 1,916.1 | 1,613.2 | 304.6 |
| Reload wall time (s, mean) | 8.302 | 7.922 | 3.522 |
| Reload CPU time (s, mean) | 8.262 | 7.912 | 3.516 |
| Two engines + update test peak RSS (MiB) | 2,564.9 | 2,120.1 | 800.1 |

## OS file-page cache: empty → hydrated

Metadata enabled; ClamAV clean-result cache disabled. CPU utilization uses one core as 100%.

| Metric | Original ClamAV | New · full DB | New · Legal Redress |
|---|---:|---:|---:|
| DB page-cache RAM before load (MiB) | 0.00 → 107.58 | 0.00 → 107.58 | 0.00 → 107.58 |
| Input page-cache RAM before scan (MiB) | 0.00 → 14.18 | 0.00 → 14.18 | 0.00 → 14.18 |
| Startup wall time (s, mean) | 8.621 → 7.935 | 7.860 → 14.733 | 3.682 → 3.491 |
| Startup wall time (s, median) | 8.119 → 7.880 | 7.853 → 7.841 | 3.490 → 3.486 |
| Startup CPU time (s, mean) | 8.437 → 7.927 | 7.674 → 14.340 | 3.645 → 3.488 |
| Startup CPU time (s, median) | 7.980 → 7.873 | 7.658 → 7.835 | 3.446 → 3.483 |
| Startup CPU utilization (%) | 97.9 → 99.9 | 97.6 → 99.0 | 99.0 → 99.9 |
| Post-startup RSS (MiB) | 959.6 → 959.6 | 791.2 → 791.1 | 131.1 → 131.2 |
| Post-startup PSS (MiB) | 958.1 → 958.0 | 789.7 → 789.6 | 129.5 → 129.6 |
| 28-file scan wall time (s, mean) | 1.810 → 1.764 | 1.981 → 1.703 | 1.682 → 2.109 |
| 28-file scan wall time (s, median) | 1.788 → 1.762 | 1.665 → 1.609 | 1.629 → 1.609 |
| 28-file scan CPU time (s, mean) | 1.769 → 1.762 | 1.897 → 1.698 | 1.650 → 2.077 |
| 28-file scan CPU time (s, median) | 1.758 → 1.761 | 1.618 → 1.608 | 1.609 → 1.608 |
| Scan CPU utilization (%) | 97.8 → 99.9 | 96.7 → 99.8 | 98.2 → 99.5 |
| Post-scan RSS (MiB) | 967.1 → 967.1 | 809.2 → 809.2 | 149.2 → 149.2 |
| Post-scan PSS (MiB) | 965.5 → 965.5 | 807.6 → 807.6 | 147.6 → 147.6 |
| Post-scan USS (MiB) | 964.6 → 964.6 | 806.8 → 806.8 | 146.8 → 146.7 |
| Input block reads (MiB per batch) | 14.18 → 0.00 | 14.18 → 0.00 | 14.18 → 0.00 |
| Per-file median latency (ms) | 10.78 → 10.57 | 10.74 → 10.41 | 10.59 → 10.45 |
| Per-file p95 latency (ms) | 385.54 → 360.02 | 428.35 → 342.64 | 348.64 → 341.17 |
| Per-file p99 latency (ms) | 754.74 → 758.20 | 709.12 → 638.81 | 636.84 → 773.01 |
| Hydrated scan throughput (MiB/s) | 8.03 | 8.32 | 6.71 |

## ClamAV clean-result cache: empty → hydrated

Diagnostic only: metadata disabled, OS input pages hydrated in both states. Not the evidence-preserving release configuration.

| Metric | Original ClamAV | New · full DB | New · Legal Redress |
|---|---:|---:|---:|
| Initial empty-cache engine RSS (MiB) | 965.6 | 797.4 | 137.0 |
| 28-file scan wall time (s) | 1.758 → 0.050 | 1.618 → 0.051 | 1.601 → 0.051 |
| 28-file scan CPU time (s) | 1.757 → 0.050 | 1.617 → 0.050 | 1.599 → 0.051 |
| Scan CPU utilization (%) | 99.9 → 99.7 | 99.9 → 99.6 | 99.9 → 99.7 |
| Post-scan RSS (MiB) | 973.0 → 973.0 | 815.1 → 815.1 | 154.6 → 154.6 |
| Post-scan PSS (MiB) | 971.4 → 971.4 | 813.6 → 813.6 | 153.0 → 153.0 |
| Post-scan USS (MiB) | 970.6 → 970.6 | 812.8 → 812.8 | 152.2 → 152.2 |
| Input block reads (MiB per batch) | 0.00 → 0.00 | 0.00 → 0.00 | 0.00 → 0.00 |
| Verified root cache-hit rate | 0% → 100% | 0% → 100% | 0% → 100% |
| Warmed-workload CPU reduction | 97.13% | 96.88% | 96.81% |
| Configured cache entry capacity | 65,536 | 65,536 | 65,536 |
