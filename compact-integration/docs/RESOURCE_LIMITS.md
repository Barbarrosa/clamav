# Native resource and lifetime limits

Production scan, worker, preparation and validation commands receive explicit
AS, CPU, wall and per-file limits from the caller. AS is a hard **per-process
address-space** limit. It bounds an individual process's resident memory but is
not an aggregate account RSS allocation. The caller must admit work before
starting processes, reserve account headroom, and serialize work across its
native state/account. Multiple private state directories are separate lock
domains; client requests cannot choose their state path.
An application policy that reserves 20% of confirmed RAM is headroom, not a
kernel account quota. PHP/Python, maintenance coordinators, unrelated account
work, and filesystem/page-cache charges also need room. A hosting account or
cgroup ceiling must be confirmed separately; a successful per-process cap does
not certify their aggregate memory usage.

Commands using state acquire or validate `STATE/job.lock` before parser/module
initialization and engine hashing. Busy commands reject before that work. The
descriptor stays open through engine destruction, allocator cleanup and `atexit`;
process exit releases it. A scanner owns one engine, a persistent worker reuses
that engine, and the bounded validator has only one engine-bearing child at a
time. Updater/coordinator metadata processes can also be resident, so maintenance
needs its own account headroom. There is no new tree-RSS guarantee.

The effective CPU allowance cannot exceed an inherited kernel hard limit.
Limits applied inside a child reflect the actual clamped allowance back into
its in-memory policy. Batch/update accounting sums self and reaped-child user and
system CPU in integer microseconds. Each child receives the remaining whole
seconds rounded down; less than one second cannot fund another batch. The
coordinator checks again after reaping and before reporting success. Scans also
check the worker's cumulative allowance before work and before accepting a
completed verdict. A resource-exhausted original never becomes clean.

The wall deadline remains active through output and process cleanup. Fatal
handlers attempt a nonblocking failure record and then exit, including when the
supervisor's output pipe is full. Missing or partial output is failure, never
scan approval. Early startup rejection also uses best-effort nonblocking output.

Workers have an idle wall timeout and a fresh processing wall allowance once a
valid private request arrives. Waiting consumes the idle envelope, not the next
original's processing envelope. CPU and address-space limits span the entire
worker lifetime, and `--worker-max-requests` still bounds reuse. Exhausted workers
must be reaped before replacement; their budget is not reset for each original.

Trusted callers can set `COMPACT_PARENT_PID` to their own positive PID in the
native process's PID namespace. It must be replaced at every direct native spawn,
not copied from an earlier ancestor. The native process checks the expected PID
around parent-death registration and rejects prior adoption, including adoption
by a non-PID-1 subreaper. Internal native forks capture the creator PID before
forking and pass it explicitly; updater execs replace the environment value.
Without this optional caller binding, a standalone command registers its current
parent, so it cannot identify adoption that occurred before entry. PHP and the
authenticated gateway supply the binding and still supervise/reap their children.

Parser limits are unchanged: 100 MiB original/member size, 400 MiB cumulative
scan size, 10,000 scanned files/layers, recursion limit 17, and a 90-second native
scan limit. Smaller caller CPU/wall/AS/file limits can stop work sooner. The
per-file filesystem limit is not an aggregate expanded-data or scratch quota.
Scan options, cryptographic validation, official bytes, selected signatures,
PE guards and coverage rules are unchanged. `doctor` without state remains an
operator diagnostic; production supervision supplies state and limits.

## Regression checks

```sh
sh compact-integration/tests/test_cpu_parent.sh
python3 -m unittest discover -s compact-integration/tests -p test_update.py -v
python3 compact-integration/tests/test_native_dos.py \
  --scanner MATCHING_COMPACT_SCAN --updater MATCHING_COMPACT_UPDATE \
  --source PINNED_UPSTREAM_SOURCE --report FRESH_REPORT.json
```

The first runner checks inherited and fractional cumulative CPU, registration
after subreaper adoption, and registered-parent death. Updater tests include an
undrained stdout deadline and fetch-child cleanup. The lifecycle suite uses small
upstream TEST-signed CVDs, the isolated upstream TEST CA, normal authentication,
native stock loading and selected-engine compilation. Diagnostic-only preload
hooks delay engine freeing/`atexit` and input reads to verify lock ownership,
cheap busy rejection, idle/request deadlines, lifetime CPU and guard reset.
Production launchers remove those hooks from their environments. These tests do
not certify an actual SiteGround account or establish all-input parser completeness.
