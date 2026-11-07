# Evidence and reproduction

Read the [plain-language result](../system-model.md) first. This appendix records
the exact scope and commands. Run date: 2 November 2026 UTC.

## Published evidence

- [summary.json](summary.json): all four access-work profiles, byte accounting,
  field-program choices with raw arguments hashed, input hashes and source hashes.
- [scalar-validation.json](scalar-validation.json): 35,871,699 independent native
  scalar comparisons; generated diagnostic row IDs are checked separately.
- [rc2-witness-replay.json](rc2-witness-replay.json) and
  [cnf-witness-replay.json](cnf-witness-replay.json): complete reconstruction from
  each saved solver assignment, including original pointer words.
- [budget-query.json](budget-query.json): both unassisted SAT timeouts and the
  separately labelled known-witness extension check.
- [native-probes.json](native-probes.json): four C-reader probes and every trial.
- [provenance.json](provenance.json): signed database, build and source identities.
- [system-work16.wcnf.gz](system-work16.wcnf.gz): the actual global weighted
  formula, 7,723 variables and 23,831 hard clauses.
- [budget-165322848.cnf.gz](budget-165322848.cnf.gz): actual byte-budget formula,
  287,964 variables, 981,684 clauses, maximum width 3.
- [system-work16.model.json.gz](system-work16.model.json.gz) and
  [budget-165322848.model.json.gz](budget-165322848.model.json.gz): signed Boolean
  assignments. They contain no native pointer constants or signature bodies.
- [artifacts.json](artifacts.json): compressed and decompressed hashes.
- [published-verification.json](published-verification.json): independent clause
  evaluation of the published formulas and their complete assignments.
- [tests.log](tests.log): all 29 model tests passed.

Native snapshots, signature payloads, pointer constants, field images and the
private variable-to-program map are excluded. The numeric formulas and Boolean
answers can be checked independently without those files. Replaying the
representation against source records requires a fresh private capture.
Fresh process addresses can change the generated programs and exact counts.

## Model contract

The query is `GET(field, row)`. The six families contain 71 native fields:
patterns, candidate records, matcher nodes, logical records, extensions and
transition values. Their original storage totals 344,972,760 bytes. The capture
has 1,508,210 patterns, 2,279,919 candidates, 555,950 nodes, 312,310 logical
records, 17,509 extensions and 19,703,808 transition values.

Programs can store a packed column at any legal width, use a constant or row
arithmetic, use NULL-preserving base offsets, derive a field by XOR/addition from
another field, or keep exact sparse exceptions to another field. Every accepted
relationship is checked over all rows. Sampling only rejects candidate sparse
relationships; it can miss beneficial ones. Candidate constants and program
forms are bounded by the implementation, so the result is not a global optimum
over arbitrary compression or programs.

Boolean variables select each field's program and enforce one choice, bounded
dependency work, and no dependency cycles. Weighted clauses charge payload
bytes. The global formula includes all field variables, complete family models,
and native-provider alternatives; it does not merely choose between previously
solved family images. Header/descriptor costs, aligned payloads, bitmap/rank
structures and identity indexes are charged. Family models also solve
independently as a cross-check; there are no cross-family derived fields.

Each identity index has a 16-byte header plus 12 bytes per source object,
including original address keys and row indexes. The original engine directories remain charged.
Transition resolution uses the original row address plus transition coordinate.
Binary search can add up to 45 key/index reads. The field work score charges
payload words, dependency steps and declared integer operations, excluding
common descriptor dispatch and identity resolution. It is not hardware latency.

The known unchanged bytes total 309,403,757. Readable source spans are counted
by address union to avoid counting overlapping token/prefix spans twice.
Hash payload/capacity, original directories, filters and null arena slots are
additional explicit terms. Uncaptured engine, allocator, parser and process
memory is unknown. The 16-unit model has 165,322,848 provider bytes, hence
474,726,605 known bytes overall versus 654,376,517 originally.

Every named native byte is replayed; padding has no query contract. Native
pointer values are preserved as identity tokens, rather than merged using
equal names or contents. A replacement engine would need accessor/provider
adaptation before freeing the original records. Physical page reclamation and
scanner behavioral equivalence are not established by this model.

Lifecycle accounting assumes two generations with this captured generation's
dimensions. It includes simultaneous original and new provider storage during
conversion. It does not bound every possible changed database update. Three
mutable uint32 logical-slot arrays cost an additional 17,593,896 bytes per scan
worker; other scan state is unknown. There is no persistent decoded-field cache.
Whole-process empty/hydrated-cache RAM and measured reload peaks remain untested.

## Solver execution

Python-SAT 1.9.dev17 RC2 solved the combined 16-unit weighted model in about
0.45 seconds. Building candidates, solving all four profiles, serializing and
full reconstruction took about a minute. This does not include capture/build
time. RC2 reported the optimum within each generated candidate pool; there is
no separately exported optimality proof certificate.

The weighted budget was encoded into width-at-most-3 CNF. Unassisted Minisat22
timed out after 30 seconds at both 165,322,848 and 165,322,847 provider bytes.
Supplying RC2's original 7,723 variable values left 280,241 encoding variables
free; Minisat completed the first query in 0.0405 seconds. Every original and
encoded clause, and the weighted cost, was checked. This is a known-answer
verification result, not an unassisted search speed result.

The [linked construction](https://github.com/openai/math/blob/main/lean/docs/378.md)
was not executed. No counts were computed. The encoding preserves feasibility;
its auxiliary assignments must not be interpreted as distinct physical layouts.

## Reproduce the solver-only checks

From the repository root, with Python 3, NumPy 2.3.5 and python-sat 1.9.dev17:

```sh
python3 -m unittest discover -s tools/compact-memory/system-model -p 'test_*.py' -q
mkdir -m 700 /tmp/clamav-system-query
gzip -dc docs/system-model-results/system-work16.wcnf.gz > /tmp/clamav-system-query/system.wcnf
gzip -dc docs/system-model-results/system-work16.model.json.gz > /tmp/clamav-system-query/system.model.json
python3 tools/compact-memory/system-model/run_budget_query.py \
  --wcnf /tmp/clamav-system-query/system.wcnf \
  --budgets 165322848,165322847 --timeout 30 \
  --private-output /tmp/clamav-system-query/queries \
  --witness /tmp/clamav-system-query/system.model.json \
  --report /tmp/clamav-system-query/report.json
```

Timing and unassisted search outcomes can vary. The saved CNF and its assignment
also permit direct independent clause evaluation. The tests compare small
models against exhaustive answers and check packed widths, dependencies,
rank structures, malformed images and byte-budget boundaries.

## Reproduce the native capture and model

Use a matching Release/Ninja build of this source, default flat nodes, normal
development dependencies, unrar enabled and signature verification enabled.
The recorded run used GCC 14.2.0 and Rust 1.90.0. Build only the library if desired:

The directory-retention option below is required for internal capture/export.
Ordinary builds retire eligible construction indexes after compilation; those
private exporters fail with a rebuild instruction rather than export partial data.

```sh
cmake -S . -B ../clamav-system-build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_AC_DIRECTORY_RETENTION=ON \
  -DENABLE_LIBCLAMAV_ONLY=ON -DENABLE_TESTS=OFF -DENABLE_UNRAR=ON \
  -DCVD_CERTS_DIRECTORY="$PWD/certs"
cmake --build ../clamav-system-build --parallel 3
python3 tools/compact-memory/relink_internal.py \
  --build ../clamav-system-build --output ../clamav-system-diagnostic
```

Set `build_dir`, `diag_dir`, `db_dir` and `work_dir` to absolute paths. Use the
database hashes in provenance.json for the recorded historical snapshot
(main 63, daily 28164, bytecode 339). Normal `cl_load` verifies the signed CVDs;
the historical-age warning is expected. A current database is also a valid new
experiment, but will have different dimensions/results.

```sh
mkdir -m 700 "$work_dir/capture"
cc -std=c11 -fgnu89-inline -O2 -Wall -Wextra -Werror -DHAVE_CONFIG_H \
  -I"$build_dir" -I"$build_dir/libclamav" -Ilibclamav \
  -Ilibclamunrar_iface -Ilibclammspack \
  $(pkg-config --cflags json-c libxml-2.0) \
  tools/compact-memory/system-model/export_system_graph.c \
  -L"$diag_dir" -Wl,-rpath,"$diag_dir" -lclamav \
  -o "$work_dir/export-system-graph"
"$work_dir/export-system-graph" "$db_dir" "$PWD/certs" "$work_dir/capture" \
  > "$work_dir/export.log" 2>&1
python3 tools/compact-memory/system-model/verify_scalar_export.py \
  --capture "$work_dir/capture" --output "$work_dir/scalars.json"
python3 tools/compact-memory/system-model/run_system_model.py \
  --capture "$work_dir/capture" --private-output "$work_dir/plans" \
  --report "$work_dir/report" --depths 1,2,3,16 \
  --known-payload-budget-mib 202.042 --workers 1
python3 tools/compact-memory/system-model/replay_witness.py \
  --capture "$work_dir/capture" --plan "$work_dir/plans/work-16" \
  --assignment "$work_dir/plans/work-16/system.model.json" \
  --report "$work_dir/replay.json"
```

The exporter creates the graph, native-layout oracle and unchanged allocation
ledger from the same live compiled engine. Its optional final argument is a
skip-list TSV using the existing diagnostic callback namespaces; no skip list
was used for these full-profile results. Capture directories must be empty and
private. Keep raw output outside the source tree.

## Native-reader checks

Compile `probe_field_store.c` with `-std=c11 -O3 -Wall -Wextra -Werror`.
Its arguments are `IMAGE NATIVE SPEC REPEATS`. SPEC starts with
`rows record_stride field_count`, followed by `member_offset width_in_bytes`
for each field in image order. Use the exported native offsetof layout.
The probe first compares every value, then times sequential and random traces
of 100,000 uniform field queries, three trials per trace, alternating reader
order. This is a schema-driven memcpy baseline, not specialized scanner code;
identity resolution is excluded, and data has already been read for validation.
No CPU pinning or statistical confidence interval is claimed.

The aggregate synthesized/native CPU ratios were patterns work1 1.1665,
work3 1.3478, work16 1.6868; logical work16 0.7085. These are neither scanner
speed measurements nor a guarantee about a real scan access distribution.

For the directed malformed-input checks, compile the same source with
`-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`, then run:

```sh
python3 tools/compact-memory/system-model/check_native_probe.py --probe /tmp/probe-field-store-asan
```

Thirteen valid layouts passed exact checks and 77 malformed layouts were
rejected without ASan/UBSan findings. Leak checking was disabled. This is a
targeted reader check, not a fully instrumented ClamAV run or fuzzing campaign.
