# Tunable-profile prototype evidence

Read [the report](../tunable-profile-prototypes.md) for conclusions and limits.
The source tools are in `tools/compact-memory/`. None is linked into the scanner.

| Evidence | Meaning |
| --- | --- |
| `export.jsonl` | Normally verified engine census and normalized-reference accounting |
| `token-preparation.json`, `logical-preparation.json` | Exact interning and eligible-template counts |
| `patterns-*`, `links-*`, `nodes-*`, `logical-*.jsonl` | Twelve native scalar configurations; all-field equality checks and paired timings |
| `tokens-*.jsonl` | Six native token-cache configurations; all-token equality, error checks and paired timings |
| `completed.json` | Successful sequential matrix completion and raw-observation hashes |
| `profile-summary.json` | Component calculations, configuration selection and timing intervals |
| `sanitizer-tests.json` | Reproducible ASan/UBSan boundary/error cases |
| `baseline-c-tests.log`, `baseline-check-count.log` | Rerun of the unchanged libclamav C suite; 1,816 checks |
| `provenance.json` | Recovery/source, tool/binary/input/database hashes and machine details |
| `evidence-sha256.json` | Evidence hashes, excluding itself |

All layout totals include the directories documented in the report, but not
allocator rounding. Native probes retain the source/oracle. Timed raw scalar
access uses normalized fixed-width records; it is not the original scanner's
pointer layout. Timed raw token access uses the interned, byte-specialized store;
it is not the original uint16 verifier. No whole-engine RSS is measured here.

The four scalar schema sizes are patterns 74 bytes/25 fields, links 12 bytes/3
fields, nodes 8 bytes/2 fields, logical headers 28 bytes/7 fields. Each test
checks every field of every record before timing. Scalar inputs are seeded
uniform random (0), sequential (1), and repeated first 32 records (2), with
131,072 queries and eight alternating timing pairs each. Token tests use 4,096
queries and four pairs per input; input 3 alternates two colliding cache blocks.
The cache starts empty for each compressed trial. In all real-data conflict
trials there are zero hits and 4,096 misses.

Execution used CPU affinity 2, sequential processes and no concurrent local
heavy build/test job. Other host activity is uncontrolled. Bootstrap intervals
use 2,000 paired-log resamples and seed 261027. Small samples, short hot-path
timings and shared-host noise preclude certification or a WordPress-average
claim. Layout sizes and exact comparisons do not depend on timing precision.

The synthetic test generator is `test_profile_codecs.py`. It tests scalar group
sizes 1, 2, 63, 64, 65, 128, 256, 1024; uint32 maximum/sentinel/wraparound values;
token lengths spanning zero through the maximum two uint16-sized arrays; six
invalid index variants; truncated/corrupt frames, incorrect decoded lengths and
invalid ranges. It uses sanitizer binaries with leak detection disabled.
These trusted-input diagnostics are not hardened database loaders, portable
serialized formats, a general fuzz campaign, or scanner differential tests.

## Reproduce

Use a matching release build of this source with its default flat-node option,
normal development dependencies, and the pinned main 63/daily 28164/bytecode 339
database snapshot. The previous reports describe obtaining and verifying that
snapshot; no raw databases, exports, names or token payloads are redistributed.
The new export's name SHA-256 equals the previous name model input.

Commands below run from the source root. Set `build_dir`, `work_dir` and `db_dir`
to your actual paths. The configured build supplies `clamav-config.h`. Compiler
and pkg-config paths may need adjustment for locally extracted dependencies.

```sh
build_dir=../build-prototypes
work_dir=../research
db_dir=../research/official-db/container
mkdir -p "$work_dir/profile-data"

cc -O2 -DHAVE_CONFIG_H -I"$build_dir" -Ilibclamav -Ilibclamunrar_iface \
  $(pkg-config --cflags json-c libxml-2.0) \
  tools/compact-memory/export_exact_layouts.c \
  -L"$build_dir/libclamav" -Wl,-rpath,"$(realpath "$build_dir/libclamav")" \
  -lclamav -o "$work_dir/export-exact-layouts"
"$work_dir/export-exact-layouts" "$db_dir" certs "$work_dir/profile-data" \
  > "$work_dir/profile-data/export.jsonl"

python3 tools/compact-memory/prepare_token_store.py "$work_dir/profile-data"
python3 tools/compact-memory/prepare_logical_store.py "$work_dir/profile-data"
cc -O3 -mpopcnt -Wall -Wextra tools/compact-memory/probe_scalar_columns.c \
  -o "$work_dir/probe-scalar-columns"
cc -O3 -Wall -Wextra tools/compact-memory/probe_token_blocks.c \
  $(pkg-config --cflags --libs libzstd) -o "$work_dir/probe-token-blocks"
python3 tools/compact-memory/run_profile_prototypes.py \
  --data "$work_dir/profile-data" --output "$work_dir/profile-results" \
  --scalar "$work_dir/probe-scalar-columns" \
  --blocks "$work_dir/probe-token-blocks" --cpu 2
python3 tools/compact-memory/analyze_profile_prototypes.py \
  --data "$work_dir/profile-data" --results "$work_dir/profile-results" \
  --previous docs/correlation-results/correlation-summary.json \
  --output "$work_dir/profile-summary.json"

cc -O1 -g -mpopcnt -fsanitize=address,undefined -fno-omit-frame-pointer \
  tools/compact-memory/probe_scalar_columns.c \
  -o "$work_dir/probe-scalar-columns-asan"
cc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  tools/compact-memory/probe_token_blocks.c $(pkg-config --cflags --libs libzstd) \
  -o "$work_dir/probe-token-blocks-asan"
ASAN_OPTIONS=detect_leaks=0 python3 tools/compact-memory/test_profile_codecs.py \
  --scalar "$work_dir/probe-scalar-columns-asan" \
  --blocks "$work_dir/probe-token-blocks-asan" \
  --output "$work_dir/profile-sanitizer-tests.json"

ctest --test-dir "$build_dir" -R '^libclamav$' --output-on-failure
```

The current aggregator validates observation checksums and the common name
export before reusing earlier components. Its exact digest-key count comes from
the same snapshot's prior census; cyclic-route and name budgets come from the
earlier aggregate. Do not substitute a different database and interpret the
mixed subtotal as a complete new result. Future portable implementations need
explicit endian conversion, checked large-offset formats, raw fallback selection,
generation ownership and a production error API.

## Source recovery

The previous workspace build and Git objects were unavailable. The complete
saved archive was restored, and every source blob/mode was used to reconstruct
the exact prior tree `ce53cf1ef590f13f07204507e41f2f3262f6bb84`. This became recovery
snapshot `6f8af2a055acfe755ac54174627dc70727a66589`, not a recreation of the original
commit's ancestry. The earlier source revision was
`479a69bb8e5d7afdeedc7c5a863cc82aa9b03af5`; the previous patch series remains
preserved in the deliverable. New commits follow the verified recovery snapshot.
Original runtime changes, licenses and historical evidence are retained.
