# Joint token dictionary selection: bounded offline experiment

31 October 2026. **Joint selection can beat a positive-gain greedy dictionary on
the exercised small cases. This is not an engine memory reduction or a practical
implementation of the linked counting algorithm.** Scanner code, rule selection,
signed databases and runtime defaults are unchanged.

The experiment implements the lead of optimizing dictionary choices together with
each sequence's encoding. The ordinary solver baseline is weighted partial MaxSAT
(PySAT RC2), with an independent SAT byte-budget search on a small witness.
Results and exact public/synthetic images are in
[joint-dictionary-results/summary.json](joint-dictionary-results/summary.json).

## What was tested

| Case | Raw image bytes | Greedy image bytes | All candidate image bytes | Joint optimum image bytes |
|---|---:|---:|---:|---:|
| Constructed complementary choices, 5 rows / 7 candidates | 140 | 140 | 181 | **130** |
| Public literal fixtures, 10 rows / 8 candidates | 756 | 756 | 878 | 756 |
| Same public rows / 16 candidates | 756 | 756 | 984 | 756 |
| Same public rows / 64 candidates, longer fragments | 756 | 756 | 1565 | **689** |
| Deterministic distinct bytes, 8 rows | 296 | 296 | 296 | 296 |
| Synthetic tagged wide tokens, 8 rows / 16 candidates | 216 | 168 | 363 | **168** |

These include the actual serialized header, dictionary, directories, decoded
lengths and mode/width flags. They exclude process/allocator overhead and decoder
scratch, which the result file reports separately. Every decoded byte and width
flag agrees with the source. The public rows are ten unique literal-only NDB
test-fixture payloads, **not compiled ClamAV token exports or a representative
official database**. Existing rule identities, prefix boundaries, special-token
tables and references are outside this experiment; none are rewritten.

The constructed case makes the interaction explicit. Storing `aabdba` or `cbc`
alone does not improve the raw-fallback objective. Sharing both reduces variable
storage from 63 to 53 bytes; the common 77-byte overhead makes complete images
140 and 130 bytes. The positive-gain greedy procedure stops at the empty
dictionary. This establishes a useful counterexample to that heuristic, not
superiority over every compression algorithm or greedy variant.

On the public case, increasing the pool from 16 fragments of maximum length 16
to 64 fragments of maximum length 32 changes the answer. Both candidate count and
maximum length change, so this does not isolate their individual effects.
Candidate generation itself is heuristic: overlapping frequency scores can favor
redundant fragments and discard complementary ones. An optimum after pruning is
only an optimum within the retained candidates. The all-candidate comparison
also demonstrates why dictionary setup and indexing costs must be charged.

## Representation and objective

The input is the existing byte-specialized `token-data.bin` and flagged
`token-index.bin` format from `prepare_token_store.py`, or explicit test rows.
The width bit remains part of each row. Tagged 16-bit values reconstruct exactly;
the optimizer treats their serialized bytes opaquely. The experiment is bounded
to 4,096 total input bytes, 256 rows and 64 candidate fragments. These are
deliberate small-instance limits, not a claim that a full database fits the model.

A dictionary contains nonrecursive byte fragments. A compressed row is a stream
of 16-bit codes: 0–255 are literals and 256+ are dictionary references. Each row
can instead retain its original raw bytes. The model jointly selects dictionary
entries and a nonoverlapping source-to-sink path through each row's substring
DAG. Every reference implies that its dictionary entry is selected. Flow and
at-most-one constraints exclude overlapping or disconnected parses.

For dictionary variables `y`, parse-edge variables `x` and raw-row variables `r`,
the minimized variable byte cost is:

```
sum((fragment_length + 4) * y) + 2 * sum(x) + sum(row_length * r)
```

The four bytes per dictionary entry pay for its offset. The shared cost is
`24 + 4 + 4*(rows+1) + 4*rows + rows`: a header, dictionary terminal offset, row
offsets, decoded lengths and mode/width flags. Serialization must equal this
accounting exactly. Unused selected dictionary entries still cost space.
Raw storage bounds the optimized byte cost from above for a feasible row set.

Optional `D` bounds modeled work per lookup as **expanded bytes + codewords**;
raw work is expanded bytes. This is an abstract operation budget, not processor
instructions or a latency guarantee. Dictionary recursion, eviction state and
decoded caches are absent. Both Python and C decoders validate dimensions,
offsets, flags, code references and expanded lengths. Input images are experimental
artifacts, not authenticated replacements for signed CVD/CLD sources.

## Connection to the supplied algorithm

The supplied [OpenAI math write-up](https://github.com/openai/math/blob/main/lean/docs/378.md)
states deterministic exact counting for every fixed clause width, with a
subexponential bound in the formula's variable count and a polynomial factor in
its canonical input length. Its formalized bound and the manuscript's sharper
bound should be distinguished. This investigation has not independently built
or checked the Lean proof and does not supply a practical execution of that
machine as a DIMACS solver.

The reduction is valid for feasibility: add a weighted byte budget, convert to
clauses of width at most three, then ask whether the count is positive. Repeated
feasibility queries locate the minimum modeled cost; a count-only oracle also
requires witness recovery by variable fixing. Auxiliary variables and alternative
encodings mean assignment counts are not counts of distinct database layouts.

The delivered `joint_budget_cnf.py` uses binary addition/comparison and long-clause
splitting. The constructed case has 144 MaxSAT variables. At variable budgets 52
and 53, the exported formulas have respectively **1,805 / 1,804 variables** and
**6,194 / 6,192 clauses**, all width at most three. Conventional SAT rejects 52
and accepts 53; its recovered witness decodes exactly. A separate binary search
from the raw bound also recovers 53, agreeing with RC2 and an exhaustive oracle.
On this one run, RC2 took about 3 ms; six SAT budget queries took about 1.10 s
including their encodings. This compares the delivered conventional baselines,
not the linked counting algorithm, which was not executed.

The linked [canonical encoding](https://github.com/openai/math/blob/main/lean/ComparatorChallenges/SubexponentialSAT.lean)
uses unary natural indexes and framed lists. For these formulas, its input length
is approximately **116 million symbols**, versus approximately **94 KB of
DIMACS**. The report calculates this length; it does not allocate that input or
execute the formalized machine. All auxiliary variables belong in the theorem's
`n`. These costs prevent a speedup inference from the asymptotic result alone;
they do not rule out a better reduction or a practical implementation with a
different input interface.

The relevant compression precedent is
[On the Smallest Size of Internal Collage Systems, CPM 2026](https://doi.org/10.4230/LIPIcs.CPM.2026.31).
Its MaxSAT formulation minimizes size in its specified grammar family, rather
than our serialized bytes and lookup-work model. No result from that paper is
used as a ClamAV savings estimate.

## CPU, residency and reload

The native C probe runs four traces: sequential, deterministic random,
repeated longest row and a small hot set. It reports both process CPU time and
monotonic elapsed time; timings include a full decoded-byte hash. Fresh processes
read each image eagerly. Raw and compressed runs agree on all decoded checksums,
including width and row boundaries. These microbenchmarks are single observations,
without confidence intervals, CPU pinning or a scanner workload. They do not
establish performance parity; compressed decoding can cost additional CPU.
For example, the 64-candidate public case took 76.3 versus 86.3 ns per sequential
lookup and 76.6 versus 90.5 ns per random lookup, raw versus optimized, including
the hash. The smaller representation therefore did not provide a free speedup in
these observations. Full raw storage remains an available comparison profile.

There is no persistent decoded cache. Allocated image bytes therefore stay the
same before and after all rows are accessed, while one scratch buffer is reused.
Loading a replacement keeps two full images and two scratch buffers alive. On
the 64-candidate public case, image bytes are 756 versus 689, scratch is 78 bytes
per decoder, and two-image payloads are 1,512 versus 1,378 bytes. These are
component allocation counts, **not measured engine RSS savings**.

Loaded, hydrated and two-image RSS snapshots are retained in the JSON. Images
this small are below page granularity and the differences are not useful memory
evidence. `getrusage` high water may include inherited process history around
spawn/exec; it is preserved separately from `/proc` snapshots and is not labeled
as a clean decoder peak. Construction/solver memory, surrounding engines, file
cache and real old/new database generations remain unmeasured.

## Validation and reproduction

The 16 Python test groups include exhaustive primary-assignment checks of 510
budget instances, independent dictionary-subset enumeration with dynamic-program
parsing on tiny cases, overlapping fragments, raw fallback, tagged widths,
infeasible work bounds, and malformed/truncated images. Native code was compiled
with warnings as errors and exercised under ASan/UBSan; leak checking was disabled.
The generated images and fixed-width formulas are public/synthetic test data.
The general CLI's artifacts can contain source bytes and should stay private
when using a private export.

```sh
python3 -m venv /tmp/joint-dictionary-venv
/tmp/joint-dictionary-venv/bin/pip install python-sat==1.9.dev17
cc -std=c11 -O3 -Wall -Wextra -Werror \
  tools/compact-memory/probe_joint_dictionary.c -o /tmp/probe-joint-dictionary
/tmp/joint-dictionary-venv/bin/python tools/compact-memory/test_joint_budget_cnf.py
/tmp/joint-dictionary-venv/bin/python tools/compact-memory/test_joint_token_dictionary.py
/tmp/joint-dictionary-venv/bin/python tools/compact-memory/run_joint_dictionary.py \
  --output /tmp/joint-dictionary-results --probe /tmp/probe-joint-dictionary \
  --repeats 20000
```

Use a new output directory. For a real compiled export, run
`joint_token_dictionary.py --data token-data.bin --index token-index.bin
--row-limit 32 --max-candidates 16 --output PRIVATE_NEW_DIRECTORY`.
The CLI refuses oversized slices; reduce the row limit rather than implying it
optimized the full database. Solver dependencies are confined to this offline
tool; no engine dependency is added.

## Next falsifiable experiment

Generate fresh compiled exports for both the full profile and the PDF/JPEG/PNG
profile with PE exclusions using their existing pinned validation paths. Optimize representative and adverse
small shards, including already-deduplicated sequences, against raw, existing
OnPair and small-block Zstd under matching index/scratch budgets. Retain pattern
identity, prefix boundaries, width flags and every selected rule. Include random
and candidate-flood lookup traces and full-engine output comparisons before any
integration. Measure actual empty/hydrated/reload memory and compiler peak.

The immediate open question is whether better candidate generation and bounded
sharding yield a gain on those exports after dictionaries and references are
charged. Only then is a practical counting implementation worth comparing with
RC2 and SAT, including reduction, witness recovery and validation time. No
additional full-database savings percentage is established by this experiment.
