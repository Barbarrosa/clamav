# Linked counting construction: feasibility evidence

Read the [plain-language assessment](../linked-counter-feasibility.md) first.
These results measure compact input access and audit published parameters. They
do **not** report execution of the linked counting algorithm.

## Artifacts

- [linked-counter-audit.json](linked-counter-audit.json): pinned source identities,
  integer parameters, eventual-cutoff witness, literal fallback size formulas
  and the source-stated structured-step count for one frontend phase.
- [lazy-input-benchmark.json](lazy-input-benchmark.json): 100,000 random bit reads
  and 100,000 run accesses, actual process limits, timings, peak resident RAM and
  input/implementation hashes.
- [full-rle-benchmark.json](full-rle-benchmark.json): complete traversal of all
  12,727,852 runs, with independent grammar sums for total length and one bits.
  The SHA-256 is over concatenated little-endian `<?Q` records: one Boolean byte
  followed by an unsigned 64-bit run length. It is not a hash of expanded input.
- [provenance.json](provenance.json): paper identity, source revision, platform,
  evidence/tool hashes and the final groundwork test result.

The formula is the same public, count-faithful full exploratory query published
in [explore-query.cnf.gz](../search-groundwork-results/explore-query.cnf.gz),
with SHA-256
`134ae40d8c03d79ff498b09cfbcb21b947a3493ec9eac6185518cffc6a0fa42d`
after decompression. It has 295,443 declared variables, 1,005,993 text clauses
and 1,005,963 distinct canonical clauses. Its logical encoding length is
3,029,313,958,669 bits. No expanded transport or giant fallback table was made.

## Reproduce

From the ClamAV repository root:

```sh
gzip -dc docs/search-groundwork-results/explore-query.cnf.gz > /tmp/memory-query.cnf
python3 tools/compact-memory/search-groundwork/linked_counter_audit.py \
  --cnf /tmp/memory-query.cnf --math-source /path/to/openai-math \
  --report /tmp/linked-counter-audit.json
```

The math checkout must be at
`4eaee87548250b2682affda7d05d947c05554bae`, with inspected files unmodified.
The audit checks their Git blob identities. This is source-specific arithmetic,
not a Lean proof check. No Lean installation or proof build was attempted here.

For the sampled input benchmark:

```sh
(
  ulimit -v 2097152
  ulimit -S -t 110
  ulimit -H -t 115
  timeout 120s python3 tools/compact-memory/search-groundwork/lazy_canonical.py \
    --cnf /tmp/memory-query.cnf --report /tmp/lazy-input-benchmark.json \
    --random-reads 100000 --run-limit 100000
)
```

For complete run traversal, use the same limits:

```sh
(
  ulimit -v 2097152
  ulimit -S -t 110
  ulimit -H -t 115
  timeout 120s python3 tools/compact-memory/search-groundwork/benchmark_full_runs.py \
    --cnf /tmp/memory-query.cnf --report /tmp/full-rle-benchmark.json
)
```

The runner periodically saves incomplete progress. Check both its exit code and
the report's `status`; an interrupted traversal is not a completed result.
`timeout` supplies the wall cap externally; the process records observed address
space and CPU limits. The saved completed run also records the wrapper's exit
code. Timings are single-run observations on this environment, not confidence
intervals or portable speed guarantees.

Run the standard-library input/parameter tests directly, or the entire groundwork
suite with the existing NumPy/python-sat dependencies:

```sh
python3 -m unittest discover -s tools/compact-memory/search-groundwork \
  -p 'test_lazy_canonical.py' -q
python3 -m unittest discover -s tools/compact-memory/search-groundwork \
  -p 'test_linked_counter_audit.py' -q
python3 -m unittest discover -s tools/compact-memory/search-groundwork \
  -p 'test_*.py' -q
```

The finite checks test exact encoder agreement, free-variable preservation,
access limits, schedule boundary/nonmonotonic behavior and fallback-size formulas
against independently enumerated tiny clause universes. They do not establish
the correctness of an extracted counter or qualify scanner performance.
