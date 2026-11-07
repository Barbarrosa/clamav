# Token storage: post-compilation byte packing fails the RAM gate

**Do not integrate this candidate.** A concrete full-database storage probe made
the eligible token buffers about 32 MiB smaller in nominal bytes, but the process
used **24 MiB more resident RAM** when their replacements came from the existing
pool. Moving replacements to individual heap buffers used **68 MiB more RAM**.

This is a destructive, isolated-process feasibility experiment, not an optimized
scanner. It deliberately does not scan after changing the token representation.
No scanner code, database selection or runtime default changed.

## Why this candidate was tested

The actual AC verifier reads `uint16_t` tokens. High bits encode case folding,
nibble wildcards and special operators. The builder also mutates tokens, shifts
the active pattern into a prefix buffer, and compares the original token bytes
while constructing ordered candidate lists.

Ordinary literals can be represented by bytes without losing information, while
tagged patterns can retain their original 16-bit arrays. However, packing during
loading changes subsequent allocation addresses. Existing AC sort ties depend
on pattern addresses, so an early packing pass cannot assume identical reporting
order. The rejected logical-sharing experiment already demonstrated this risk.

The probe therefore waits until the original engine is fully compiled. Candidate
links and their ordering have already been constructed. It converts only whole
prefix-plus-pattern sequences whose every token is at most 255. Tagged sequences
are left unchanged. This is a narrower experiment than the earlier offline model
that combines token deduplication and byte specialization.

## Actual full-database result

The signed snapshot loads **3,628,192 signatures** and contains **1,508,210 AC
patterns** in the measured diagnostic build. Of these, **1,280,869 patterns**
were eligible for the byte representation; **227,341** retained their tagged
16-bit storage.

The eligible sequences contain **35,840,740 tokens**, occupying **71,681,480
payload bytes** originally. New byte allocations, including a terminator and
rounding to at least two-byte pointer alignment, request **38,056,332 bytes**.
That is a nominal **32.07 MiB reduction**, before pool retention and allocator
effects. The original payload count excludes spare terminator bytes and headers;
it is not a census of original charged allocations.

| Fresh process | RSS before conversion | RSS after conversion and pool flush | Change |
|---|---:|---:|---:|
| Original engine control | 791.30 MiB | 791.30 MiB | +0.004 MiB |
| Byte buffers allocated from the original pool | 791.54 MiB | 815.54 MiB | **+24.00 MiB** |
| Individual heap byte buffers | 791.41 MiB | 859.77 MiB | **+68.35 MiB** |

The pool case maps another **24.10 MiB**. Freeing the old buffers and calling the
existing pool flush does not recover enough resident pages to offset the new
allocations. Small freed fragments retain pool/free-list storage; the pool does
not coalesce all nearby dead allocations into releasable regions. The heap case
also pays for individual allocation bookkeeping and an explicit **11.51 MiB**
owner-pointer directory used by this diagnostic's destruction path.

These are three serial, single observations, not confidence intervals. Each
process was pinned to CPU 0 with a 4 GiB address-space limit, CPU limits of
120/125 seconds and a 120-second wall timeout. Total process times were
7.75–7.99 seconds. Conversion includes full reconstruction checking, so its
elapsed time is not a proposed scanner compilation-time estimate.

## What was checked, and what was not

Every converted token was compared directly with the original 16-bit token under
zero extension. Original prefix coordinates were checked before conversion.
The control and both byte modes have identical reconstruction hashes and counts,
and all three engine destruction paths completed normally. Small real-engine
fixtures separately exercise ordinary literals, shifted prefixes, wildcards,+nibble tokens and special alternatives. Signed source databases are read only.

The byte modes intentionally leave an engine representation that its original
verifier cannot read. They **must not be used for scanning**. The probe does not
establish scan-time parity, callback ordering after a verifier change, full
failure-path correctness, a byte-format ABI, reload peaks or production safety.
It uses the existing private-export diagnostic library, whose binary and input
hashes are recorded; it is not a newly compiled production candidate.

The diagnostic keeps original pattern records and ordered links, avoiding a
premature claim that an allocation-changing loader is compatible. But this
candidate already fails the resident-memory requirement, so adding a new token
reader and format flag would not qualify it.

## Next prerequisite

Further token work needs a storage-lifetime design that actually releases the
old representation. Early byte specialization must first solve the allocation
address/order coupling. Late specialization needs demonstrably reclaimable old
storage, without unacceptable construction/reload peaks. Deduplication or an
offline dictionary can reduce nominal bytes further, but that alone does not
solve either prerequisite.

The earlier offline model's larger reduction remains a representation result;
it is not an additional runtime saving. These measurements strengthen the reason
to keep that distinction.

## Evidence and reproduction

Source: [probe_token_repack.c](../tools/compact-memory/token-qualification/probe_token_repack.c).
The [manifest](token-compaction-results/manifest.json) binds the probe, source,
diagnostic library and all three signed database files by SHA-256. The
[summary](token-compaction-results/summary.json), raw outputs and
[artifact hashes](token-compaction-results/artifacts.json) contain only counts,
timings and hashes; no raw signature data is published.

Compile against the matching generated configuration/private-export library:

```sh
cc -std=gnu99 -O2 -Wall -Wextra -DHAVE_CONFIG_H \
  -DENABLE_AC_NODE_IDS=1 -DENABLE_AC_FLAT_NODES=1 \
  -I/path/to/build -Ilibclamav -Ilibclamunrar_iface \
  -I/path/to/sysroot/usr/include \
  -I/path/to/sysroot/usr/include/json-c \
  -I/path/to/sysroot/usr/include/libxml2 \
  tools/compact-memory/token-qualification/probe_token_repack.c \
  -L/path/to/private-export-library \
  -Wl,--disable-new-dtags -Wl,-rpath,/path/to/private-export-library \
  -lclamav -lcrypto -o /tmp/probe-token-repack
```

The library must export `mpool_malloc`, `mpool_free`, `mpool_flush` and
`mpool_getstats`; ordinary builds intentionally hide these private symbols.
Set `LD_LIBRARY_PATH` to that library plus both matching unrar-module directories.
Run fresh serial processes for `control`, `pool-byte` and `heap-byte` with the
same database and certificate directory. Apply the process limits above before
starting. The optional `force-ac` argument exists only for small test databases;
the full-database measurements did not force a different matcher selection.
