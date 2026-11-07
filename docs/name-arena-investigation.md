# Signature-name storage: a measured rejection

**The straightforward order-preserving name-arena conversion increases RAM.**
It is not suitable for integration under the current requirements.

The proposed change was to wait until compilation finished, then copy the hash
matchers' names into one stable, uncompressed arena. Existing name-pointer arrays
would continue to provide direct reads. Each original occurrence would keep its
own distinct address, including equal names, and no decoded cache or disk-backed
name lookup would be added. Waiting until compilation avoids changing the
allocation addresses used to order AC candidates while constructing the matcher.

## Actual full-database experiment

A standalone diagnostic loaded the signed database with 3,628,192 signatures,
compiled the retained engine, checked name ownership, then copied and released
the old names. It operated on the existing private-export diagnostic library;
no runtime engine implementation or default changed.

| Observation | Result |
|---|---:|
| Non-NULL hash-name occurrences | 3,213,522 |
| Original pointer aliases among those occurrences | 0 |
| New raw-name arena | 77,488,025 bytes, 73.898 MiB |
| Resident RAM immediately before conversion, after validation | 829,976,576 bytes |
| Resident RAM after conversion and pool flush | 907,464,704 bytes |
| Increase | **77,488,128 bytes, 73.898 MiB** |
| Pool mapped/carved extent change | 0 / 0 bytes |
| Conversion CPU/wall guarantee | Not established; one measured wall time was 0.232 seconds |

The ordered name stream's SHA-256 is identical before and after conversion. The
probe checked that no original pointers were shared, and creates one positive-size
arena slice per occurrence, preserving distinct identities without merging equal
strings. It publishes no name strings or native addresses.

The complete process took 10.30 seconds under a 4 GiB address-space limit,
120-second CPU limit and 120-second wall timeout. Resident high water increased
from 865,128,448 bytes at compilation to 907,419,648 bytes after copying. Linux
RSS and high-water values are separately sampled and can differ slightly.

## Why the old memory did not disappear

`mpool_free` links each freed allocation into a size-class free list. The existing
free-page reclamation deliberately preserves free-list metadata and advises only
the whole interior pages of **individual large fragments**. It skips fragments
smaller than a page plus its header. Small name allocations therefore remain in
the pool after they are freed; they are not coalesced into releasable pages.

The new name arena consequently adds essentially its full payload to RSS. This
is exactly the lifecycle issue that a stored-byte comparison would miss.

## Other name approaches and their gates

- **Exact whole-name deduplication is a small payload opportunity here.** The
  earlier census counted 87,619,213 name bytes before string interning and
  87,171,124 unique bytes: only 448,089 bytes, about 0.427 MiB, before index costs.
  That census covers more name families than this hash-only probe. Merging
  occurrences also requires preserving the original evidence identity contract.
- **Compressed blocks with permanent expansion do not pass the hydrated-memory
  requirement.** The prior exact prototype's 87,171,124 raw bytes become
  94,710,024–101,361,960 bytes after all names have been expanded and retained.
  Evicting expanded strings can invalidate returned pointers.
- **Allocating a packed arena during loading could avoid old pool fragments,**
  but changes later pool addresses and can change duplicate-alert ordering.
  It does not inherit the successful ordering argument of postcompile copying.
- **A mapped raw-name file makes residency workload-dependent** and introduces
  page-fault, immutable-generation and I/O-failure obligations. It has not met the
  cold/hydrated timing and memory criteria and is not substituted here.
- **Coalescing the old small free fragments requires a new allocator strategy.**
  The intrusive free-list metadata prevents simply advising their pages away.
  A metadata relocation or nonmoving compaction design needs separate complexity,
  failure, reuse, ordering and performance analysis.

## Status and evidence

The candidate is rejected at the memory gate. Full scanner throughput, failure
behavior and reload qualification were not pursued after that decisive failure.
The diagnostic deliberately exits without invoking the old destructor, which
does not support the relocated ownership. It is **not an integrated candidate**
and must not be enabled in production.

[Aggregate results and hashes](name-arena-results/name-arena-summary.json),
[raw observations](name-arena-results/pack.jsonl) and
[diagnostic source](../tools/compact-memory/probe_name_arena.c) are retained for
inspection. Raw CVDs and private native data remain outside the repository.

Rebuild the diagnostic against the matching private-export library and generated
configuration. In this environment:

```sh
cc -std=gnu99 -O2 -Wall -Wextra -Wno-misleading-indentation -DHAVE_CONFIG_H \
  -I/path/to/build -Ilibclamav -Ilibclamunrar_iface \
  -I/path/to/sysroot/usr/include \
  -I/path/to/sysroot/usr/include/json-c \
  -I/path/to/sysroot/usr/include/libxml2 \
  tools/compact-memory/probe_name_arena.c \
  -L/path/to/diagnostic -Wl,--disable-new-dtags \
  -Wl,-rpath,/path/to/diagnostic -lclamav -lcrypto -o /tmp/probe-name-arena
```

The private-header build emits the pre-existing `cli_dbgmsg` inline-declaration
warning, so this command does not claim warnings-as-errors qualification. The
diagnostic library exports `mpool_free`, `mpool_flush` and `mpool_getstats` in
addition to the normal API. Its exact hash and the database/certificate hashes
are bound in the result file. Run serially with both matching unrar module
directories in `LD_LIBRARY_PATH`, under the recorded operating-system limits:

```sh
/tmp/probe-name-arena /private/signed-database certs pack
```
