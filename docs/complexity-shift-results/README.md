# Complexity-shift evidence

See `../complexity-shift-implementation.md` for decisions, measurements and limits.
The `flat` hash label denotes the rejected sorted-size-directory prototype;
`indexed` denotes the retained prototype using ClamAV's existing size hash.
`baseline` is the unmodified source restored from artifact version 5, not stock
upstream ClamAV. All use the same pinned database and full-feature Release build.

The principal standalone probes are:

- `probe_hash_equivalence.c`: every hash record, mutated digest, alternate size,
  exact selected-name/return-code transcript; four size-lookup access traces.
- `probe_scan_corpus.c`: public API, ordered callbacks, final names and return
  codes in first-hit and all-match modes; cache disabled in both variants.
- `test_flat_hash.c`: production matcher included under ASan/UBSan, allocation
  rollback/retry, duplicate selection, NULL/empty names, name pointer lifetime,
  unaligned digests, normalization and the 24-bit name-offset boundary.
- `onpair-probe/`: independent dictionary decoding over every unique token,
  full equality before timing and explicit index/dictionary/scratch accounting.
- `summarize_complexity_shift.py`: recompute aggregate numbers and assert
  differential transcript equality from the retained JSONL records.

Raw signatures, downloaded databases, WordPress sources, codec dependencies,
compiler packages and build products are excluded. The corpus manifest stores
only paths, lengths and SHA-256 hashes. Timings are observations on a shared
host, not deployment guarantees. Decoder component bytes are not engine RSS.

The daemon test was attempted and stopped after repeated socket startup
failures. `clamd-startup-diagnostic.log` records `Operation not permitted` for
Unix socket allocation; this environment does not qualify daemon integration.
