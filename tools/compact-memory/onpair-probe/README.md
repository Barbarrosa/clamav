# Independent token decoding experiment

This is an MIT-licensed, standalone research harness. It is not linked into
libclamav and is not a production signature format. The pinned `onpair` crate
is independently licensed Apache-2.0 and requires Rust 1.91. Engine builds
remain on Rust 1.90. No third-party source or binary is bundled here.

Inputs are trusted diagnostic files from `export_exact_layouts.c` followed by
`prepare_token_store.py`. The width flag in the original index is retained in
an explicitly charged bitmap. Every reconstructed token and width is checked.
The retained representation is dictionary bytes/offsets, fixed 16-bit codes,
32-bit row offsets, the bitmap and one padded scratch buffer. Source arrays,
training workspace and benchmark query arrays are excluded from representation
bytes; this is not process RSS. Vector capacities are reported separately.

Build/run, using Rust 1.91:

    cargo build --release --locked
    target/release/clamav-onpair-probe DATA/token-data.bin DATA/token-index.bin 12
    target/release/clamav-onpair-probe DATA/token-data.bin DATA/token-index.bin 14
    target/release/clamav-onpair-probe DATA/token-data.bin DATA/token-index.bin 16

The five access traces are random, sequential, repeated first 32 rows, repeated
longest row, and alternating first/last rows. Five trials alternate raw/packed
measurement order. The checksum samples length and endpoints; byte-for-byte
correctness is separately checked over every row before timing. Raw access
uses a slice, while OnPair reconstructs a complete row. This measures access
cost, not the full ClamAV verifier or early-exit matching cost.

The safe bounded decoder is used. Too-small output and an invalid dictionary
length are rejected. This is a smoke test of validation, not a codec security
audit. Adopting a serialized codec would additionally require full descriptor,
row-offset and code validation, authenticated immutable backing, errors that
never turn into clean verdicts, concurrency tests and differential full-scanner
verification. No cache, prediction, I/O or new scan path is introduced here.

Primary algorithm paper: https://arxiv.org/abs/2508.02280
Implementation used: https://crates.io/crates/onpair/0.2.1
Implementation repository: https://github.com/spiraldb/onpair

Follow-up index experiment:

    TOKEN_INDEX_FLAGS=1 target/release/clamav-onpair-probe DATA/token-data.bin DATA/token-index.bin 16

This keeps the width flag in the code-offset high bit and removes the parallel
bitmap. Code count cannot exceed source byte count (each code emits at least
one byte), so the existing <2^31-byte input-layout bound is sufficient. Both
code-slice access and width reconstruction are checked for every row. The
reported retained layout excludes the now-unneeded bitmap vector header; the
probe itself still contains source/oracle and configuration variables.
