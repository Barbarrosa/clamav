# Final default-build checks

The final build uses **`ENABLE_AC_DIRECTORY_RETENTION=ON`**, the normal default.
C library, scanner, signature-tool and Rust test groups all passed. These checks
are separate from the opt-in retired-directory performance experiment, which
missed the strict timing gates. No additional memory saving is promoted.

[Artifact binding and log hashes](summary.json) record the exact tested library.
[CTest output](ctest.log) shows all four groups passing. Application tests that
need local sockets remain blocked, as recorded in the [test audit](../tests/README.md).
