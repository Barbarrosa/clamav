# Core tests and restored public fixtures

The directory-retirement research build passed the C library, scanner and
signature-tool test groups after six missing public upstream test fixtures were
restored. The Rust suite passed all **67 tests** with its writable toolchain homes
set correctly. These results do not resolve the complete performance gate.

The first complete CTest attempt is retained. It reported two C setup failures
and four scanner failures caused by missing files, plus a Rust environment error.
The original ClamAV reference passed its C and scanner groups, including
145 scanner tests and one platform skip. Inspection showed that the branch's
initial import already omitted six files matching generic build-artifact ignore
patterns. This was not a directory-retirement regression.

The six restored files are exact bytes from upstream commit
`dd3aa1907cf6e34286c86f8a24dd16e7a8d8810d`: `daily.pdb`, the documented test PE
executable, and four icon-signature files in `weak-sigs`. Their sizes and SHA-256
hashes, and their absence in the initial import and retained baseline, are in the
[summary](summary.json). Narrow `.gitignore` exceptions preserve these particular
fixtures. No fixture content was invented, simplified or changed to obtain a pass.

After restoration, the C library, scanner and signature-tool CTest groups passed
in 22.94 seconds. The corrected cached Rust CTest run passed in 0.17 seconds.
The candidate and original libraries are bound by SHA-256 in the summary. These
are the explicit directory-retirement research artifacts; the results are not an
attestation for every future build configuration.

The initial application checks remain **blocked** in this sandbox. Eleven
submission-client tests and eight updater tests could not create local test
server sockets (`Operation not permitted`). Fifteen daemon tests stopped during
setup because of the initially missing `daily.pdb`; they have not been rerun
with socket access. None of these blocked checks is counted as a pass.

Raw logs retain both the failures and corrected runs. Reproduction uses the
normal `ctest --test-dir BUILD --output-on-failure` command, with the private
Python, Check, unrar-module and Cargo paths configured for this workspace. The
Rust environment requires `RUSTUP_HOME=/workspace/clamav-rustup`,
`CARGO_HOME=/workspace/clamav-cargo` and `CARGO_NET_OFFLINE=true` here. Application
server tests additionally require local socket access.
