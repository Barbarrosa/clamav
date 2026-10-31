# PE exclusion boundary regression

This test checks the conservative selector's specific contract: **before an
excluded PE matcher can run, the original has a sticky PE hold**. It does not use
the blanket reduced-release hold as evidence. It does not assert that ClamAV can
parse every possible file.

Run from the source directory against a completed Release build with Ninja:

```sh
python3 tools/subset-selector/boundary/build_audit.py \
  --source . --build ../build --output ../boundary-library
python3 tools/subset-selector/build_probe.py --build ../build \
  --libdir ../boundary-library --output ../boundary-library/probe --boundary-test
export LD_LIBRARY_PATH="$(realpath ../boundary-library):$(realpath ../build/libclamunrar_iface):$(realpath ../build/libclamunrar)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python3 tools/subset-selector/boundary/test_boundary.py \
  --probe ../boundary-library/probe --certs certs --output ../boundary-results
python3 tools/subset-selector/boundary/audit_callers.py \
  --source . --output ../boundary-results/source-callers.json
```

The output directory must not already exist, preventing old handler rules from
contaminating a rerun. Python 3.10+, Pillow and the normal ClamAV/probe build
dependencies are required. For custom SDKs, pass the same compiler/include/library
options used to build the regular probe. This is a Linux build-tree test.

`build_audit.py` recompiles only diagnostic copies of three C objects with the
build's original compiler commands, then links a separate diagnostic library.
Witness calls at PE target matching, PE dispatch and section/import hash matching
observe the adapter's hold bits on entry. The original source and shipping library
are untouched. The instrumentation manifest records source hashes and commands.

The five signature families are Target:1 NDB and LDB, MDB, MSB and IMP. Nine
positive files per family exercise a renamed PE, raw/Flate/ASCIIHex PDF streams,
nested PDF/ZIP, appended PNG, root ZIP and raw embedded PE. Four controls per
family include clean PDF/PNG, malformed PDF and appended JPEG. Every expected
result row must be present exactly once. Separate checks cover HandlerType and
the MaxEmbeddedPE early exit. All fixtures are harmless, synthetic and never run
as programs; synthetic databases are explicitly unsigned test inputs.

The mutation control disables only the PE hold in a diagnostic probe. The same
fixture must still reach an instrumented boundary, and the guard assertion must
then reject it. Missing witness coverage, missing rows or a blanket `outcome=held`
cannot make this test pass. No mutation override is compiled into regular probes.

Observed controls distinguish inherited parser limitations: an appended PE in the
JPEG fixture is not reached by either full or reduced mode; the malformed PDF does
not report a parse-error hold. They do not demonstrate successful content coverage.
The test therefore does not authorize automatic release of reduced clean results.

Source review complements the fixtures. The active `cli_scan_buff` callers supply
OLE2 and text targets, not PE. `cli_scan_desc` callers supply generic, script,
HTML and text targets. Its shared fmap implementation is instrumented. PE target
matching flows through `scanraw` after file typing; handler rules recurse through
`cli_magic_scan` with the forced type. Section/import hash checks are reached from
`cli_scanpe`. Embedded PE recursion uses `cli_magic_scan`; the MaxEmbeddedPE skip
branch is witnessed separately. A dormant `blob.c` branch uses a binary target,
and a PE-disassembly call in `pe.c` is commented out. These observations apply to
the recorded source revisions and build configuration only. A new caller or parser
change requires review, not just reusing this report.
