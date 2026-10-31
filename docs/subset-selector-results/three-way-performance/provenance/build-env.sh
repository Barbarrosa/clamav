#!/bin/bash
TASK_BUILD_ROOT=/workspace/scratch/48dde463229d/analysis-run
export PATH="$TASK_BUILD_ROOT/sdk/rust/bin:$TASK_BUILD_ROOT/sdk/usr/bin:$TASK_BUILD_ROOT/tooling/cmake/data/bin:$TASK_BUILD_ROOT/tooling/bin:$PATH"
export PYTHONPATH="$TASK_BUILD_ROOT/tooling${PYTHONPATH:+:$PYTHONPATH}"
export LD_LIBRARY_PATH="$TASK_BUILD_ROOT/sdk/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBCLANG_PATH="$TASK_BUILD_ROOT/sdk/usr/lib/llvm-18/lib"
export BINDGEN_EXTRA_CLANG_ARGS="-isystem $TASK_BUILD_ROOT/sdk/usr/lib/llvm-18/lib/clang/18/include"
export BISON_PKGDATADIR="$TASK_BUILD_ROOT/sdk/usr/share/bison"
export M4="$TASK_BUILD_ROOT/sdk/usr/bin/m4"
export CARGO_HOME="$TASK_BUILD_ROOT/cargo"
export CMAKE_PREFIX_PATH="$TASK_BUILD_ROOT/sdk/usr"
export PKG_CONFIG_PATH="$TASK_BUILD_ROOT/sdk/usr/lib/x86_64-linux-gnu/pkgconfig"
export CARGO_BUILD_JOBS=3
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_CODEGEN_UNITS=1
