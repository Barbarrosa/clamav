#!/bin/bash
set -e
. /workspace/scratch/48dde463229d/analysis-run/build-env.sh
variant="$1"
cmake -S "$TASK_BUILD_ROOT/$variant" -B "$TASK_BUILD_ROOT/build-$variant" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON -DENABLE_MAN_PAGES=OFF \
  -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF -DENABLE_SYSTEMD=OFF \
  -DENABLE_UNRAR=ON -DMAINTAINER_MODE=ON \
  -DCMAKE_INSTALL_PREFIX="$TASK_BUILD_ROOT/install-$variant" \
  -DCVD_CERTS_DIRECTORY="$TASK_BUILD_ROOT/$variant/certs" \
  -DCURL_LIBRARY_RELEASE="$TASK_BUILD_ROOT/sdk/usr/lib/x86_64-linux-gnu/libcurl.so" \
  -DCURL_INCLUDE_DIR="$TASK_BUILD_ROOT/sdk/usr/include/x86_64-linux-gnu" \
  -DLIBXML2_INCLUDE_DIR="$TASK_BUILD_ROOT/sdk/usr/include/libxml2" \
  -DLIBXML2_LIBRARY="$TASK_BUILD_ROOT/sdk/usr/lib/x86_64-linux-gnu/libxml2.so"
