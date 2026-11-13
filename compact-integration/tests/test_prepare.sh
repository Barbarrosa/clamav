#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ci_test_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ci_test_tmp=$(mktemp -d)
trap 'rm -rf "$ci_test_tmp"' EXIT HUP INT TERM
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  "$ci_test_root/test_prepare.c" \
  $(pkg-config --cflags --libs sqlite3 zlib json-c openssl) \
  -o "$ci_test_tmp/test-prepare"
"$ci_test_tmp/test-prepare" "$ci_test_tmp"
