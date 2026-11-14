#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ci_tests=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ci_tmp=$(mktemp -d)
trap 'rm -rf "$ci_tmp"' EXIT HUP INT TERM
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  "$ci_tests/test_cpu_parent.c" -o "$ci_tmp/test-cpu-parent"
"$ci_tmp/test-cpu-parent"
