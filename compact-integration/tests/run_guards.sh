#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
ci_tests=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ci_source=${1:?patched source directory required}
ci_build=${2:?matching build directory required}
ci_report=${3:?fresh report directory required}
mkdir -p "$ci_report"
LD_LIBRARY_PATH="$ci_build/libclamunrar:$ci_build/libclamunrar_iface:$ci_build/libclamav${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$ci_source/libclamav" -I"$ci_build" $(pkg-config --cflags json-c) \
  "$ci_tests/guard_probe.c" -L"$ci_build/libclamav" -Wl,-rpath,"$ci_build/libclamav" \
  -lclamav $(pkg-config --libs json-c) -o "$ci_report/guard-probe"
${CC:-cc} -std=c11 -fgnu89-inline -O2 -Wall -Wextra -Werror -DHAVE_CONFIG_H \
  -I"$ci_source/libclamav" -I"$ci_build" -I"$ci_build/libclamav" \
  -I"$ci_source/libclamav_rust" -I"$ci_source/libclamunrar_iface" -I"$ci_source/libclammspack" \
  $(pkg-config --cflags json-c libxml-2.0) "$ci_tests/guard_entry_probe.c" \
  -L"$ci_build/libclamav" -Wl,-rpath,"$ci_build/libclamav" -lclamav -o "$ci_report/guard-entry-probe"
"$ci_report/guard-entry-probe" buff
"$ci_report/guard-entry-probe" fmap
python3 "$ci_tests/test_guards.py" --probe "$ci_report/guard-probe" \
  --certs "$ci_source/certs" --report "$ci_report/guard-tests.json"
python3 "$ci_tests/test_guard_mutations.py" --source "$ci_source" --build "$ci_build" \
  --probe "$ci_report/guard-entry-probe" --output "$ci_report/mutations"
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror "$ci_tests/test_limits.c" -o "$ci_report/test-limits"
"$ci_report/test-limits"
sh "$ci_tests/test_cpu_parent.sh"
