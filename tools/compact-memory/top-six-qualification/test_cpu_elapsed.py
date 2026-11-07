"""Compile the actual collector arithmetic at timer-resolution boundaries.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class CpuElapsedTests(unittest.TestCase):
    def test_zero_short_and_invalid_intervals(self):
        source = (Path(__file__).resolve().parents[3] /
                  'tools/subset-selector/performance/performance_probe.c').read_text()
        sample = re.search(r'struct sample \{[^}]+\};', source).group()
        helper = re.search(r'static double cpu_elapsed\([^}]+\}', source).group()
        program = '#include <assert.h>\n#include <math.h>\n' + sample + '\n' + helper + r'''
int main(void) {
    const double users[] = {0, 0.000001, 8.001237, 48.805901, 125.409112, 600};
    const double systems[] = {0, 0.000001, 0.673450, 13.219087};
    for (unsigned i = 0; i < sizeof(users) / sizeof(*users); i++)
        for (unsigned j = 0; j < sizeof(systems) / sizeof(*systems); j++) {
            struct sample a = {.user = users[i], .system = systems[j]}, b = a;
            assert(cpu_elapsed(a, b) == 0);
            b.user += 0.000001; b.system += 0.000002;
            assert(fabs(cpu_elapsed(a, b) - 0.000003) < 1e-12);
            b = a; b.user -= 0.000001;
            /* Invalid counter decreases stay invalid; the helper never clamps. */
            assert(cpu_elapsed(a, b) < 0);
        }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cpu_elapsed.c'
            path.write_text(program)
            binary = Path(tmp) / 'cpu_elapsed'
            subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(path), '-lm', '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    unittest.main()
