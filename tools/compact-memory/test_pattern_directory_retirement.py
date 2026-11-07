"""Compile actual AC code to check directory retirement and conservative fallback.
SPDX-License-Identifier: GPL-2.0-only

The retirement caller is linked from the complete production matcher-ac.c.
Only allocator release functions are stubbed: their real reclamation behavior
is checked separately by test_mpool_reclaim_one.py. A configured ClamAV build
supplies platform/dependency headers; no scanner benchmark is run here.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

DRIVER = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clamav-config.h"
#include "others.h"
#include "matcher-ac.h"
#include "require_ac_directories.h"

static unsigned releases, unexpected_frees;
#ifdef USE_MPOOL
static mpool_t *expected_pool = (mpool_t *)(uintptr_t)0x1000;
void mpool_free_reclaim(mpool_t *pool, void *ptr) {
    assert(pool == expected_pool && ptr);
    releases++;
    free(ptr);
}
void mpool_free(mpool_t *pool, void *ptr) {
    (void)pool;
    if (ptr) { unexpected_frees++; free(ptr); }
}
void mpool_destroy(mpool_t *pool) { (void)pool; assert(0); }
#endif

static void setup(struct cli_matcher *root, struct cli_ac_patt *patterns,
                  struct cli_ac_lsig **logical) {
    memset(root, 0, sizeof(*root));
#ifdef USE_MPOOL
    root->mempool = expected_pool;
#endif
    root->ac_patterns = 2;
    root->ac_pattable = malloc(2 * sizeof(*root->ac_pattable));
    assert(root->ac_pattable);
    root->ac_pattable[0] = patterns;
    root->ac_pattable[1] = patterns + 1;
    root->ac_lsigs = 2;
    root->ac_lsigtable = logical;
}

int main(void) {
    struct cli_ac_patt patterns[2] = {{0}}, before[2];
    struct cli_ac_lsig a = {0}, b = {0};
    struct cli_ac_lsig *logical[2] = {&a, &b};
    struct cli_matcher root;
    uint16_t tokens[3] = {0x12, 0x34, 0x56};
    char name[] = "Keep.Name";
    patterns[0].pattern = tokens;
    patterns[0].virname = name;
    patterns[0].length[0] = 3;
    patterns[1].pattern = tokens + 1;
    patterns[1].lsigid[0] = 1;
    memcpy(before, patterns, sizeof(before));

    cli_ac_retire_pattern_directory(NULL);
    setup(&root, patterns, logical);
    struct cli_ac_patt **old = root.ac_pattable;
    cli_ac_retire_pattern_directory(&root);
    assert(root.ac_patterns == 2);
    assert(!memcmp(patterns, before, sizeof(before)));
    assert(patterns[0].pattern == tokens && patterns[0].virname == name);
#if defined(USE_MPOOL) && !defined(ENABLE_AC_DIRECTORY_RETENTION)
    assert(root.ac_pattable == NULL && releases == 1);
    /* Destruction must not dereference the retired directory or free pooled
     * pattern/token/name payload that is still owned by the containing pool. */
    root.ac_lsigtable = NULL;
    root.ac_lsigs = 0;
    cli_ac_free(&root);
    assert(!unexpected_frees);
    assert(!memcmp(patterns, before, sizeof(before)));
    cli_ac_retire_pattern_directory(&root);
    assert(releases == 1);
#else
    assert(root.ac_pattable == old && !releases);
    free(root.ac_pattable);
#endif

    /* Non-NULL macro metadata is a runtime-lookup dependency, even if the
     * pointed-to array happens to contain only zero IDs. */
    uint32_t ids[2] = {0, 0};
    b.tdb.macro_ptids = ids;
    setup(&root, patterns, logical);
    old = root.ac_pattable;
    unsigned count = releases;
    cli_ac_retire_pattern_directory(&root);
    assert(root.ac_pattable == old && releases == count);
    free(old);
    b.tdb.macro_ptids = NULL;

    setup(&root, patterns, logical);
    old = root.ac_pattable;
    root.ac_lsigtable = NULL;
    cli_ac_retire_pattern_directory(&root);
    assert(root.ac_pattable == old && releases == count);
    free(old);

    setup(&root, patterns, logical);
    old = root.ac_pattable;
    logical[1] = NULL;
    cli_ac_retire_pattern_directory(&root);
    assert(root.ac_pattable == old && releases == count);
    free(old);
    logical[1] = &b;

#ifdef USE_MPOOL
    setup(&root, patterns, logical);
    old = root.ac_pattable;
    root.mempool = NULL;
    cli_ac_retire_pattern_directory(&root);
    assert(root.ac_pattable == old && releases == count);
    free(old);
#endif

    /* Exporters must distinguish empty roots from missing required indexes. */
    struct cl_engine engine = {0};
    struct cli_matcher *roots[CLI_MTARGETS] = {0};
    memset(&root, 0, sizeof(root));
    engine.root = roots;
    roots[0] = &root;
    assert(cm_require_ac_directories(&engine));
    root.ac_patterns = 2;
    assert(!cm_require_ac_directories(&engine));
    root.ac_pattable = (struct cli_ac_patt **)(uintptr_t)1;
    root.ac_lists = 2;
    assert(!cm_require_ac_directories(&engine));
    root.ac_listtable = (struct cli_ac_list **)(uintptr_t)1;
    assert(cm_require_ac_directories(&engine));
    return 0;
}
'''


def configured_build():
    candidates = [Path(os.environ['CLAMAV_TEST_BUILD'])] if os.environ.get('CLAMAV_TEST_BUILD') else []
    candidates += [ROOT / 'build', ROOT.parent / 'clamav-system-build']
    return next((p for p in candidates if (p / 'clamav-config.h').is_file()), None)


@unittest.skipUnless(shutil.which('cc'), 'C compiler needed')
class PatternDirectoryTests(unittest.TestCase):
    def compile_and_run(self, mode):
        build = configured_build()
        if build is None:
            self.skipTest('configure ClamAV or set CLAMAV_TEST_BUILD')
        cache = {}
        for line in (build / 'CMakeCache.txt').read_text().splitlines():
            if line and not line.startswith(('#', '//')) and '=' in line and ':' in line.split('=', 1)[0]:
                name, value = line.split('=', 1)
                cache[name.split(':', 1)[0]] = value
        config = (build / 'clamav-config.h').read_text()
        config = re.sub(r'(?m)^#define ENABLE_AC_DIRECTORY_RETENTION\b.*$',
                        '/* directory retention disabled for this test */', config)
        config = re.sub(r'(?m)^#define USE_MPOOL\b.*$',
                        '/* pool mode selected below */', config)
        if mode == 'no-pool':
            config += '\n#undef USE_MPOOL\n'
        else:
            config += '\n#define USE_MPOOL 1\n'
        if mode == 'retain':
            config += '\n#define ENABLE_AC_DIRECTORY_RETENTION 1\n'
        includes = [ROOT / 'libclamav', build, build / 'libclamav',
                    ROOT / 'libclamunrar_iface', ROOT / 'libclammspack', ROOT / 'libclamav_rust',
                    ROOT / 'tools/compact-memory']
        includes += [Path(cache[k]) for k in ('JSONC_INCLUDE_DIR', 'LIBXML2_INCLUDE_DIR')
                     if cache.get(k) and not cache[k].endswith('-NOTFOUND')]
        flags = ['-std=gnu11', '-DHAVE_CONFIG_H', '-O0', '-ffunction-sections', '-fdata-sections']
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'clamav-config.h').write_text(config)
            (work / 'driver.c').write_text(DRIVER)
            command = ['cc', *flags, '-I' + str(work)]
            command += ['-I' + str(p) for p in includes]
            command += [str(ROOT / 'libclamav/matcher-ac.c'), str(work / 'driver.c'),
                        '-Wl,--gc-sections', '-o', str(work / 'probe')]
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run([str(work / 'probe')], check=True, capture_output=True, text=True)

    def test_pool_retirement_preserves_payloads_and_macro_fallback(self):
        self.compile_and_run('pool')

    def test_research_retention_preserves_directory(self):
        self.compile_and_run('retain')

    def test_no_pool_keeps_individual_cleanup_ownership(self):
        self.compile_and_run('no-pool')


if __name__ == '__main__':
    unittest.main()
