"""Execute production candidate retirement/destruction against heap and pool.

Requires an existing configured ClamAV build, selected with
CLAMAV_CANDIDATE_CONFIG_DIR. No scanner benchmark or memory-saving claim is made.
SPDX-License-Identifier: GPL-2.0-only
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = r'''
#include "clamav-config.h"
#include "clamav.h"
#include "matcher.h"
#include "matcher-ac.h"
#include "mpool.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Unrelated references from the production pool translation unit. */
void cli_errmsg(const char *format, ...) { (void)format; }
void cli_dbgmsg(const char *format, ...) { (void)format; }
int cli_hex2str_to(const char *hex, char *ptr, size_t len)
{ (void)hex; (void)ptr; (void)len; return -1; }
int cli_realhex2ui(const char *hex, uint16_t *ptr, unsigned int len)
{ (void)hex; (void)ptr; (void)len; return -1; }

enum { COUNT = 512 };
static struct cli_ac_list *objects[COUNT];
static unsigned frees[COUNT], table_frees;
static void *original_table;
void __real_free(void *ptr);
static void record_free(void *ptr)
{
    unsigned i;
    if (ptr) {
        if (ptr == original_table) ++table_frees;
        for (i = 0; i < COUNT; ++i) if (ptr == objects[i]) ++frees[i];
    }
}
void __wrap_free(void *ptr) { record_free(ptr); __real_free(ptr); }
#ifdef USE_MPOOL
void __real_mpool_free(mpool_t *pool, void *ptr);
void __wrap_mpool_free(mpool_t *pool, void *ptr)
{ record_free(ptr); __real_mpool_free(pool, ptr); }
#endif

int main(void)
{
    struct cli_matcher root = {0};
    struct cli_ac_patt pattern = {0};
    struct cli_ac_list copies[COUNT];
    unsigned i;
#ifdef USE_MPOOL
    mpool_t *pool = mpool_create();
    assert(pool);
    root.mempool = pool;
#endif
    root.ac_lists = COUNT;
    root.ac_listtable = MPOOL_CALLOC(root.mempool, COUNT, sizeof(*root.ac_listtable));
    assert(root.ac_listtable);
    original_table = root.ac_listtable;
    for (i = 0; i < COUNT; ++i) {
        objects[i] = root.ac_listtable[i] = MPOOL_CALLOC(root.mempool, 1, sizeof(*objects[i]));
        assert(objects[i]);
        objects[i]->me = &pattern;
        if (i) {
            objects[i]->next = objects[i - 1];
            objects[i]->next_same = objects[i / 2];
        }
        copies[i] = *objects[i];
    }
    cli_ac_discard_listtable(NULL);
    cli_ac_discard_listtable(&root);
    assert(root.ac_lists == COUNT);
#if defined(USE_MPOOL) && !defined(ENABLE_AC_DIRECTORY_RETENTION)
    assert(root.ac_listtable == NULL);
    cli_ac_discard_listtable(&root); /* Idempotent retirement, not recompilation. */
    /* Every identity and both ordered-link fields remain byte-identical. */
    for (i = 0; i < COUNT; ++i) assert(!memcmp(objects[i], &copies[i], sizeof(copies[i])));
#else
    assert(root.ac_listtable == original_table);
    for (i = 0; i < COUNT; ++i) assert(!memcmp(objects[i], &copies[i], sizeof(copies[i])));
#endif
    cli_ac_free(&root);
#ifdef USE_MPOOL
#ifndef ENABLE_AC_DIRECTORY_RETENTION
    /* Omitted per-candidate frees do not transfer ownership out of the pool. */
    for (i = 0; i < COUNT; ++i) {
        assert(frees[i] == 0);
        assert(!memcmp(objects[i], &copies[i], sizeof(copies[i])));
    }
#else
    assert(table_frees == 1);
    for (i = 0; i < COUNT; ++i) assert(frees[i] == 1);
#endif
    {
        uintptr_t old_page = (uintptr_t)objects[0];
        size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
        unsigned char resident;
        old_page -= old_page % page_size;
        mpool_destroy(pool);
        errno = 0;
        assert(mincore((void *)old_page, page_size, &resident) == -1);
        assert(errno == ENOMEM);
    }
#else
    assert(table_frees == 1);
    for (i = 0; i < COUNT; ++i) assert(frees[i] == 1);
#endif
    return 0;
}
'''


class CandidateDirectoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        option = os.environ.get('CLAMAV_CANDIDATE_CONFIG_DIR')
        choices = [Path(option)] if option else [ROOT / 'build', ROOT.parent / 'clamav-system-build']
        cls.config = next((p for p in choices if (p / 'clamav-config.h').exists()), None)
        cls.compiler = shutil.which(os.environ.get('CC', 'cc'))
        if cls.config is None or cls.compiler is None:
            raise unittest.SkipTest('a configured ClamAV build and C compiler are required')
        cls.directory = tempfile.TemporaryDirectory(prefix='candidate-directory-')
        cls.tmp = Path(cls.directory.name)
        (cls.tmp / 'fixture.c').write_text(FIXTURE)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def build_and_run(self, pool, retain):
        case = self.tmp / ('pool' + str(int(pool)) + '-retain' + str(int(retain)))
        case.mkdir()
        config = (self.config / 'clamav-config.h').read_text()
        config = re.sub(r'^#define ENABLE_AC_DIRECTORY_RETENTION.*$', '', config, flags=re.M)
        if not pool:
            config = config.replace('#define USE_MPOOL 1', '/* Test the original heap fallback. */')
        if retain:
            config += '\n#define ENABLE_AC_DIRECTORY_RETENTION 1\n'
        (case / 'clamav-config.h').write_text(config)
        includes = [case, self.config, self.config / 'libclamav', ROOT / 'libclamav', ROOT,
                    ROOT / 'libclamunrar_iface', ROOT / 'libclammspack/mspack', ROOT / 'libclamav_rust']
        sysroot = ROOT.parent / 'clamav-sysroot/usr/include'
        if sysroot.exists():
            includes += [sysroot, sysroot / 'json-c', sysroot / 'libxml2']
        command = [self.compiler, '-std=gnu11', '-O1', '-DHAVE_CONFIG_H',
                   '-ffunction-sections', '-fdata-sections']
        command += [flag for path in includes for flag in ('-I', str(path))]
        command += [str(self.tmp / 'fixture.c'), str(ROOT / 'libclamav/matcher-ac.c')]
        if pool:
            command += [str(ROOT / 'libclamav/mpool.c')]
        command += ['-Wl,--gc-sections', '-Wl,--wrap=free', '-pthread', '-o', str(case / 'test')]
        if pool:
            command += ['-Wl,--wrap=mpool_free']
        build = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(build.returncode, 0, '\n'.join(build.stderr.splitlines()[:60]))
        run = subprocess.run([str(case / 'test')], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_pool_retirement_preserves_links_and_pool_owns_lifetime(self):
        self.build_and_run(pool=True, retain=False)

    def test_retained_diagnostic_directory_keeps_legacy_individual_cleanup(self):
        self.build_and_run(pool=True, retain=True)

    def test_heap_fallback_keeps_directory_and_frees_every_entry_once(self):
        self.build_and_run(pool=False, retain=False)


if __name__ == '__main__':
    unittest.main()
