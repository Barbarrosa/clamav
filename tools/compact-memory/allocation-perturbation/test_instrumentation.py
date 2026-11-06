"""Exercise actual heap/pool perturbation paths without building the scanner.

Uses a configured ClamAV build's headers (CLAMAV_PERTURB_CONFIG_DIR), the real
mpool.c, and only logging/hex stubs for unrelated references. Measurements are
not taken here. SPDX-License-Identifier: GPL-2.0-only
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = r'''
#include "clamav-config.h"
#include "memory_perturb.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Pool logging and unreachable hex-decoder references only. */
void cli_errmsg(const char *format, ...) { (void)format; }
void cli_dbgmsg(const char *format, ...) { (void)format; }
int cli_hex2str_to(const char *hex, char *ptr, size_t len)
{ (void)hex; (void)ptr; (void)len; return -1; }
int cli_realhex2ui(const char *hex, uint16_t *ptr, unsigned int len)
{ (void)hex; (void)ptr; (void)len; return -1; }

static void snapshot(void) {
#ifdef CM_MEMORY_PERTURB
    cm_perturb_snapshot("fixture");
#endif
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "normal";
    unsigned char *p, *q;
    size_t i;
    mpool_t *pool;
    if (!strcmp(mode, "heap")) {
        p = CM_PERTURB_CALLOC("patterns", 4, 8);
        assert(p);
        for (i = 0; i < 32; ++i) assert(p[i] == 0);
        memset(p, 0xa3, 32);
        q = CM_PERTURB_REALLOC("patterns", p, 512);
        assert(q);
        for (i = 0; i < 32; ++i) assert(q[i] == 0xa3);
        p = CM_PERTURB_REALLOC("patterns", q, SIZE_MAX);
        assert(!p);
        for (i = 0; i < 32; ++i) assert(q[i] == 0xa3);
        free(q);
        assert(!CM_PERTURB_CALLOC("patterns", SIZE_MAX, 2));
    } else if (!strcmp(mode, "pool")) {
        pool = mpool_create(); assert(pool);
        p = CM_MPOOL_CALLOC("patterns", pool, 1, 24); assert(p);
        assert((uintptr_t)p % 8 == 0);
        for (i = 0; i < 24; ++i) assert(p[i] == 0);
        memset(p, 0x61, 24);
        q = CM_MPOOL_REALLOC("patterns", pool, p, 512); assert(q);
        assert((uintptr_t)q % 8 == 0);
        for (i = 0; i < 24; ++i) assert(q[i] == 0x61);
#ifdef CM_MEMORY_PERTURB
        p = CM_MPOOL_REALLOC("patterns", pool, q, SIZE_MAX);
        assert(!p);
        for (i = 0; i < 24; ++i) assert(q[i] == 0x61);
        assert(!CM_MPOOL_CALLOC("patterns", pool, SIZE_MAX, 2));
#endif
        assert(!CM_MPOOL_REALLOC("patterns", pool, q, 0));
        for (i = 0; i < 24; ++i) assert(q[i] == 0x61);
        mpool_free(pool, q);
        for (i = 1; i <= 64; ++i) {
            p = CM_MPOOL_MALLOC("patterns", pool, i); assert(p);
            /* Preserve the original pool's size-derived alignment. */
            if (!(i % 8)) assert(!((uintptr_t)p % 8));
            else if (!(i % 4)) assert(!((uintptr_t)p % 4));
            else if (!(i % 2)) assert(!((uintptr_t)p % 2));
            memset(p, 0x3c, i); mpool_free(pool, p);
        }
        mpool_destroy(pool);
    } else if (!strcmp(mode, "cap")) {
        p = CM_PERTURB_MALLOC("patterns", 32); assert(p);
        memset(p, 0x27, 32);
        q = CM_PERTURB_REALLOC("patterns", p, 64); assert(!q);
        for (i = 0; i < 32; ++i) assert(p[i] == 0x27);
        assert(!CM_PERTURB_MALLOC("patterns", 32));
        /* The cap only blocks selected categories. */
        q = CM_PERTURB_MALLOC("names", 32); assert(q);
        free(q); free(p);
    } else if (!strcmp(mode, "once")) {
        pool = mpool_create(); assert(pool);
        p = CM_MPOOL_CALLOC("patterns", pool, 2, 16); assert(p);
        q = CM_MPOOL_REALLOC("patterns", pool, p, 512); assert(q);
        mpool_free(pool, q); mpool_destroy(pool);
    } else if (!strcmp(mode, "rollback")) {
        /* Fits size_t after padding, but exceeds the maximum malloc object.
         * A failed underlying allocation must release its cap reservation. */
        p = CM_PERTURB_MALLOC("patterns", SIZE_MAX / 2); assert(!p);
        p = CM_PERTURB_MALLOC("patterns", 32); assert(p); free(p);
    } else if (!strcmp(mode, "zero")) {
        pool = mpool_create(); assert(pool);
        assert(!CM_MPOOL_MALLOC("patterns", pool, 0));
        assert(!CM_MPOOL_CALLOC("patterns", pool, 0, 16));
        mpool_destroy(pool);
        p = CM_PERTURB_MALLOC("patterns", 0); free(p);
        p = CM_PERTURB_CALLOC("patterns", 0, 16); free(p);
    } else {
        return 2;
    }
    snapshot();
    return 0;
}
'''


class InstrumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = os.environ.get('CLAMAV_PERTURB_CONFIG_DIR')
        candidates = ([Path(config)] if config else
                      [ROOT / 'build', ROOT.parent / 'clamav-system-build'])
        cls.config = next((p for p in candidates if (p / 'clamav-config.h').exists()), None)
        if cls.config is None:
            raise unittest.SkipTest('configure ClamAV first or set CLAMAV_PERTURB_CONFIG_DIR')
        compiler = shutil.which(os.environ.get('CC', 'cc'))
        if compiler is None:
            raise unittest.SkipTest('C compiler unavailable')
        cls.directory = tempfile.TemporaryDirectory(prefix='clamav-perturb-tests-')
        cls.tmp = Path(cls.directory.name)
        source = cls.tmp / 'fixture.c'
        source.write_text(FIXTURE)
        includes = [cls.config, cls.config / 'libclamav', ROOT / 'libclamav', ROOT,
                    ROOT / 'libclamunrar_iface',
                    ROOT / 'libclammspack/mspack', ROOT / 'libclamav_rust']
        sysroot = ROOT.parent / 'clamav-sysroot/usr/include'
        if sysroot.exists():
            includes.extend([sysroot, sysroot / 'json-c', sysroot / 'libxml2'])
        common = [compiler, '-std=gnu11', '-O1', '-DHAVE_CONFIG_H']
        common.extend(flag for p in includes for flag in ('-I', str(p)))
        cls.binaries = {}
        for enabled in (False, True):
            output = cls.tmp / ('enabled' if enabled else 'disabled')
            command = common + (['-DCM_MEMORY_PERTURB=1'] if enabled else [])
            command += [str(source), str(ROOT / 'libclamav/mpool.c')]
            if enabled:
                command += [str(ROOT / 'libclamav/memory_perturb.c')]
            command += ['-pthread', '-o', str(output)]
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError('fixture compilation failed:\n' + result.stderr)
            cls.binaries[enabled] = output

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_fixture(self, mode, dose=32, cap=10000000, enabled=True):
        log = self.tmp / (self.id().split('.')[-1] + '.jsonl')
        log.unlink(missing_ok=True)
        env = dict(os.environ, CM_PAD_GROUP='patterns', CM_PAD_BYTES=str(dose),
                   CM_PAD_MAX_BYTES=str(cap), CM_PAD_LOG=str(log))
        result = subprocess.run([str(self.binaries[enabled]), mode], env=env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_heap_zeroing_copy_overflow_and_realloc_failure(self):
        self.run_fixture('heap')

    def test_actual_pool_alignment_zeroing_copy_and_failure(self):
        self.run_fixture('pool')

    def test_cap_fails_closed_and_keeps_realloc_original(self):
        self.run_fixture('cap', dose=32, cap=32)

    def test_zero_size_pool_semantics(self):
        self.run_fixture('zero')

    def test_pool_calloc_realloc_are_charged_exactly_once(self):
        records = self.run_fixture('once')
        self.assertEqual(len(records), 1)
        groups = records[0]['groups']
        self.assertEqual(groups['patterns']['calls'], 2)
        self.assertEqual(groups['patterns']['successful_calls'], 2)
        self.assertEqual(groups['patterns']['requested_bytes'], 32 + 512)
        self.assertEqual(groups['patterns']['added_bytes'], 64)
        self.assertEqual(groups['patterns']['injected_calls'], 2)
        self.assertEqual(groups['pool_other']['calls'], 0)
        self.assertIn('not live', records[0]['scope'])

    def test_failed_underlying_malloc_rolls_back_cap_reservation(self):
        records = self.run_fixture('rollback', dose=32, cap=32)
        counters = records[0]['groups']['patterns']
        self.assertEqual(counters['calls'], 2)
        self.assertEqual(counters['successful_calls'], 1)
        self.assertEqual(counters['failed_calls'], 1)
        self.assertEqual(counters['added_bytes'], 32)
        self.assertEqual(counters['skipped_cap_calls'], 0)

    def test_zero_padding_control(self):
        self.run_fixture('heap', dose=0)
        self.run_fixture('pool', dose=0)

    def test_disabled_build_has_no_instrumentation_or_log(self):
        self.assertEqual(self.run_fixture('heap', enabled=False), [])
        self.assertEqual(self.run_fixture('pool', enabled=False), [])


if __name__ == '__main__':
    unittest.main()
