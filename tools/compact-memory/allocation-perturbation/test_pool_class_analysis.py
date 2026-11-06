"""Check the arithmetic against actual production mpool allocations.
SPDX-License-Identifier: GPL-2.0-only
"""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from pool_class_analysis import inspect_source, profile

ROOT = Path(__file__).resolve().parents[3]


class PoolClassAnalysisTests(unittest.TestCase):
    def test_transition_and_logical_plateaus(self):
        classes = inspect_source(ROOT / 'libclamav/mpool.c')
        for dose in (0, 8, 32):
            self.assertEqual(profile(1024 + dose, classes)['fresh_carve_possible_charges'], [1176])
        for dose in (0, 8):
            self.assertEqual(profile(168 + dose, classes)['fresh_carve_possible_charges'], [196])
        self.assertEqual(profile(24, classes)['fresh_carve_possible_charges'], list(range(26, 34)))

    @unittest.skipUnless(shutil.which('cc'), 'C compiler needed for independent allocator check')
    def test_actual_production_header_alignment_and_charges(self):
        spec = importlib.util.spec_from_file_location('mpool_flush_harness', ROOT / 'tools/compact-memory/test_mpool_flush.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        c = r'''
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include "mpool.c"
int main(void) {
    const size_t sizes[] = {1,2,4,8,24,32,48,56,80,96,104,128,168,176,200,1024,1032,1056};
    printf("{\"header\":%zu,\"pointer_bytes\":%zu,\"cases\":[", (size_t)FRAG_OVERHEAD, sizeof(void *));
    int comma=0;
    for (unsigned s=0;s<sizeof(sizes)/sizeof(sizes[0]);++s) {
        for (unsigned residue=0;residue<8;++residue) {
            mpool_t *mp=mpool_create(); assert(mp);
            mp->u.mpm.usize += 16 + ((residue + 8 - mp->u.mpm.usize%8)%8);
            size_t before=mp->u.mpm.usize;
            void *p=mpool_malloc(mp,sizes[s]); assert(p);
            struct FRAG *f=(struct FRAG *)((char *)p-FRAG_OVERHEAD);
            assert((uintptr_t)p % alignof(sizes[s]) == 0);
            size_t charge=from_bits(f->u.a.sbits), increment=mp->u.mpm.usize-before;
            unsigned padding=f->u.a.padding;
            mpool_free(mp,p);
            void *reused=mpool_malloc(mp,sizes[s]); assert(reused);
            printf("%s[%zu,%u,%u,%zu,%zu,%d]",comma?",":"",sizes[s],alignof(sizes[s]),padding,charge,increment,reused==p);
            comma=1;mpool_destroy(mp);
        }
    }
    puts("]}"); return 0;
}
'''
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            for f in ('mpool.c', 'mpool.h', 'memory_perturb.h'):
                shutil.copy2(ROOT / 'libclamav' / f, work / f)
            for f, content in module.HEADERS.items():
                (work / f).write_text(content)
            (work / 'probe.c').write_text(c)
            flags = ['-std=c11', '-D_DEFAULT_SOURCE', '-DUSE_MPOOL', '-DHAVE_UNISTD_H=1',
                     '-DHAVE_STRING_H=1', '-DHAVE_MMAP=1', '-DHAVE_SYS_MMAN_H=1',
                     '-DSIZEOF_VOID_P=8', '-DC_LINUX=1', '-DANONYMOUS_MAP=MAP_ANONYMOUS',
                     '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-O2']
            subprocess.run(['cc', *flags, 'probe.c', '-o', 'probe'], cwd=work, check=True, capture_output=True)
            result = json.loads(subprocess.check_output([str(work / 'probe')], text=True))
        self.assertEqual(result['header'], 2)
        self.assertEqual(result['pointer_bytes'], 8)
        classes = inspect_source(ROOT / 'libclamav/mpool.c')
        for size, align, pad, charge, actual_increment, same_address_reused in result['cases']:
            p = profile(size, classes)
            self.assertEqual(align, p['alignment'])
            self.assertEqual(charge, p['by_alignment_padding'][pad]['fragment_charge_bytes'])
            self.assertEqual(actual_increment, charge)
            self.assertEqual(same_address_reused, charge == p['free_list_lookup_class'])


if __name__ == '__main__':
    unittest.main()
