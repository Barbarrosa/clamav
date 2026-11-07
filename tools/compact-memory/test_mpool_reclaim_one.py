#!/usr/bin/env python3
"""Test targeted reclaim in production mpool code, not a cloned allocator.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]

HARNESS=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
static unsigned advice_calls, advice_failures;
static size_t advised_bytes;
static uintptr_t advised_start;
static int fail_advice;
static int test_madvise(void *ptr, size_t size, int advice) {
    ++advice_calls;advised_start=(uintptr_t)ptr;advised_bytes=size;
    if (fail_advice) {++advice_failures;errno=EINVAL;return -1;}
    return (int)syscall(SYS_madvise,ptr,size,advice);
}
#define madvise test_madvise
#include "mpool.c"
#undef madvise

static void check(const unsigned char *ptr,size_t n,unsigned char byte) {
    for (size_t i=0;i<n;++i) assert(ptr[i]==byte);
}

static struct FRAG *base(void *ptr,unsigned *bits) {
    struct FRAG *f=(struct FRAG*)((char*)ptr-FRAG_OVERHEAD);
    *bits=f->u.a.sbits;
    return allocbase_fromfrag(f);
}

int main(void) {
    const size_t large=1048512;
    mpool_t *mp=mpool_create();assert(mp);
    unsigned char *first=mpool_malloc(mp,large),*retired=mpool_malloc(mp,large);
    unsigned char *guard=mpool_malloc(mp,193),*failed=mpool_malloc(mp,large);
    assert(first&&retired&&guard&&failed);
    memset(first,0x11,large);memset(retired,0x5a,large);
    memset(guard,0x6c,193);memset(failed,0x33,large);
    unsigned bits,first_bits;
    struct FRAG *retired_base=base(retired,&bits),*first_base=base(first,&first_bits);
    assert(bits==first_bits);
    mpool_free(mp,first);
    assert(mp->avail[bits]==first_base);
    errno=ERANGE;
    MPOOL_FREE_RECLAIM(mp,retired);
    assert(errno==ERANGE);
    assert(mp->avail[bits]==retired_base&&retired_base->u.next.ptr==first_base);
    check(guard,193,0x6c);check(failed,large,0x33);
    uintptr_t start=align_to_pagesize(mp,(uintptr_t)retired_base+sizeof(*retired_base));
    uintptr_t end=(uintptr_t)retired_base+from_bits(bits);end-=end%mp->psize;
    assert(start<end);
#ifdef HAVE_MADVISE
    assert(advice_calls==1&&advice_failures==0);
    assert(advised_start==start&&advised_bytes==end-start);
    assert(start>=(uintptr_t)retired_base+sizeof(*retired_base));
    assert(end<=(uintptr_t)retired_base+from_bits(bits));
    check((const unsigned char*)start,end-start,0);
#else
    assert(advice_calls==0);
#endif
    unsigned char *reused=mpool_malloc(mp,large);assert(reused==retired);
    assert(mp->avail[bits]==first_base);
    /* Metadata and partial boundary pages stay valid after advice. */
    assert(reused[sizeof(struct FRAG)]==0x5a);
    check(guard,193,0x6c);
    memset(reused,0x42,large);
    reused=mpool_realloc(mp,reused,large+8);assert(reused);
    check(reused,large,0x42);

    unsigned failed_bits;struct FRAG *failed_base=base(failed,&failed_bits);
    unsigned before=advice_calls;
    fail_advice=1;errno=ERANGE;
    MPOOL_FREE_RECLAIM(mp,failed);assert(errno==ERANGE);
    assert(mp->avail[failed_bits]==failed_base);
#ifdef HAVE_MADVISE
    assert(advice_calls==before+1&&advice_failures==1);
#else
    assert(advice_calls==before);
#endif
    failed=mpool_malloc(mp,large);assert(failed);
    check(failed+sizeof(struct FRAG),large-sizeof(struct FRAG),0x33);check(guard,193,0x6c);
    /* Small and NULL retirements do not advise or traverse old free nodes. */
    unsigned char *small=mpool_malloc(mp,97);assert(small);memset(small,0x4d,97);
    before=advice_calls;errno=ERANGE;
    MPOOL_FREE_RECLAIM(mp,small);MPOOL_FREE_RECLAIM(mp,NULL);
    assert(errno==ERANGE&&advice_calls==before);
    small=mpool_malloc(mp,97);assert(small);
    /* Free-list links may overwrite a freed allocation's payload prefix. */
    check(small+sizeof(struct FRAG),97-sizeof(struct FRAG),0x4d);
    printf("{\"checks\":\"passed\",\"advice_calls\":%u,\"advice_failures\":%u,\"one_fragment_only\":true,\"metadata_and_reuse_preserved\":true}\n",advice_calls,advice_failures);
    mpool_destroy(mp);return 0;
}
'''


def run(source=ROOT/'libclamav/mpool.c',*,advice=True,sanitize=False):
    spec=importlib.util.spec_from_file_location('mpool_flush',ROOT/'tools/compact-memory/test_mpool_flush.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory() as name:
        work=Path(name)
        for file in ('mpool.c','mpool.h','memory_perturb.h'):
            shutil.copy2(source.parent/file,work/file)
        for file,text in module.HEADERS.items():(work/file).write_text(text)
        (work/'probe.c').write_text(HARNESS)
        cmd=['cc','-std=c11','-D_DEFAULT_SOURCE','-DUSE_MPOOL','-DHAVE_UNISTD_H=1',
             '-DHAVE_STRING_H=1','-DHAVE_MMAP=1','-DHAVE_SYS_MMAN_H=1',
             '-DSIZEOF_VOID_P=8','-DC_LINUX=1','-DANONYMOUS_MAP=MAP_ANONYMOUS',
             '-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-O2','probe.c','-o','probe']
        if advice:cmd.insert(1,'-DHAVE_MADVISE=1')
        if sanitize:cmd[1:1]=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
        subprocess.run(cmd,cwd=work,check=True,capture_output=True)
        env=os.environ.copy()
        if sanitize:env['ASAN_OPTIONS']='detect_leaks=0'
        result=subprocess.run([str(work/'probe')],check=True,capture_output=True,text=True,env=env)
        return json.loads(result.stdout)


@unittest.skipUnless(shutil.which('cc'),'C compiler needed')
class ReclaimOneTests(unittest.TestCase):
    def test_advice_success_failure_boundaries_and_exact_reuse(self):
        self.assertEqual(run()['checks'],'passed')

    def test_without_advice_is_ordinary_pool_free(self):
        self.assertEqual(run(advice=False)['checks'],'passed')

    def test_nonpool_macro_is_an_ordinary_free(self):
        with tempfile.TemporaryDirectory() as name:
            work=Path(name);shutil.copy2(ROOT/'libclamav/mpool.h',work/'mpool.h')
            (work/'probe.c').write_text('''
#include <stdlib.h>
#include <assert.h>
static unsigned calls;
static void counted_free(void *ptr) { ++calls;free(ptr); }
#define free counted_free
#include "mpool.h"
int main(void) { void *p=malloc(32);assert(p);MPOOL_FREE_RECLAIM(NULL,p);assert(calls==1);return 0; }
''')
            subprocess.run(['cc','-std=c11','-O2','probe.c','-o','probe'],cwd=work,check=True,capture_output=True)
            subprocess.run([str(work/'probe')],check=True,capture_output=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path,nargs='?',default=ROOT/'libclamav/mpool.c')
    parser.add_argument('--sanitize',action='store_true')
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    import hashlib
    result={'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest(),
            'sanitizers':args.sanitize,'advice':run(args.source,sanitize=args.sanitize),
            'fallback':run(args.source,advice=False,sanitize=args.sanitize),
            'scope':'Targeted allocator operation only; scanner behavior and memory/performance require engine qualification.'}
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
