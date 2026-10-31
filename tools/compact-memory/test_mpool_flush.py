#!/usr/bin/env python3
"""Regression test of production mpool_flush: page release, failures and reuse.

Linux harness with minimal compatibility headers and original allocator code.
Run with SOURCE [--sanitize] [--no-advice]; no cloned purge implementation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

HEADERS = {'clamav.h': '#include <stdint.h>\nstruct cl_engine { struct MP *mempool; };\n', 'clamav-types.h': '#include <stdint.h>\n#include <stddef.h>\n', 'others.h': '\n#include <stdio.h>\n#include <stdlib.h>\n#include <stdarg.h>\n#define UNUSEDPARAM(x) ((void)(x))\n#define CLI_STRNLEN strnlen\nstruct unaligned_ptr { void *ptr; } __attribute__((packed));\nstatic size_t cli_getpagesize(void) { return (size_t)sysconf(_SC_PAGESIZE); }\nstatic void cli_errmsg(const char *s, ...) {\n    va_list a; va_start(a,s); vfprintf(stderr,s,a); va_end(a);\n}\n#define cli_dbgmsg(...) ((void)0)\n', 'str.h': 'int cli_hex2str_to(const char *, char *, unsigned int);\nint cli_realhex2ui(const char *, uint16_t *, unsigned int);\n', 'readdb.h': '/* No definitions needed by mpool.c. */\n'}

HARNESS = r'''
#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
struct purge_stats { size_t fragments, calls, bytes, failures; };
static struct purge_stats stats;
static int fail_advice;
static int test_madvise(void *p, size_t size, int advice) {
    ++stats.calls;
    if (fail_advice) { ++stats.failures; errno=EINVAL; return -1; }
    int result = (int)syscall(SYS_madvise,p,size,advice);
    if (result==0) stats.bytes+=size; else ++stats.failures;
    return result;
}
#define madvise test_madvise
#include "mpool.c"
#undef madvise

static struct purge_stats run_flush(mpool_t *mp) {
    stats = (struct purge_stats){0};
    for (unsigned b=0; b<FRAGSBITS; ++b)
        for (struct FRAG *f=mp->avail[b]; f; f=f->u.next.ptr) ++stats.fragments;
    mpool_flush(mp);
    return stats;
}

static size_t rss_kib(void) {
    FILE *f = fopen("/proc/self/smaps_rollup", "r");
    assert(f);
    char line[512]; size_t rss = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "Rss: %zu kB", &rss) == 1) break;
    fclose(f); assert(rss); return rss;
}

static void check_bytes(const unsigned char *p, size_t n, unsigned char value) {
    for (size_t i = 0; i < n; ++i) assert(p[i] == value);
}

struct free_node { struct FRAG *base, *next; unsigned bucket; };
static size_t snapshot(mpool_t *mp, struct free_node *nodes, size_t capacity) {
    size_t n = 0;
    for (unsigned b = 0; b < FRAGSBITS; ++b)
        for (struct FRAG *f = mp->avail[b]; f; f = f->u.next.ptr) {
            assert(n < capacity);
            nodes[n++] = (struct free_node){f, f->u.next.ptr, b};
        }
    return n;
}
static void check_snapshot(mpool_t *mp, struct free_node *nodes, size_t n) {
    size_t i = 0;
    for (unsigned b = 0; b < FRAGSBITS; ++b)
        for (struct FRAG *f = mp->avail[b]; f; f = f->u.next.ptr) {
            assert(i < n && nodes[i].base == f && nodes[i].bucket == b);
            assert(nodes[i].next == f->u.next.ptr); ++i;
        }
    assert(i == n);
}

int main(void) {
    enum {N = 32, SMALL = 128};
    const size_t large_size = 1048512;
    mpool_t *mp = mpool_create(); assert(mp);
    unsigned char *live[N], *large[N], *small[SMALL];
    struct free_node nodes[256];
    for (int i = 0; i < N; ++i) {
        live[i] = mpool_malloc(mp, 193); assert(live[i]);
        memset(live[i], 0x31 + i, 193);
    }
    for (int i = 0; i < SMALL; ++i) {
        small[i] = mpool_malloc(mp, 97); assert(small[i]);
        memset(small[i], 0x7d, 97);
    }
    for (int i = 0; i < SMALL; i += 2) mpool_free(mp, small[i]);
    size_t n = snapshot(mp, nodes, 256);
    struct purge_stats small_stats = run_flush(mp);
    assert(small_stats.fragments == SMALL/2 && small_stats.calls == 0);
    check_snapshot(mp, nodes, n);
    for (int i = 1; i < SMALL; i += 2) check_bytes(small[i], 97, 0x7d);

    for (int i = 0; i < N; ++i) {
        large[i] = mpool_malloc(mp, large_size); assert(large[i]);
        memset(large[i], 0xa5, large_size);
    }
    /* Add irregular sizes whose page edges must not overwrite neighboring data. */
    const size_t sizes[] = {3753,4093,8191,16384,63500,65536};
    unsigned char *edges[6], *guards[6];
    for (int i = 0; i < 6; ++i) {
        edges[i] = mpool_malloc(mp, sizes[i]); assert(edges[i]);
        memset(edges[i], 0x99, sizes[i]);
        guards[i] = mpool_malloc(mp, 101); assert(guards[i]);
        memset(guards[i], 0x6a, 101);
    }
    for (int i = 0; i < 6; ++i) mpool_free(mp, edges[i]);
    for (int i = 0; i < N; ++i) mpool_free(mp, large[i]);
    fail_advice=1;
    errno=ERANGE;
    struct purge_stats rejected=run_flush(mp);
    assert(errno==ERANGE && rejected.bytes==0);
#ifdef HAVE_MADVISE
    assert(rejected.failures>0);
#else
    assert(rejected.calls==0);
#endif
    fail_advice=0;
    (void)rss_kib();
    n = snapshot(mp, nodes, 256);
    size_t before = rss_kib();
    struct purge_stats s = run_flush(mp);
    size_t after = rss_kib();
    #ifdef HAVE_MADVISE
    assert(s.calls > 0 && s.failures == 0 && s.bytes > 31u*1024u*1024u);
#else
    assert(s.calls == 0 && s.bytes == 0);
#endif
    check_snapshot(mp, nodes, n);
    for (int i = 0; i < N; ++i) check_bytes(live[i], 193, 0x31 + i);
    for (int i = 0; i < 6; ++i) check_bytes(guards[i], 101, 0x6a);
    for (int i = 1; i < SMALL; i += 2) check_bytes(small[i], 97, 0x7d);

    /* Repeat purge without mutation: free links must remain valid. */
    struct purge_stats again = run_flush(mp);
    assert(again.bytes == s.bytes && again.failures == 0);
    check_snapshot(mp, nodes, n);

    /* Same free-list pop sequence and user addresses after physical reclamation. */
    for (int i = N-1; i >= 0; --i) {
        unsigned char *p = mpool_malloc(mp, large_size);
        assert(p == large[i]);
        memset(p, 0x42, large_size);
        check_bytes(p, large_size, 0x42);
    }
    for (int i = 0; i < N; ++i) mpool_free(mp, large[i]);
    assert(run_flush(mp).failures == 0);
    for (int i = N-1; i >= 0; --i) {
        unsigned char *p = mpool_calloc(mp, 1, large_size);
        assert(p == large[i]); check_bytes(p, large_size, 0);
        large[i] = p;
    }
    for (int i = 0; i < N; ++i) check_bytes(live[i], 193, 0x31 + i);
    for (int i = 0; i < 6; ++i) check_bytes(guards[i], 101, 0x6a);
    printf("{\"page_bytes\":%zu,\"fragments\":%zu,\"advice_calls\":%zu,"
           "\"advised_bytes\":%zu,\"advice_failures\":%zu,\"rss_before_kib\":%zu,"
           "\"rss_after_kib\":%zu,\"rss_reduction_kib\":%zd,"
           "\"small_only_advice_calls\":%zu,\"checks\":\"passed\"}\n",
           mp->psize,s.fragments,s.calls,s.bytes,s.failures,before,after,
           (ssize_t)before-(ssize_t)after,small_stats.calls);
    mpool_destroy(mp);
    return 0;
}
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("--sanitize", action="store_true")
    p.add_argument("--no-advice", action="store_true")
    args = p.parse_args()
    source = args.source.resolve() / "libclamav" / "mpool.c"
    with tempfile.TemporaryDirectory(prefix="mpool-reconsideration-") as temp:
        work = Path(temp)
        shutil.copy2(source, work / "mpool.c")
        shutil.copy2(source.with_name("mpool.h"), work / "mpool.h")
        for name, content in HEADERS.items():
            (work / name).write_text(content)
        (work / "probe.c").write_text(HARNESS)
        flags = ["-std=c11", "-D_DEFAULT_SOURCE", "-DUSE_MPOOL", "-DHAVE_UNISTD_H=1",
                 "-DHAVE_STRING_H=1", "-DHAVE_MMAP=1", "-DHAVE_SYS_MMAN_H=1",
                 "-DSIZEOF_VOID_P=8", "-DC_LINUX=1", "-DANONYMOUS_MAP=MAP_ANONYMOUS",
                 "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"]
        if not args.no_advice:
            flags += ["-DHAVE_MADVISE=1"]
        flags += (["-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"]
                  if args.sanitize else ["-O2"])
        subprocess.run(["cc", *flags, "probe.c", "-o", "probe"], cwd=work, check=True)
        runs = [json.loads(subprocess.check_output([str(work/"probe")], text=True))
                for _ in range(1 if args.sanitize else 3)]
    print(json.dumps({"scope":"production mpool_flush isolated regression",
                      "mpool_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                      "platform":platform.platform(), "compiler":subprocess.check_output(
                          ["cc","--version"],text=True).splitlines()[0],
                      "sanitized":args.sanitize, "advice_enabled":not args.no_advice, "asan_options":os.environ.get("ASAN_OPTIONS"), "runs":runs}, indent=2))

if __name__ == "__main__":
    main()
