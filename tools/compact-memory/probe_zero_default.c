/* SPDX-License-Identifier: GPL-2.0-only
 * Linux diagnostic: a reversible zero-default encoding of 32-bit offsets.
 * Fresh anonymous mappings isolate the OS zero-page effect from malloc reuse.
 * Not integrated into ClamAV; no scan-time claim follows from these RSS values.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#define NONE UINT32_C(0xfffffffe)
static size_t rss(void)
{
    FILE *f = fopen("/proc/self/smaps_rollup", "r"); char line[256]; size_t n = 0;
    if (!f) abort();
    while (fgets(line, sizeof(line), f)) if (sscanf(line, "Rss: %zu kB", &n) == 1) break;
    fclose(f); return n;
}
static volatile uint64_t sink;
int main(int argc, char **argv)
{
    if (argc != 3) return 1;
    unsigned encoded = strtoul(argv[1], NULL, 10), percent = strtoul(argv[2], NULL, 10);
    if (encoded > 1 || percent > 100) return 2;
    size_t slots = 1386025, bytes = slots * 4, page = sysconf(_SC_PAGESIZE);
    size_t start = rss();
    uint32_t *a = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint32_t *b = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) return 3;
    if (!encoded) for (size_t i = 0; i < slots; i++) a[i] = b[i] = NONE;
    uint32_t mask = encoded ? NONE : 0;
    uint64_t sum = 0;
    for (size_t i = 0; i < slots; i++) {
        if ((a[i] ^ mask) != NONE || (b[i] ^ mask) != NONE) abort();
        sum += a[i] ^ mask; sum += b[i] ^ mask;
    }
    sink = sum;
    size_t initialized = rss(), pages = (bytes + page - 1) / page;
    size_t touched = pages * percent / 100;
    for (size_t p = 0; p < touched; p++) {
        size_t i = p * page / 4;
        a[i] = (uint32_t)i ^ mask; b[i] = (UINT32_MAX - (uint32_t)i) ^ mask;
    }
    for (size_t i = 0; i < slots; i++) {
        int changed = i % (page / 4) == 0 && i / (page / 4) < touched;
        if ((a[i] ^ mask) != (changed ? (uint32_t)i : NONE) ||
            (b[i] ^ mask) != (changed ? UINT32_MAX - (uint32_t)i : NONE)) abort();
    }
    /* Explicit edge values: the transform is a bijection, including sentinels. */
    uint32_t edges[] = {0, 1, 0x7fffffff, 0xfffffffd, NONE, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(edges) / sizeof(*edges); i++)
        if (((edges[i] ^ NONE) ^ NONE) != edges[i]) abort();
    printf("{\"encoded\":%u,\"page_write_percent\":%u,\"slots\":%zu,\"payload_bytes\":%zu,\"start_rss_kib\":%zu,\"initialized_rss_kib\":%zu,\"after_writes_rss_kib\":%zu,\"every_slot_verified\":true}\n",
           encoded, percent, slots, bytes * 2, start, initialized, rss());
    munmap(a, bytes); munmap(b, bytes);
}
