/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only experiment: exact block interning and bounded cyclic-column rank.
 * Retains the engine as an oracle. Reported bytes are replacement structures,
 * not whole-process RSS. No scanner behavior is modified.
 */
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef CLI_AC_FLAT_NODES
#error "A matching flat-node build is required"
#endif
struct row { const uint32_t *p; uint32_t id; };
struct group { void *mask; uint16_t *offset; uint32_t *value; unsigned raw; };
struct cyclic { struct group *group; uint32_t *state_row; size_t groups, bytes; unsigned width; };
static size_t cmpbytes;
static int compare_rows(const void *a, const void *b)
{ return memcmp(((const struct row *)a)->p, ((const struct row *)b)->p, cmpbytes); }
static int compare_addresses(const void *a, const void *b)
{
    uintptr_t x = (uintptr_t)((const struct row *)a)->p, y = (uintptr_t)((const struct row *)b)->p;
    return (x > y) - (x < y);
}
static void *alloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) abort(); return p; }
static uint64_t mask_get(const void *p, unsigned w, unsigned c)
{ return w == 16 ? ((const uint16_t *)p)[c] : w == 32 ? ((const uint32_t *)p)[c] : ((const uint64_t *)p)[c]; }
static void mask_set(void *p, unsigned w, unsigned c, uint64_t m)
{ if (w == 16) ((uint16_t *)p)[c] = m; else if (w == 32) ((uint32_t *)p)[c] = m; else ((uint64_t *)p)[c] = m; }
static uint32_t cyclic_lookup(const struct cyclic *v, uint32_t state, unsigned c)
{
    uint32_t row = v->state_row[state], pos = row % v->width;
    const struct group *g = &v->group[row / v->width];
    if (g->raw) return g->value[pos * 256 + c];
    uint64_t bits = mask_get(g->mask, v->width, c);
    unsigned rank = __builtin_popcountll(bits & ((UINT64_C(1) << pos) - 1));
    unsigned start = g->offset[c], index = start + rank;
    if (index == g->offset[c + 1]) index = start;
    return g->value[index];
}
static void cyclic_free(struct cyclic *v)
{
    for (size_t i = 0; i < v->groups; i++) { free(v->group[i].mask); free(v->group[i].offset); free(v->group[i].value); }
    free(v->group); free(v->state_row); memset(v, 0, sizeof(*v));
}
static struct cyclic cyclic_build(const struct cli_matcher *root, struct row *rows,
                                 size_t count, unsigned width, unsigned target, unsigned sorted)
{
    struct cyclic v = {0};
    size_t states = (size_t)root->ac_nodes + 2;
    v.width = width; v.groups = (count + width - 1) / width;
    v.group = calloc(v.groups, sizeof(*v.group)); v.state_row = alloc(states * 4);
    if (!v.group) abort();
    v.bytes = v.groups * sizeof(*v.group) + states * 4;
    struct row *addresses = alloc(count * sizeof(*addresses));
    for (size_t i = 0; i < count; i++) { addresses[i].p = rows[i].p; addresses[i].id = i; }
    qsort(addresses, count, sizeof(*addresses), compare_addresses);
    v.state_row[0] = 0;
    for (size_t i = 1; i < states; i++) {
        struct row key = {root->ac_flatnodes[i].trans, 0};
        struct row *p = bsearch(&key, addresses, count, sizeof(*addresses), compare_addresses);
        if (!p) abort();
        v.state_row[i] = p->id;
    }
    free(addresses);
    unsigned rawgroups = 0;
    for (size_t b = 0; b < v.groups; b++) {
        struct group *g = &v.group[b];
        size_t begin = b * width, n = count - begin;
        if (n > width) n = width;
        uint64_t masks[256]; uint16_t offsets[257];
        unsigned total = 0;
        for (unsigned c = 0; c < 256; c++) {
            uint64_t bits = 0;
            for (unsigned i = 0; i < n; i++)
                if (rows[begin + i].p[c] != rows[begin + (i + 1) % n].p[c]) bits |= UINT64_C(1) << i;
            if (!bits) bits = 1; /* A constant column still needs one owner. */
            masks[c] = bits; offsets[c] = total; total += __builtin_popcountll(bits);
        }
        offsets[256] = total;
        size_t packed = 256 * (width / 8) + sizeof(offsets) + total * 4;
        if (packed >= n * 1024) {
            g->raw = 1; rawgroups++; g->value = alloc(n * 1024);
            for (size_t i = 0; i < n; i++) memcpy(g->value + i * 256, rows[begin + i].p, 1024);
            v.bytes += n * 1024;
        } else {
            g->mask = alloc(256 * (width / 8)); g->offset = alloc(sizeof(offsets)); g->value = alloc(total * 4);
            memcpy(g->offset, offsets, sizeof(offsets));
            unsigned j = 0;
            for (unsigned c = 0; c < 256; c++) {
                mask_set(g->mask, width, c, masks[c]);
                uint64_t bits = masks[c];
                while (bits) { unsigned i = __builtin_ctzll(bits); g->value[j++] = rows[begin + i].p[c]; bits &= bits - 1; }
            }
            if (j != total) abort();
            v.bytes += packed;
        }
    }
    /* This checks every source state and byte, not just sampled strings. */
    for (size_t s = 1; s < states; s++) for (unsigned c = 0; c < 256; c++)
        if (cyclic_lookup(&v, s, c) != root->ac_flatnodes[s].trans[c]) abort();
    printf("{\"kind\":\"cyclic_rank\",\"target\":%u,\"width\":%u,\"lex_sorted\":%u,\"rows\":%zu,\"bytes\":%zu,\"raw_groups\":%u,\"all_state_byte_pairs_verified\":%zu}\n",
           target, width, sorted, count, v.bytes, rawgroups, (states - 1) * 256);
    fflush(stdout); return v;
}
static void microblocks(struct row *rows, size_t n, unsigned w, unsigned target, size_t states)
{
    size_t blocks = n * (256 / w);
    struct row *parts = alloc(blocks * sizeof(*parts)); uint32_t *ids = alloc(blocks * 4);
    uint32_t *payload = alloc(n * 1024);
    for (size_t i = 0; i < blocks; i++) { parts[i].p = rows[i / (256 / w)].p + (i % (256 / w)) * w; parts[i].id = i; }
    cmpbytes = w * 4; qsort(parts, blocks, sizeof(*parts), compare_rows);
    size_t distinct = 0;
    for (size_t i = 0; i < blocks; i++) {
        if (!i || memcmp(parts[i - 1].p, parts[i].p, cmpbytes)) {
            memcpy(payload + distinct * w, parts[i].p, cmpbytes); distinct++;
        }
        ids[parts[i].id] = distinct - 1;
    }
    for (size_t i = 0; i < blocks; i++)
        if (memcmp(payload + ids[i] * w, rows[i / (256 / w)].p + (i % (256 / w)) * w, cmpbytes)) abort();
    printf("{\"kind\":\"microblocks\",\"target\":%u,\"width\":%u,\"rows\":%zu,\"unique_blocks\":%zu,\"bytes_including_state_row_map\":%zu,\"all_row_entries_verified\":%zu}\n",
           target, w, n, distinct, distinct * w * 4 + blocks * 4 + states * 4, n * 256);
    fflush(stdout); free(parts); free(ids); free(payload);
}
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
static volatile uint64_t sink;
static double scan(const struct cli_matcher *root, const struct cyclic *v, unsigned char *in, size_t n, unsigned mode)
{
    uint32_t state = 1; uint64_t sum = 0; double t = now();
    for (size_t i = 0; i < n; i++) { state = mode ? cyclic_lookup(v, state, in[i]) : root->ac_flatnodes[state].trans[in[i]]; sum += state; }
    sink = sum; return now() - t;
}
int main(int argc, char **argv)
{
    if (argc != 3 || cl_init(CL_INIT_DEFAULT)) return 1;
    struct cl_engine *e = cl_engine_new(); unsigned signatures;
    if (!e || cl_engine_set_str(e, CL_ENGINE_CVDCERTSDIR, argv[2]) || cl_engine_set_num(e, CL_ENGINE_DISABLE_CACHE, 1) ||
        cl_load(argv[1], e, &signatures, CL_DB_STDOPT) || cl_engine_compile(e)) return 2;
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *r = e->root[target];
        if (!r || !r->ac_root || !r->ac_nodes) continue;
        size_t n = (size_t)r->trans_cnt + 1, states = (size_t)r->ac_nodes + 2;
        struct row *rows = alloc(n * sizeof(*rows));
        rows[0].p = r->ac_root->trans;
        for (size_t i = 1; i < n; i++) rows[i].p = r->trans_array[i - 1];
        for (unsigned w = 8; w <= 64; w *= 2) microblocks(rows, n, w, target, states);
        struct cyclic best = {0};
        for (unsigned sorted = 0; sorted < 2; sorted++) {
            if (sorted) { cmpbytes = 1024; qsort(rows, n, sizeof(*rows), compare_rows); }
            for (unsigned w = 16; w <= 64; w *= 2) {
                struct cyclic v = cyclic_build(r, rows, n, w, target, sorted);
                if (!best.bytes || v.bytes < best.bytes) { cyclic_free(&best); best = v; }
                else cyclic_free(&v);
            }
        }
        if (target == 1) {
            size_t length = 1u << 20; unsigned char *input = alloc(length);
            for (unsigned kind = 0; kind < 3; kind++) {
                uint64_t rng = 123456789;
                for (size_t i = 0; i < length; i++) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; input[i] = kind == 0 ? (unsigned char)rng : kind == 1 ? 0 : (unsigned char)i; }
                for (unsigned trial = 0; trial < 10; trial++) {
                    double times[2]; uint64_t sums[2];
                    for (unsigned order = 0; order < 2; order++) { unsigned mode = order ^ (trial & 1); times[mode] = scan(r, &best, input, length, mode); sums[mode] = sink; }
                    if (sums[0] != sums[1]) abort();
                    printf("{\"kind\":\"cyclic_timing\",\"target\":1,\"input\":%u,\"bytes\":%zu,\"trial\":%u,\"dense_seconds\":%.9f,\"cyclic_seconds\":%.9f}\n",kind,length,trial,times[0],times[1]); fflush(stdout);
                }
            }
            free(input);
        }
        cyclic_free(&best); free(rows);
    }
    cl_engine_free(e); puts("{\"kind\":\"complete\"}");
}
