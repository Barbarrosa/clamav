/* SPDX-License-Identifier: GPL-2.0-only
 * Isolated exact routing experiment for the compiled flat, depth <= 3 AC trie.
 * Retains the original engine and node/output IDs as the reference oracle.
 * This is not a production matcher or a whole-scanner memory measurement.
 */
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef CLI_AC_FLAT_NODES
#error "This probe requires flat node IDs"
#endif
#define WORDS (1u << 18)
struct directory {
    uint32_t first[256], second[65536];
    uint64_t *bits;
    uint32_t *rank, *values;
    uint32_t count;
};
static uint32_t step(const struct cli_matcher *root, uint32_t state, unsigned byte)
{
    return root->ac_flatnodes[state].trans[byte];
}
static void build(const struct cli_matcher *root, struct directory *d)
{
    d->bits = calloc(WORDS, sizeof(*d->bits));
    d->rank = malloc(WORDS * sizeof(*d->rank));
    if (!d->bits || !d->rank) abort();
    for (unsigned a = 0; a < 256; a++) {
        d->first[a] = step(root, 1, a);
        for (unsigned b = 0; b < 256; b++)
            d->second[a * 256 + b] = step(root, d->first[a], b);
    }
    for (uint32_t key = 0; key < (1u << 24); key++) {
        uint32_t state = step(root, d->second[key >> 8], key & 255);
        if (state != d->second[key & 65535]) {
            d->bits[key >> 6] |= UINT64_C(1) << (key & 63);
            d->count++;
        }
    }
    d->values = malloc((size_t)(d->count ? d->count : 1) * sizeof(*d->values));
    if (!d->values) abort();
    uint32_t n = 0;
    for (uint32_t word = 0; word < WORDS; word++) {
        d->rank[word] = n;
        uint64_t bits = d->bits[word];
        while (bits) {
            unsigned bit = __builtin_ctzll(bits);
            uint32_t key = word * 64 + bit;
            d->values[n++] = step(root, d->second[key >> 8], key & 255);
            bits &= bits - 1;
        }
    }
    if (n != d->count) abort();
}
static inline uint32_t lookup(const struct directory *d, uint32_t key)
{
    uint64_t bits = d->bits[key >> 6], mask = UINT64_C(1) << (key & 63);
    if (!(bits & mask)) return d->second[key & 65535];
    return d->values[d->rank[key >> 6] + __builtin_popcountll(bits & (mask - 1))];
}
static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}
static volatile uint64_t sink;
static double scan(const struct cli_matcher *r, const struct directory *d,
                   const unsigned char *input, size_t n, int compact)
{
    uint32_t state = 1, key = input[0] * 256u + input[1];
    uint64_t sum = 0;
    state = d->second[key];
    double start = now();
    for (size_t i = 2; i < n; i++) {
        if (compact) {
            key = ((key << 8) | input[i]) & 0xffffff;
            state = lookup(d, key);
        } else state = step(r, state, input[i]);
        sum += state;
    }
    sink = sum;
    return now() - start;
}
int main(int argc, char **argv)
{
    if (argc != 3 || cl_init(CL_INIT_DEFAULT)) return 1;
    struct cl_engine *engine = cl_engine_new();
    unsigned signatures;
    if (!engine || cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, argv[2]) ||
        cl_load(argv[1], engine, &signatures, CL_DB_STDOPT) || cl_engine_compile(engine)) return 2;
    const size_t n = 8u << 20;
    unsigned char *input = malloc(n);
    if (!input) return 3;
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *root = engine->root[target];
        if (!root || !root->ac_root || !root->ac_nodes) continue;
        if (root->ac_maxdepth > 3 || !root->ac_flatnodes) return 4;
        struct directory *d = calloc(1, sizeof(*d));
        if (!d) return 5;
        build(root, d);
        /* Exhaustively check every 3-byte key, then longer streams below. */
        for (uint32_t key = 0; key < (1u << 24); key++)
            if (lookup(d, key) != step(root, d->second[key >> 8], key & 255)) return 6;
        printf("{\"kind\":\"routing_size\",\"target\":%u,\"rows_bytes\":%" PRIu64
               ",\"directory_bytes\":%zu,\"overrides\":%u,\"all_24bit_keys_verified\":true}\n",
               target, ((uint64_t)root->trans_cnt + 1) * 256 * sizeof(cli_ac_transition_t),
               sizeof(*d) + WORDS * (sizeof(uint64_t) + sizeof(uint32_t)) + d->count * sizeof(uint32_t), d->count);
        fflush(stdout);
        if (target == 1) for (unsigned kind = 0; kind < 3; kind++) {
            uint64_t rng = 123456789;
            for (size_t i = 0; i < n; i++) {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                input[i] = kind == 0 ? (unsigned char)rng : kind == 1 ? 0 : (unsigned char)i;
            }
            uint32_t state = 1, key = 0;
            for (size_t i = 0; i < n; i++) {
                state = step(root, state, input[i]);
                key = ((key << 8) | input[i]) & 0xffffff;
                uint32_t expected = i == 0 ? d->first[key] : i == 1 ? d->second[key] : lookup(d, key);
                if (state != expected) return 7;
            }
            (void)scan(root, d, input, n, 0); (void)scan(root, d, input, n, 1);
            for (unsigned trial = 0; trial < 30; trial++) {
                double timing[2]; uint64_t sums[2];
                for (unsigned order = 0; order < 2; order++) {
                    unsigned mode = order ^ (trial & 1);
                    timing[mode] = scan(root, d, input, n, mode); sums[mode] = sink;
                }
                if (sums[0] != sums[1]) return 8;
                printf("{\"kind\":\"routing_trial\",\"target\":%u,\"input\":%u,\"bytes\":%zu,\"trial\":%u,\"dense_seconds\":%.9f,\"directory_seconds\":%.9f}\n",
                       target, kind, n, trial, timing[0], timing[1]);
            }
            fflush(stdout);
        }
        free(d->bits); free(d->rank); free(d->values); free(d);
    }
    free(input); cl_engine_free(engine);
}
