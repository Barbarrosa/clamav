/* SPDX-License-Identifier: GPL-2.0-only
 * Internal, read-only census. Build against the exact matching source/library.
 * Sizes exclude allocator rounding unless explicitly called capacity bytes.
 */
#include "clamav-config.h"
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "filtering.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "require_ac_directories.h"

static uint64_t hot_bytes, candidate_bytes, pattern_bytes, hash_bytes, name_bytes;
static uint64_t logical_bytes, logical_aux_bytes;
static const char **all_names;
static size_t names_count, names_capacity;
/* Optional diagnostic exports; not an engine serialization format. */
static FILE *name_export, *token_export;
static void write_u32(FILE *file, uint32_t n)
{
    unsigned char bytes[4] = {n, n >> 8, n >> 16, n >> 24};
    if (fwrite(bytes, 1, 4, file) != 4) abort();
}
static void record_name(const char *name)
{
    if (!name) return;
    if (names_count == names_capacity) {
        size_t next = names_capacity ? names_capacity * 2 : 4096;
        if (next < names_capacity || next > SIZE_MAX / sizeof(*all_names)) abort();
        void *p = realloc(all_names, next * sizeof(*all_names));
        if (!p) abort();
        all_names      = p;
        names_capacity = next;
    }
    all_names[names_count++] = name;
}
static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}
static void hash_bucket(const struct cli_sz_hash *s, unsigned keylen,
                        uint64_t *items, uint64_t *bytes, uint64_t *names)
{
    *items += s->items;
    *bytes += (uint64_t)s->items * (keylen + sizeof(char *));
    for (uint32_t j = 0; j < s->items; j++)
        if (s->virusnames[j]) {
            *names += strlen(s->virusnames[j]) + 1;
            record_name(s->virusnames[j]);
        }
}
static void hash_census(const char *label, const struct cli_matcher *r)
{
    static const unsigned keylen[] = {16, 20, 32};
    if (!r) return;
    for (unsigned t = 0; t < CLI_HASH_AVAIL_TYPES; t++) {
        if (r->hm.compiled) {
            const struct cli_hash_compiled *g = &r->hm.compiled[t];
            uint64_t metadata = sizeof(*g) + g->directory.capacity * sizeof(*g->directory.htable) + (g->buckets + 1) * sizeof(*g->starts);
            uint64_t bytes = g->items * (cli_hash_len(t) + g->name_width);
            uint64_t names = g->items ? g->name_bytes : 0;
            for (size_t j = 0; j < g->items; j++) record_name(cli_hm_compiled_name(g, j));
            hash_bytes += bytes + metadata;
            name_bytes += names;
            printf("{\"kind\":\"hash\",\"layout\":\"flat\",\"purpose\":\"%s\",\"type\":%u,\"items\":%zu,\"size_buckets\":%zu,\"payload_bytes\":%" PRIu64 ",\"metadata_capacity_bytes\":%" PRIu64 ",\"name_bytes\":%" PRIu64 ",\"name_offset_width\":%u}\n", label, t, g->items, g->buckets, bytes, metadata, names, g->name_width);
            continue;
        }
        const struct cli_htu32 *ht = &r->hm.sizehashes[t];
        uint64_t items = 0, bytes = 0, names = 0, buckets = 0;
        for (size_t i = 0; i < ht->capacity; i++) {
            if (!ht->htable[i].key || ht->htable[i].key == UINT32_MAX) continue;
            buckets++;
            hash_bucket(ht->htable[i].data.as_ptr, keylen[t], &items, &bytes, &names);
        }
        hash_bucket(&r->hwild.hashes[t], keylen[t], &items, &bytes, &names);
        uint64_t metadata = ht->capacity * sizeof(*ht->htable) + buckets * sizeof(struct cli_sz_hash);
        hash_bytes += bytes + metadata;
        name_bytes += names;
        printf("{\"kind\":\"hash\",\"purpose\":\"%s\",\"type\":%u,\"items\":%" PRIu64 ",\"size_buckets\":%" PRIu64 ",\"payload_bytes\":%" PRIu64 ",\"metadata_capacity_bytes\":%" PRIu64 ",\"name_bytes\":%" PRIu64 "}\n", label, t, items, buckets, bytes, metadata, names);
    }
}
static void census(struct cl_engine *e)
{
    for (unsigned i = 0; i < CLI_MTARGETS; i++) {
        struct cli_matcher *r = e->root[i];
        if (!r) continue;
        uint64_t rows        = r->ac_root ? r->trans_cnt + 1 : 0;
        uint64_t transitions = rows * 256 * sizeof(cli_ac_transition_t);
        uint64_t nodes       = r->ac_root ? ((uint64_t)r->ac_nodes + 2) * sizeof(struct cli_ac_node) : 0;
        uint64_t filters     = r->filter ? sizeof(*r->filter) : 0;
        uint64_t candidates  = (uint64_t)r->ac_lists * (sizeof(struct cli_ac_list) + sizeof(void *));
        uint64_t patterns    = (uint64_t)r->ac_patterns * (sizeof(struct cli_ac_patt) + sizeof(void *));
        uint64_t ext = 0, tokens = 0, names = 0;
        uint64_t byte_patterns = 0, byte_tokens = 0, runs = 0, tagged = 0;
        uint64_t simple_offsets = 0, logical_patterns = 0, multipart = 0;
        for (uint32_t j = 0; j < r->ac_patterns; j++) {
            const struct cli_ac_patt *p = r->ac_pattable[j];
            uint32_t count = (uint32_t)p->length[0] + p->prefix_length[0];
            bool bytes_only = true;
            unsigned previous = UINT32_MAX;
            if (token_export) write_u32(token_export, count);
            for (uint32_t k = 0; k < count; k++) {
                unsigned value = k < p->prefix_length[0] ? p->prefix[k] : p->pattern[k - p->prefix_length[0]];
                if (value > 255) { bytes_only = false; tagged++; }
                if (value != previous) runs++;
                previous = value;
                if (token_export) {
                    unsigned char encoded[2] = {value, value >> 8};
                    if (fwrite(encoded, 1, 2, token_export) != 2) abort();
                }
            }
            if (bytes_only) { byte_patterns++; byte_tokens += count; }
            if (p->offdata[0] == CLI_OFF_ANY) simple_offsets++;
            if (p->lsigid[0]) logical_patterns++;
            if (p->parts) multipart++;
            if (p->ext) ext += sizeof(*p->ext);
            tokens += ((uint64_t)p->length[0] + p->prefix_length[0]) * sizeof(uint16_t);
            if (p->virname) {
                names += strlen(p->virname) + 1;
                record_name(p->virname);
            }
        }
        logical_bytes += (uint64_t)r->ac_lsigs * (sizeof(struct cli_ac_lsig) + sizeof(void *));
        for (uint32_t j = 0; j < r->ac_lsigs; j++) {
            const struct cli_ac_lsig *l = r->ac_lsigtable[j];
            if (l->virname) {
                names += strlen(l->virname) + 1;
                record_name(l->virname);
            }
            if (l->type == CLI_LSIG_NORMAL && l->u.logic) logical_aux_bytes += strlen(l->u.logic) + 1;
            logical_aux_bytes += ((uint64_t)l->tdb.cnt[CLI_TDB_UINT] + (uint64_t)l->tdb.cnt[CLI_TDB_RANGE]) * sizeof(uint32_t);
            logical_aux_bytes += l->tdb.cnt[CLI_TDB_STR];
            if (l->tdb.macro_ptids) logical_aux_bytes += (uint64_t)l->tdb.subsigs * sizeof(uint32_t);
        }
        hot_bytes += transitions + nodes + filters;
        candidate_bytes += candidates;
        pattern_bytes += patterns + ext + tokens;
        name_bytes += names;
        if (name_export) printf("{\"kind\":\"encoding_profile\",\"target\":%u,\"byte_only_patterns\":%" PRIu64 ",\"byte_only_tokens\":%" PRIu64 ",\"tagged_tokens\":%" PRIu64 ",\"token_runs\":%" PRIu64 ",\"any_offset_patterns\":%" PRIu64 ",\"logical_patterns\":%" PRIu64 ",\"multipart_patterns\":%" PRIu64 "}\n", i, byte_patterns, byte_tokens, tagged, runs, simple_offsets, logical_patterns, multipart);
        printf("{\"kind\":\"ac\",\"target\":%u,\"nodes\":%u,\"patterns\":%u,\"logical\":%u,\"slots\":%zu,\"rows\":%" PRIu64 ",\"transition_bytes\":%" PRIu64 ",\"node_bytes\":%" PRIu64 ",\"filter_bytes\":%" PRIu64 ",\"candidate_bytes\":%" PRIu64 ",\"pattern_bytes\":%" PRIu64 ",\"extension_bytes\":%" PRIu64 ",\"token_bytes\":%" PRIu64 ",\"name_bytes\":%" PRIu64 ",\"pcre\":%u}\n", i, r->ac_nodes, r->ac_patterns, r->ac_lsigs, r->ac_lsig_slots, rows, transitions, nodes, filters, candidates, patterns, ext, tokens, names, r->pcre_metas);
    }
    hash_census("file", e->hm_hdb);
    hash_census("section", e->hm_mdb);
    hash_census("import", e->hm_imp);
    hash_census("false_positive", e->hm_fp);
    qsort(all_names, names_count, sizeof(*all_names), name_cmp);
    uint64_t unique_bytes = 0, unique_count = 0;
    for (size_t i = 0; i < names_count; i++) {
        if (i && !strcmp(all_names[i], all_names[i - 1])) continue;
        unique_count++;
        unique_bytes += strlen(all_names[i]) + 1;
        if (name_export) {
            size_t length = strlen(all_names[i]);
            if (length > UINT32_MAX) abort();
            write_u32(name_export, length);
            if (fwrite(all_names[i], 1, length, name_export) != length) abort();
        }
    }
    printf("{\"kind\":\"resident_floor_components\",\"unique_names\":%" PRIu64 ",\"unique_name_bytes\":%" PRIu64 ",\"logical_records_bytes\":%" PRIu64 ",\"logical_aux_bytes_before_interning\":%" PRIu64 ",\"ac_core_bytes\":%" PRIu64 "}\n", unique_count, unique_bytes, logical_bytes, logical_aux_bytes, hot_bytes);
    free(all_names);
    printf("{\"kind\":\"totals\",\"resident_ac_core_bytes\":%" PRIu64 ",\"candidate_bytes\":%" PRIu64 ",\"pattern_bytes\":%" PRIu64 ",\"hash_bytes\":%" PRIu64 ",\"name_bytes_before_interning\":%" PRIu64 "}\n", hot_bytes, candidate_bytes, pattern_bytes, hash_bytes, name_bytes);
}
int main(int argc, char **argv)
{
    unsigned n = 0;
    cl_error_t s;
    struct cl_engine *e;
    if ((argc != 3 && argc != 5) || cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) return 1;
    if (argc == 5) {
        name_export = fopen(argv[3], "wb");
        token_export = fopen(argv[4], "wb");
        if (!name_export || !token_export) return 6;
    }
    e = cl_engine_new();
    if (!e) return 2;
    if (cl_engine_set_num(e, CL_ENGINE_DISABLE_CACHE, 1) != CL_SUCCESS || cl_engine_set_str(e, CL_ENGINE_CVDCERTSDIR, argv[2]) != CL_SUCCESS) return 3;
    if ((s = cl_load(argv[1], e, &n, CL_DB_STDOPT)) != CL_SUCCESS) {
        fprintf(stderr, "load: %s\n", cl_strerror(s));
        return 4;
    }
    if ((s = cl_engine_compile(e)) != CL_SUCCESS) {
        fprintf(stderr, "compile: %s\n", cl_strerror(s));
        return 5;
    }
    if (!cm_require_ac_directories(e))
        return 8;
    printf("{\"kind\":\"database\",\"signatures\":%u,\"pointer_bytes\":%zu,\"transition_bytes\":%zu,\"logical_record_bytes\":%zu}\n", n, sizeof(void *), sizeof(cli_ac_transition_t), sizeof(struct cli_ac_lsig));
    census(e);
    if (name_export && fclose(name_export)) return 7;
    if (token_export && fclose(token_export)) return 7;
    cl_engine_free(e);
    return 0;
}
