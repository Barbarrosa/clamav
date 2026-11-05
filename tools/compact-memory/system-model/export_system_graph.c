/* SPDX-License-Identifier: GPL-2.0-only
 * Single-snapshot diagnostic graph of the retained compiled AC/logical engine.
 * Raw data is private research input, never a shipping engine image. This adds
 * graph edges to the existing exact exporter without modifying scanner source.
 */
#define _POSIX_C_SOURCE 200809L
#include "clamav-config.h"
#include "clamav.h"
static void system_graph_finish(struct cl_engine *engine);
static cl_error_t system_graph_load(const char *path, struct cl_engine *engine,
                                    unsigned int *signatures, unsigned int options);
/* The existing exporter calls this only after writing its exact tables. Taking
 * the supplement immediately before destruction keeps allocation-sensitive IDs
 * and ordered links from the SAME engine instance, with no second database load.
 */
#define cl_engine_free system_graph_finish
#define cl_load system_graph_load
#define main exact_tables_main
#include "../export_exact_layouts.c"
#undef main
#undef cl_engine_free
#undef cl_load

#include <stddef.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdarg.h>

static FILE *graph_ledger;
static int system_census_printf(const char *format, ...);
#define printf system_census_printf
#define main system_census_main_unused
#include "../engine_census.c"
#undef main
#undef printf
static int system_census_printf(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = vfprintf(graph_ledger ? graph_ledger : stdout, format, arguments);
    va_end(arguments);
    return result;
}

enum object_kind {
    SG_OBJ_NAME = 1u << 0, SG_OBJ_TOKEN = 1u << 1, SG_OBJ_EXTENSION = 1u << 2,
    SG_OBJ_UINT = 1u << 3, SG_OBJ_RANGE = 1u << 4, SG_OBJ_STRING = 1u << 5,
    SG_OBJ_MACRO = 1u << 6, SG_OBJ_PROGRAM = 1u << 7, SG_OBJ_ICON = 1u << 8,
    SG_OBJ_SCALAR = 1u << 9, SG_OBJ_OPAQUE = 1u << 10, SG_OBJ_SPECIAL_TABLE = 1u << 11
};
struct object { const void *ptr; uint32_t kind, extent; };
struct row_ref { const cli_ac_transition_t *ptr; uint32_t target; };
static struct object *objects;
static size_t object_count, object_capacity;
static struct row_ref *transition_rows;
static size_t transition_count, transition_capacity;
static const char *graph_directory;
static const char *graph_skips;
static unsigned long long graph_skip_events, graph_load_events;

struct graph_skiplist { char *bytes; char **keys; size_t count; };
static int graph_skip_compare(const char *format, const char *name, const char *key)
{
    size_t n = strlen(format);
    int difference = strncmp(format, key, n);
    if (difference) return difference;
    if (key[n] != '\t') return -1;
    return strcmp(name, key + n + 1);
}
static int graph_sigload(const char *format, const char *name, unsigned int custom, void *context)
{
    (void)custom;
    struct graph_skiplist *list = context;
    graph_load_events++;
    if (!strcmp(format, "mdb") || !strcmp(format, "msb") || !strcmp(format, "imp")) name = "*";
    else if (strcmp(format, "ndb") && strcmp(format, "ldb")) return 0;
    size_t left = 0, right = list->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        int difference = graph_skip_compare(format, name, list->keys[middle]);
        if (!difference) { graph_skip_events++; return 1; }
        if (difference < 0) right = middle;
        else left = middle + 1;
    }
    return 0;
}
static cl_error_t system_graph_load(const char *path, struct cl_engine *engine,
                                    unsigned int *signatures, unsigned int options)
{
    /* Exact callback namespaces mirror the existing diagnostic scan_probe.c.
       This accepts a trusted already-prepared manifest, not an activation rule. */
    struct graph_skiplist list = {0};
    if (graph_skips && strcmp(graph_skips, "-")) {
        FILE *file = fopen(graph_skips, "rb");
        if (!file || fseek(file, 0, SEEK_END)) abort();
        long bytes = ftell(file);
        if (bytes < 0 || bytes >= 512L * 1024 * 1024 || fseek(file, 0, SEEK_SET)) abort();
        list.bytes = allocate((size_t)bytes + 1);
        if (fread(list.bytes, 1, (size_t)bytes, file) != (size_t)bytes || fclose(file)) abort();
        list.bytes[bytes] = 0;
        if (bytes && list.bytes[bytes - 1] != '\n') abort();
        for (long i = 0; i < bytes; i++) {
            if (!list.bytes[i]) abort();
            if (list.bytes[i] == '\n') list.count++;
        }
        list.keys = allocate(list.count * sizeof(*list.keys));
        size_t index = 0;
        char *start = list.bytes;
        for (long i = 0; i < bytes; i++) if (list.bytes[i] == '\n') {
            list.bytes[i] = 0;
            if (!strchr(start, '\t')) abort();
            list.keys[index++] = start; start = list.bytes + i + 1;
        }
        for (size_t i = 1; i < list.count; i++)
            if (strcmp(list.keys[i - 1], list.keys[i]) >= 0) abort();
        cl_engine_set_clcb_sigload(engine, graph_sigload, &list);
    }
    cl_error_t result = cl_load(path, engine, signatures, options);
    cl_engine_set_clcb_sigload(engine, NULL, NULL);
    free(list.bytes); free(list.keys);
    return result;
}

static void add_object(const void *ptr, uint32_t kind, size_t extent)
{
    if (!ptr) return;
    if (extent >= NIL) abort();
    if (object_count == object_capacity) {
        size_t capacity = object_capacity ? object_capacity * 2 : 4096;
        if (capacity < object_capacity || capacity > SIZE_MAX / sizeof(*objects)) abort();
        void *p = realloc(objects, capacity * sizeof(*objects));
        if (!p) abort();
        objects = p; object_capacity = capacity;
    }
    objects[object_count++] = (struct object){ptr, kind, (uint32_t)extent};
}
static int object_cmp(const void *a, const void *b)
{
    uintptr_t x = (uintptr_t)((const struct object *)a)->ptr;
    uintptr_t y = (uintptr_t)((const struct object *)b)->ptr;
    return (x > y) - (x < y);
}
static uint32_t object_id(const void *ptr)
{
    if (!ptr) return NIL;
    struct object key = {ptr, 0, 0};
    const struct object *p = bsearch(&key, objects, object_count, sizeof(*objects), object_cmp);
    if (!p || p->ptr != ptr || (size_t)(p - objects) >= NIL) abort();
    return (uint32_t)(p - objects);
}
static void add_name_object(const char *name)
{
    if (name) add_object(name, SG_OBJ_NAME, strlen(name) + 1);
}
static void add_row(const cli_ac_transition_t *ptr, uint32_t target)
{
    if (!ptr) return;
    if (transition_count == transition_capacity) {
        size_t capacity = transition_capacity ? transition_capacity * 2 : 4096;
        if (capacity < transition_capacity || capacity > SIZE_MAX / sizeof(*transition_rows)) abort();
        void *p = realloc(transition_rows, capacity * sizeof(*transition_rows));
        if (!p) abort();
        transition_rows = p; transition_capacity = capacity;
    }
    transition_rows[transition_count++] = (struct row_ref){ptr, target};
}
static int row_cmp(const void *a, const void *b)
{
    uintptr_t x = (uintptr_t)((const struct row_ref *)a)->ptr;
    uintptr_t y = (uintptr_t)((const struct row_ref *)b)->ptr;
    return (x > y) - (x < y);
}
static uint32_t row_id(const cli_ac_transition_t *ptr)
{
    if (!ptr) return NIL;
    struct row_ref key = {ptr, 0};
    const struct row_ref *p = bsearch(&key, transition_rows, transition_count, sizeof(*transition_rows), row_cmp);
    if (!p || p->ptr != ptr || (size_t)(p - transition_rows) >= NIL) abort();
    return (uint32_t)(p - transition_rows);
}
static uint32_t graph_node(const struct cli_matcher *root, const struct cli_ac_node *node, uint32_t base)
{
    if (!node) return NIL;
    if (!root->ac_flatnodes) {
        if (root->ac_nodes || node != root->ac_root) abort();
        return base;
    }
    return nodeid(root, node, base);
}
static const struct cli_ac_node *node_at(const struct cli_matcher *root, uint32_t local)
{
    if (!root->ac_flatnodes) {
        if (root->ac_nodes || local != 1) abort();
        return root->ac_root;
    }
    return root->ac_flatnodes + local;
}
static void gather_logical(const struct cli_ac_lsig *logic)
{
    const struct cli_lsig_tdb *d = &logic->tdb;
    add_name_object(logic->virname);
    if (logic->type == CLI_LSIG_NORMAL && logic->u.logic)
        add_object(logic->u.logic, SG_OBJ_PROGRAM, strlen(logic->u.logic) + 1);
    else add_object(logic->u.code_start, SG_OBJ_OPAQUE, 0);
    add_object(d->val, SG_OBJ_UINT, (size_t)d->cnt[CLI_TDB_UINT] * 4);
    add_object(d->range, SG_OBJ_RANGE, (size_t)d->cnt[CLI_TDB_RANGE] * 4);
    add_object(d->str, SG_OBJ_STRING, d->cnt[CLI_TDB_STR]);
    add_object(d->macro_ptids, SG_OBJ_MACRO, (size_t)d->subsigs * 4);
    const uint32_t *coordinates[] = {d->target, d->engine, d->nos, d->ep,
                                    d->filesize, d->container, d->handlertype};
    for (size_t i = 0; i < 7; i++) add_object(coordinates[i], SG_OBJ_SCALAR, 4);
    if (d->icongrp1) add_object(d->icongrp1, SG_OBJ_ICON, strlen(d->icongrp1) + 1);
    if (d->icongrp2) add_object(d->icongrp2, SG_OBJ_ICON, strlen(d->icongrp2) + 1);
    add_object(d->intermediates, SG_OBJ_OPAQUE, 0);
}
static void coordinate_ref(FILE *out, const struct cli_lsig_tdb *d, const uint32_t *ptr)
{
    /* Object identity alone cannot express an interior pointer. Retain both
       the exact pointer ID and source array+coordinate when available. */
    uint32_t id = NIL;
    put(out, object_id(ptr), 4);
    if (!ptr) { put(out, NIL, 4); put(out, NIL, 4); return; }
    if (coordinate(d, ptr, &id)) {
        put(out, object_id(id >> 31 ? d->range : d->val), 4);
        put(out, (id & UINT32_C(0x7fffffff)) * 4, 4);
    } else { put(out, NIL, 4); put(out, NIL, 4); }
}
static void close_checked(FILE *file) { if (fclose(file)) abort(); }
static void put64(FILE *file, uint64_t value)
{
    put(file, (uint32_t)value, 4); put(file, (uint32_t)(value >> 32), 4);
}
static void native_bytes(FILE *file, const void *ptr, size_t count)
{
    if (count && fwrite(ptr, 1, count, file) != count) abort();
}

static void native_field(FILE *out, const char *name, size_t offset, size_t width,
                         size_t count, int final)
{
    fprintf(out, "    \"%s\":{\"native_offset\":%zu,\"element_bytes\":%zu,\"count\":%zu}%s\n",
            name, offset, width, count, final ? "" : ",");
}

static void system_graph_finish(struct cl_engine *engine)
{
    size_t pattern_count = 0, link_count = 0, logical_count = 0, node_count = 0;
    /* The original exporter's name array was freed before this callback. */
    names = NULL; name_count = name_cap = 0;
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *root = engine->root[target];
        if (!root) continue;
        pattern_count += root->ac_patterns; link_count += root->ac_lists;
        logical_count += root->ac_lsigs;
        if (root->ac_root) {
            node_count += (size_t)root->ac_nodes + 1;
            add_row(root->ac_root->trans, target);
            for (size_t j = 0; j < root->trans_cnt; j++) add_row(root->trans_array[j], target);
            for (uint32_t local = 1; local <= root->ac_nodes + 1; local++)
                add_row(node_at(root, local)->trans, target);
        }
        for (uint32_t j = 0; j < root->ac_patterns; j++) {
            const struct cli_ac_patt *p = root->ac_pattable[j];
            add_name_object(p->virname); addname(p->virname);
            add_object(p->pattern, SG_OBJ_TOKEN, (size_t)p->length[0] * 2);
            add_object(p->prefix, SG_OBJ_TOKEN, (size_t)p->prefix_length[0] * 2);
            add_object(p->ext, SG_OBJ_EXTENSION, p->ext ? sizeof(*p->ext) : 0);
            if (p->ext) {
                add_object(p->ext->customdata, SG_OBJ_OPAQUE, 0);
                add_object(p->ext->special_table, SG_OBJ_SPECIAL_TABLE,
                           (size_t)p->ext->special * sizeof(void *));
            }
        }
        for (uint32_t j = 0; j < root->ac_lsigs; j++) {
            gather_logical(root->ac_lsigtable[j]); addname(root->ac_lsigtable[j]->virname);
        }
    }
    hash_names(engine->hm_hdb); hash_names(engine->hm_mdb);
    hash_names(engine->hm_imp); hash_names(engine->hm_fp);
    for (size_t i = 0; i < name_count; i++) add_name_object(names[i]);
    qsort(names, name_count, sizeof(*names), namecmp);
    size_t unique = 0;
    for (size_t i = 0; i < name_count; i++)
        if (!i || strcmp(names[i], names[i - 1])) names[unique++] = names[i];
    name_count = unique;
    qsort(objects, object_count, sizeof(*objects), object_cmp);
    unique = 0;
    for (size_t i = 0; i < object_count; i++) {
        if (!unique || objects[i].ptr != objects[unique - 1].ptr) objects[unique++] = objects[i];
        else {
            objects[unique - 1].kind |= objects[i].kind;
            if (objects[i].extent > objects[unique - 1].extent) objects[unique - 1].extent = objects[i].extent;
        }
    }
    object_count = unique;
    qsort(transition_rows, transition_count, sizeof(*transition_rows), row_cmp);
    unique = 0;
    for (size_t i = 0; i < transition_count; i++) {
        if (!unique || transition_rows[i].ptr != transition_rows[unique - 1].ptr)
            transition_rows[unique++] = transition_rows[i];
        else if (transition_rows[i].target != transition_rows[unique - 1].target) abort();
    }
    transition_count = unique;
    if (pattern_count >= NIL || link_count >= NIL || logical_count >= NIL || node_count >= NIL ||
        object_count >= NIL || transition_count >= NIL) abort();
    struct ref *patterns = allocate(pattern_count * sizeof(*patterns));
    struct ref *links = allocate(link_count * sizeof(*links));
    size_t pi = 0, li = 0;
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *root = engine->root[target]; if (!root) continue;
        for (uint32_t j = 0; j < root->ac_patterns; j++, pi++) patterns[pi] = (struct ref){root->ac_pattable[j], (uint32_t)pi};
        for (uint32_t j = 0; j < root->ac_lists; j++, li++) links[li] = (struct ref){root->ac_listtable[j], (uint32_t)li};
    }
    qsort(patterns, pattern_count, sizeof(*patterns), ptrcmp);
    qsort(links, link_count, sizeof(*links), ptrcmp);
    FILE *of = output(graph_directory, "objects.bin");
    FILE *pf = output(graph_directory, "pattern_objects.bin");
    FILE *ef = output(graph_directory, "extensions.bin");
    FILE *lf = output(graph_directory, "logical_objects.bin");
    FILE *nf = output(graph_directory, "node_graph.bin");
    FILE *rf = output(graph_directory, "transitions.bin");
    FILE *sf = output(graph_directory, "logical_slots.bin");
    FILE *targets = output(graph_directory, "targets.bin");
    FILE *native_patterns = output(graph_directory, "native_patterns.bin");
    FILE *native_links = output(graph_directory, "native_links.bin");
    FILE *native_nodes = output(graph_directory, "native_nodes.bin");
    FILE *native_logical = output(graph_directory, "native_logical.bin");
    FILE *native_extensions = output(graph_directory, "native_extensions.bin");
    FILE *pattern_addresses = output(graph_directory, "pattern_addresses.bin");
    FILE *link_addresses = output(graph_directory, "link_addresses.bin");
    FILE *node_addresses = output(graph_directory, "node_addresses.bin");
    FILE *logical_addresses = output(graph_directory, "logical_addresses.bin");
    FILE *transition_addresses = output(graph_directory, "transition_addresses.bin");
    FILE *transition_cleanup = output(graph_directory, "transition_cleanup.bin");
    put(of, (uint32_t)object_count, 4);
    uint64_t raw_object_bytes = 0, opaque_objects = 0;
    for (size_t i = 0; i < object_count; i++) {
        const struct object *o = &objects[i];
        uint32_t raw = o->kind & (SG_OBJ_EXTENSION | SG_OBJ_OPAQUE | SG_OBJ_SPECIAL_TABLE) ? 0 : o->extent;
        put(of, o->kind, 4); put(of, o->extent, 4); put(of, raw, 4);
        put(of, o->kind & SG_OBJ_NAME ? nameid(o->ptr) : NIL, 4);
        put64(of, (uint64_t)(uintptr_t)o->ptr);
        if (raw && fwrite(o->ptr, 1, raw, of) != raw) abort();
        raw_object_bytes += raw; opaque_objects += raw != o->extent || !o->extent;
        if (o->kind & SG_OBJ_EXTENSION) {
            const struct cli_ac_patt_ext *e = o->ptr;
            uint32_t values[] = {(uint32_t)i, object_id(e->customdata), object_id(e->special_table),
                e->mindist, e->maxdist, e->boundary, e->special, e->special_pattern,
                e->ch[0], e->ch[1], e->ch_mindist[0], e->ch_mindist[1], e->ch_maxdist[0], e->ch_maxdist[1]};
            for (size_t k = 0; k < sizeof(values)/sizeof(*values); k++) put(ef, values[k], 4);
            native_bytes(native_extensions, e, sizeof(*e));
        }
    }
    for (size_t i = 0; i < transition_count; i++) {
        const struct row_ref *row = &transition_rows[i];
        const struct cli_matcher *root = engine->root[row->target];
        put64(transition_addresses, (uint64_t)(uintptr_t)row->ptr);
        put(rf, row->target, 4);
        for (unsigned byte = 0; byte < 256; byte++) {
            uint32_t value = row->ptr[byte];
            if (value > root->ac_nodes + 1) abort();
            put(rf, value, 4);
        }
    }
    uint32_t node_base = 0, pattern_base = 0, link_base = 0, logical_base = 0;
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *root = engine->root[target]; if (!root) continue;
        uint32_t counts[] = {target, pattern_base, root->ac_patterns, link_base, root->ac_lists,
                            logical_base, root->ac_lsigs, node_base, root->ac_root ? root->ac_nodes + 1 : 0};
        for (size_t i = 0; i < sizeof(counts)/sizeof(*counts); i++) put(targets, counts[i], 4);
        if (root->trans_cnt >= NIL || root->trans_capacity >= NIL) abort();
        put(transition_cleanup, target, 4); put(transition_cleanup, (uint32_t)root->trans_cnt, 4);
        put(transition_cleanup, (uint32_t)root->trans_capacity, 4);
        for (size_t j = 0; j < root->trans_cnt; j++)
            put64(transition_cleanup, (uint64_t)(uintptr_t)root->trans_array[j]);
        for (uint32_t j = 0; j < root->ac_patterns; j++) {
            const struct cli_ac_patt *p = root->ac_pattable[j];
            native_bytes(native_patterns, p, sizeof(*p));
            put64(pattern_addresses, (uint64_t)(uintptr_t)p);
            uint32_t values[] = {object_id(p->pattern), object_id(p->prefix), object_id(p->ext), object_id(p->virname)};
            for (size_t k = 0; k < 4; k++) put(pf, values[k], 4);
        }
        for (uint32_t j = 0; j < root->ac_lsigs; j++) {
            const struct cli_ac_lsig *logic = root->ac_lsigtable[j];
            native_bytes(native_logical, logic, sizeof(*logic));
            put64(logical_addresses, (uint64_t)(uintptr_t)logic);
            const struct cli_lsig_tdb *d = &logic->tdb;
            uint32_t values[] = {object_id(logic->virname), object_id(logic->u.logic), object_id(d->val),
                object_id(d->range), object_id(d->str), object_id(d->macro_ptids), object_id(d->icongrp1),
                object_id(d->icongrp2), object_id(d->intermediates), d->subsigs,
                d->cnt[CLI_TDB_UINT], d->cnt[CLI_TDB_RANGE], d->cnt[CLI_TDB_STR]};
            for (size_t k = 0; k < sizeof(values)/sizeof(*values); k++) put(lf, values[k], 4);
            const uint32_t *coordinates[] = {d->target, d->engine, d->nos, d->ep, d->filesize, d->container, d->handlertype};
            for (size_t k = 0; k < 7; k++) coordinate_ref(lf, d, coordinates[k]);
        }
        put(sf, target, 4); put(sf, root->ac_lsigs, 4);
        if (root->ac_lsig_slots >= NIL) abort();
        put(sf, (uint32_t)root->ac_lsig_slots, 4);
        put(sf, root->ac_lsig_offsets ? root->ac_lsigs + 1 : 0, 4);
        if (root->ac_lsig_offsets)
            for (uint32_t j = 0; j <= root->ac_lsigs; j++) put(sf, root->ac_lsig_offsets[j], 4);
        if (root->ac_root) for (uint32_t local = 1; local <= root->ac_nodes + 1; local++) {
            const struct cli_ac_node *node = node_at(root, local);
            native_bytes(native_nodes, node, sizeof(*node));
            put64(node_addresses, (uint64_t)(uintptr_t)node);
            uint32_t values[] = {target, local, reference(links, link_count, node->list),
                                graph_node(root, node->fail, node_base), row_id(node->trans)};
            for (size_t k = 0; k < 5; k++) put(nf, values[k], 4);
        }
        for (uint32_t j = 0; j < root->ac_lists; j++) {
            native_bytes(native_links, root->ac_listtable[j], sizeof(*root->ac_listtable[j]));
            put64(link_addresses, (uint64_t)(uintptr_t)root->ac_listtable[j]);
        }
        pattern_base += root->ac_patterns; link_base += root->ac_lists;
        logical_base += root->ac_lsigs;
        if (root->ac_root) node_base += root->ac_nodes + 1;
    }
    close_checked(of); close_checked(pf); close_checked(ef); close_checked(lf);
    close_checked(nf); close_checked(rf); close_checked(sf); close_checked(targets);
    close_checked(native_patterns); close_checked(native_links); close_checked(native_nodes);
    close_checked(native_logical); close_checked(native_extensions);
    close_checked(pattern_addresses); close_checked(link_addresses); close_checked(node_addresses);
    close_checked(logical_addresses); close_checked(transition_addresses);
    close_checked(transition_cleanup);
    FILE *schema = output(graph_directory, "graph-schema.json");
    fprintf(schema, "{\n  \"schema\":1,\n  \"endianness\":\"little\",\n  \"null_id\":4294967295,\n"
        "  \"patterns\":%zu,\n  \"candidate_records\":%zu,\n  \"nodes\":%zu,\n  \"transition_rows\":%zu,\n"
        "  \"logical_records\":%zu,\n  \"objects\":%zu,\n  \"opaque_objects\":%llu,\n  \"raw_object_bytes\":%llu,\n"
        "  \"native_sizes\":{\"pointer\":%zu,\"pattern\":%zu,\"candidate\":%zu,\"node\":%zu,\"logical\":%zu,\"extension\":%zu},\n"
        "  \"files\":{\n"
        "    \"patterns.bin\":\"existing exact exporter: 74 bytes; 13 u32 + 10 u16 + depth/sigopts u8; pattern/prefix token counts retained\",\n"
        "    \"links.bin\":\"existing exact exporter: pattern,next,next_same u32 IDs; original ordered edges\",\n"
        "    \"objects.bin\":\"u32 count then kind_mask,extent,raw_bytes,name_value_id u32 + source_address u64 + raw byte payload; IDs and source pointers retain identity, text IDs are separate\",\n"
        "    \"pattern_objects.bin\":\"pattern,prefix,extension,name object IDs u32, in exact pattern row order\",\n"
        "    \"extensions.bin\":\"14 u32: object,customdata,special_table,mindist,maxdist,boundary,special,special_pattern,ch0,ch1,min0,min1,max0,max1\",\n"
        "    \"logical_objects.bin\":\"34 u32 per logical row: name/program/val/range/str/macro/icon1/icon2/intermediates object IDs; subsigs/cnt[3]; seven triples exactpointerID,baseobjectID,byteoffset\",\n"
        "    \"node_graph.bin\":\"5 u32: target,local_nodeID,listID,global_failure_nodeID,transition_rowID\",\n"
        "    \"transitions.bin\":\"257 u32: target then 256 exact target-local node IDs; zero means unset\",\n"
        "    \"transition_cleanup.bin\":\"per target: target,used_count,capacity u32 then used_count u64 source row addresses, original cleanup order; unused capacity bytes not read\",\n"
        "    \"targets.bin\":\"9 u32: target,patternbase/count,listbase/count,logicalbase/count,nodebase/count\",\n"
        "    \"logical_slots.bin\":\"per target: target,logical_count,slot_count,directory_count u32 then exact row-offset directory\"\n"
        "  },\n"
        "  \"native_files\":{\"native_patterns.bin\":\"sizeof(pattern) raw native bytes per pattern row\","
        "\"native_links.bin\":\"sizeof(candidate) raw native bytes per ordered candidate row\","
        "\"native_nodes.bin\":\"sizeof(node) raw native bytes per visible node (null slots excluded and charged separately)\","
        "\"native_logical.bin\":\"sizeof(logical) raw native bytes per logical row\","
        "\"native_extensions.bin\":\"sizeof(extension) raw native bytes, same order as extensions.bin\"},\n"
        "  \"address_files\":\"pattern_addresses.bin,link_addresses.bin,node_addresses.bin,logical_addresses.bin,transition_addresses.bin contain u64 source addresses in the matching table row order; diagnostic oracles, not free runtime directories\",\n"
        "  \"kind_bits\":{\"name\":1,\"token16\":2,\"extension\":4,\"uint_values\":8,\"range_values\":16,\"string_bytes\":32,\"macro_ids\":64,\"program\":128,\"icon\":256,\"scalar_coordinate\":512,\"opaque\":1024,\"special_table\":2048},\n"
        "  \"scope\":\"single compiled engine snapshot; exact AC/logical values and ordered references; object extent is a constructor-proven readable span, not allocator capacity (pattern tokens may point inside prefix storage); opaque special/custom/bytecode/intermediate payloads retained outside synthesis; hash keys and other parser state are not exported\",\n"
        "  \"raw_data_policy\":\"private diagnostic inputs contain threat names, signature bodies and native addresses; never publish raw values\"\n}\n",
        pattern_count, link_count, node_count, transition_count, logical_count, object_count,
        (unsigned long long)opaque_objects, (unsigned long long)raw_object_bytes,
        sizeof(void *), sizeof(struct cli_ac_patt), sizeof(struct cli_ac_list),
        sizeof(struct cli_ac_node), sizeof(struct cli_ac_lsig), sizeof(struct cli_ac_patt_ext));
    close_checked(schema);
    FILE *layout = output(graph_directory, "native-layout.json");
    fprintf(layout, "{\n  \"schema\":1,\n  \"native_pointer_bytes\":%zu,\n  \"pattern_size\":%zu,\n  \"pattern_fields\":{\n",
            sizeof(void *), sizeof(struct cli_ac_patt));
#define PF(member, type, count, final) native_field(layout, #member, offsetof(struct cli_ac_patt, member), sizeof(type), count, final)
    PF(pattern, void *, 1, 0); PF(prefix, void *, 1, 0); PF(ext, void *, 1, 0); PF(virname, void *, 1, 0);
    PF(sigid, uint32_t, 1, 0); PF(lsigid, uint32_t, 3, 0); PF(offdata, uint32_t, 4, 0);
    PF(offset_min, uint32_t, 1, 0); PF(offset_max, uint32_t, 1, 0);
    PF(length, uint16_t, 3, 0); PF(prefix_length, uint16_t, 3, 0);
    PF(parts, uint16_t, 1, 0); PF(partno, uint16_t, 1, 0); PF(rtype, uint16_t, 1, 0); PF(type, uint16_t, 1, 0);
    PF(depth, uint8_t, 1, 0); PF(sigopts, uint8_t, 1, 1);
#undef PF
    fprintf(layout, "  },\n  \"pattern_export_columns\":[\n"
        "    {\"column\":0,\"source\":\"generated concatenated token-sequence row identity\",\"native_member\":null,\"native_saving_eligible\":false},\n"
        "    {\"column\":1,\"source\":\"virname byte-value ID; actual pointer identity separately exported\",\"native_member\":\"virname\"},\n"
        "    {\"column\":2,\"source\":\"extension identity ID\",\"native_member\":\"ext\"},\n"
        "    {\"columns\":[3,4,5,6,7,8,9,10,11,12],\"source\":\"sigid,lsigid[0:3],offdata[0:4],offset_min,offset_max\"},\n"
        "    {\"offset_bytes\":52,\"source\":\"length[0:3],prefix_length[0:3],parts,partno,rtype,type as10u16; depth,sigopts as2u8\"}\n"
        "  ],\n  \"candidate_size\":%zu,\n  \"candidate_fields\":{\n", sizeof(struct cli_ac_list));
#define LF(member, final) native_field(layout, #member, offsetof(struct cli_ac_list, member), sizeof(void *), 1, final)
    LF(me, 0); LF(next, 0); LF(next_same, 1);
#undef LF
    fprintf(layout, "  },\n  \"node_size\":%zu,\n  \"node_fields\":{\n", sizeof(struct cli_ac_node));
#define NF(member, final) native_field(layout, #member, offsetof(struct cli_ac_node, member), sizeof(void *), 1, final)
    NF(list, 0); NF(trans, 0); NF(fail, 1);
#undef NF
    fprintf(layout, "  },\n  \"logical_size\":%zu,\n  \"logical_fields\":{\n", sizeof(struct cli_ac_lsig));
#define LG(member, width, final) native_field(layout, #member, offsetof(struct cli_ac_lsig, member), width, 1, final)
    LG(id, sizeof(uint32_t), 0); LG(bc_idx, sizeof(unsigned), 0); LG(type, sizeof(lsig_type_t), 0);
    LG(flag, sizeof(uint8_t), 0); LG(u, sizeof(void *), 0); LG(virname, sizeof(void *), 0);
    LG(tdb, sizeof(struct cli_lsig_tdb), 1);
#undef LG
    fprintf(layout, "  },\n  \"tdb_size\":%zu,\n  \"tdb_fields\":{\n", sizeof(struct cli_lsig_tdb));
#define TF(member, type, count, final) native_field(layout, #member, offsetof(struct cli_lsig_tdb, member), sizeof(type), count, final)
    TF(val, void *, 1, 0); TF(range, void *, 1, 0); TF(str, void *, 1, 0);
    TF(cnt, tdb_type_t, 3, 0); TF(subsigs, uint32_t, 1, 0);
    TF(target, void *, 1, 0); TF(engine, void *, 1, 0); TF(nos, void *, 1, 0);
    TF(ep, void *, 1, 0); TF(filesize, void *, 1, 0); TF(container, void *, 1, 0);
    TF(handlertype, void *, 1, 0); TF(intermediates, void *, 1, 0);
    TF(icongrp1, void *, 1, 0); TF(icongrp2, void *, 1, 0); TF(macro_ptids, void *, 1, 0);
#ifdef USE_MPOOL
    TF(mempool, void *, 1, 1);
#else
    TF(_padding_mempool, void *, 1, 1);
#endif
#undef TF
    fprintf(layout, "  },\n  \"extension_size\":%zu,\n  \"extension_fields\":{\n", sizeof(struct cli_ac_patt_ext));
#define EF(member, type, count, final) native_field(layout, #member, offsetof(struct cli_ac_patt_ext, member), sizeof(type), count, final)
    EF(customdata, void *, 1, 0); EF(special_table, void *, 1, 0);
    EF(mindist, uint32_t, 1, 0); EF(maxdist, uint32_t, 1, 0); EF(boundary, uint32_t, 1, 0);
    EF(special, uint16_t, 1, 0); EF(special_pattern, uint16_t, 1, 0);
    EF(ch, uint16_t, 2, 0); EF(ch_mindist, uint16_t, 2, 0); EF(ch_maxdist, uint16_t, 2, 1);
#undef EF
    fprintf(layout, "  },\n  \"targets\":[\n");
    int first = 1;
    for (unsigned target = 0; target < CLI_MTARGETS; target++) {
        struct cli_matcher *root = engine->root[target]; if (!root) continue;
        fprintf(layout, "%s    {\"target\":%u,\"patterns\":%u,\"candidate_records\":%u,\"logical_records\":%u,"
                "\"node_slots_including_null\":%llu,\"native_pattern_record_bytes\":%llu,\"native_pattern_directory_bytes\":%llu,"
                "\"native_candidate_record_bytes\":%llu,\"native_candidate_directory_bytes\":%llu,"
                "\"native_logical_record_bytes\":%llu,\"native_logical_directory_bytes\":%llu,"
                "\"native_node_arena_bytes\":%llu,\"native_transition_rows\":%llu,\"native_transition_bytes\":%llu,"
                "\"retained_transition_cleanup_capacity_bytes\":%llu,\"logical_slots\":%llu,\"logical_slot_directory_bytes\":%llu}",
                first ? "" : ",\n", target, root->ac_patterns, root->ac_lists, root->ac_lsigs,
                root->ac_flatnodes ? (unsigned long long)root->ac_nodes + 2 : root->ac_root ? 1 : 0,
                (unsigned long long)root->ac_patterns * sizeof(struct cli_ac_patt),
                (unsigned long long)root->ac_patterns * sizeof(void *),
                (unsigned long long)root->ac_lists * sizeof(struct cli_ac_list),
                (unsigned long long)root->ac_lists * sizeof(void *),
                (unsigned long long)root->ac_lsigs * sizeof(struct cli_ac_lsig),
                (unsigned long long)root->ac_lsigs * sizeof(void *),
                root->ac_flatnodes ? ((unsigned long long)root->ac_nodes + 2) * sizeof(struct cli_ac_node) : root->ac_root ? sizeof(struct cli_ac_node) : 0,
                root->ac_root ? (unsigned long long)root->trans_cnt + 1 : 0,
                root->ac_root ? ((unsigned long long)root->trans_cnt + 1) * 256 * sizeof(cli_ac_transition_t) : 0,
                (unsigned long long)root->trans_capacity * sizeof(void *),
                (unsigned long long)root->ac_lsig_slots,
                root->ac_lsig_offsets ? ((unsigned long long)root->ac_lsigs + 1) * 4 : 0);
        first = 0;
    }
    fprintf(layout, "\n  ],\n  \"limits\":[\"Counts measure native payload/directory extents, not allocator RSS.\","
            "\"Transition rows are retained; builder node arrays are discarded after frozen-order packing.\","
            "\"Opaque special/custom/bytecode/intermediate data stays outside synthesis and must remain retained.\","
            "\"Generated export IDs and other absent native columns cannot be counted as removed native fields.\"]\n}\n");
    close_checked(layout);
    /* This is the unchanged read-only census on the SAME engine snapshot.
       In particular its hash payload/directory capacities remain outside the
       synthesized AC metadata and cannot disappear from the resident ledger. */
    graph_ledger = output(graph_directory, "resident-ledger.jsonl");
    census(engine);
    close_checked(graph_ledger);
    graph_ledger = NULL;
    printf("{\"kind\":\"system_graph\",\"patterns\":%zu,\"candidate_records\":%zu,\"nodes\":%zu,\"transition_rows\":%zu,\"logical_records\":%zu,\"objects\":%zu,\"opaque_objects\":%llu,\"same_engine_instance\":true,\"sigload_calls\":%llu,\"skipped_events\":%llu}\n",
           pattern_count, link_count, node_count, transition_count, logical_count, object_count,
           (unsigned long long)opaque_objects, graph_load_events, graph_skip_events);
    free(patterns); free(links); free(names); free(objects); free(transition_rows);
    cl_engine_free(engine);
}

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 5) return 1;
    uint32_t byte_order = 1;
    if (*(unsigned char *)&byte_order != 1) return 2;
    struct stat info;
    if (lstat(argv[3], &info) || !S_ISDIR(info.st_mode) || (info.st_mode & 077)) {
        fprintf(stderr, "graph export requires an existing private (0700) directory\n");
        return 2;
    }
    DIR *dir = opendir(argv[3]);
    if (!dir) return 2;
    struct dirent *entry;
    while ((entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            closedir(dir); fprintf(stderr, "graph export directory must be empty\n"); return 2;
        }
    if (closedir(dir)) return 2;
    graph_directory = argv[3];
    graph_skips = argc == 5 ? argv[4] : NULL;
    return exact_tables_main(4, argv);
}
