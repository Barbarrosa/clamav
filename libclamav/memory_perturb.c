/* SPDX-License-Identifier: GPL-2.0-only
 * Cumulative allocation sensitivity diagnostics, never live-memory accounting.
 * Only compiled into explicitly enabled research builds.
 */
#include "memory_perturb.h"
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *const groups[] = {
    "names", "patterns", "candidates", "tokens", "nodes", "transitions",
    "logical", "scanstate", "build_scratch", "hashes", "pool_other", "heap_other"};
#define NGROUPS (sizeof(groups) / sizeof(groups[0]))
struct counter {
    uint64_t calls, requested_bytes, successful_calls, failed_calls;
    uint64_t added_bytes, injected_calls, skipped_cap_calls, overflow_failures;
};
static struct counter counters[NGROUPS];
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static size_t pad_bytes, max_added_bytes = 512 * 1024 * 1024, reserved_added;
static int selected = -1, config_valid = 1, all_groups;
static const char *log_path;

static uint64_t sat_add(uint64_t a, uint64_t b)
{
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static size_t group_index(const char *group)
{
    size_t i;
    for (i = 0; i < NGROUPS; i++)
        if (group && !strcmp(group, groups[i])) return i;
    return NGROUPS - 1;
}

static int parse_size(const char *text, size_t *out)
{
    char *end;
    uintmax_t value;
    const char *p;
    if (!text || !*text) return 0;
    for (p = text; *p; p++) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    value = strtoumax(text, &end, 10);
    if (errno || *end || value > SIZE_MAX) return 0;
    *out = (size_t)value;
    return 1;
}

static void configure(void)
{
    const char *group = getenv("CM_PAD_GROUP"), *bytes = getenv("CM_PAD_BYTES");
    const char *cap = getenv("CM_PAD_MAX_BYTES");
    size_t i;
    log_path = getenv("CM_PAD_LOG");
    if (bytes && (!parse_size(bytes, &pad_bytes) || pad_bytes % 8 || pad_bytes > 1048576)) config_valid = 0;
    if (cap && !parse_size(cap, &max_added_bytes)) config_valid = 0;
    if (group && !strcmp(group, "all")) all_groups = 1;
    else if (group && *group) {
        for (i = 0; i < NGROUPS; i++) if (!strcmp(group, groups[i])) selected = (int)i;
        if (selected < 0) config_valid = 0;
    }
    if (pad_bytes && !group) config_valid = 0;
    if (!config_valid) pad_bytes = 0;
}

int cm_perturb_prepare(const char *group, size_t requested, size_t *physical, size_t *added)
{
    size_t i = group_index(group);
    struct counter *c = &counters[i];
    pthread_once(&once, configure);
    *physical = requested;
    *added = 0;
    pthread_mutex_lock(&lock);
    c->calls = sat_add(c->calls, 1);
    c->requested_bytes = sat_add(c->requested_bytes, requested);
    if (requested && pad_bytes && (all_groups || selected == (int)i)) {
        if (requested > SIZE_MAX - pad_bytes) {
            c->overflow_failures = sat_add(c->overflow_failures, 1);
            c->failed_calls = sat_add(c->failed_calls, 1);
            pthread_mutex_unlock(&lock);
            errno = ENOMEM;
            return 0;
        }
        if (pad_bytes <= max_added_bytes && reserved_added <= max_added_bytes - pad_bytes) {
            reserved_added += pad_bytes;
            *added = pad_bytes;
            *physical += pad_bytes;
        } else {
            c->skipped_cap_calls = sat_add(c->skipped_cap_calls, 1);
            c->failed_calls = sat_add(c->failed_calls, 1);
            pthread_mutex_unlock(&lock);
            errno = ENOMEM;
            return 0;
        }
    }
    pthread_mutex_unlock(&lock);
    return 1;
}

void cm_perturb_reject_overflow(const char *group)
{
    struct counter *c = &counters[group_index(group)];
    pthread_once(&once, configure);
    pthread_mutex_lock(&lock);
    c->calls = sat_add(c->calls, 1);
    c->failed_calls = sat_add(c->failed_calls, 1);
    c->overflow_failures = sat_add(c->overflow_failures, 1);
    pthread_mutex_unlock(&lock);
    errno = ENOMEM;
}

void cm_perturb_finish(const char *group, void *ptr, size_t requested, size_t added)
{
    struct counter *c = &counters[group_index(group)];
    /* Volatile writes make the injected tail physically resident, even when
     * the caller never reads it. No byte of the requested payload is touched. */
    if (ptr && added) {
        volatile unsigned char *tail = (volatile unsigned char *)ptr + requested;
        size_t i;
        for (i = 0; i < added; i++) tail[i] = 0xa5;
    }
    pthread_mutex_lock(&lock);
    if (ptr) {
        c->successful_calls = sat_add(c->successful_calls, 1);
        c->added_bytes = sat_add(c->added_bytes, added);
        if (added) c->injected_calls = sat_add(c->injected_calls, 1);
    } else {
        c->failed_calls = sat_add(c->failed_calls, 1);
        reserved_added -= added;
    }
    pthread_mutex_unlock(&lock);
}

void *cm_perturb_malloc(const char *group, size_t size)
{
    size_t physical, added;
    void *ptr;
    if (!cm_perturb_prepare(group, size, &physical, &added)) return NULL;
    ptr = malloc(physical);
    cm_perturb_finish(group, ptr, size, added);
    return ptr;
}

void *cm_perturb_calloc(const char *group, size_t count, size_t size)
{
    size_t requested, physical, added;
    void *ptr;
    if (size && count > SIZE_MAX / size) { cm_perturb_reject_overflow(group); return NULL; }
    requested = count * size;
    if (!cm_perturb_prepare(group, requested, &physical, &added)) return NULL;
    ptr = added ? calloc(1, physical) : calloc(count, size);
    cm_perturb_finish(group, ptr, requested, added);
    return ptr;
}

void *cm_perturb_realloc(const char *group, void *ptr, size_t size)
{
    size_t physical, added;
    void *result;
    if (!cm_perturb_prepare(group, size, &physical, &added)) return NULL;
    result = realloc(ptr, physical);
    cm_perturb_finish(group, result, size, added);
    return result;
}

static void json_string(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    fputc('"', out);
    for (; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

int cm_perturb_pool_stats(const struct cl_engine *engine, size_t *carved, size_t *mapped)
{
#ifdef USE_MPOOL
    return mpool_getstats(engine, carved, mapped);
#else
    (void)engine;
    (void)carved;
    (void)mapped;
    return -1;
#endif
}

void cm_perturb_snapshot(const char *label)
{
    FILE *out;
    size_t i;
    pthread_once(&once, configure);
    if (!log_path || !*log_path) return;
    pthread_mutex_lock(&lock);
    out = fopen(log_path, "a");
    if (!out) { pthread_mutex_unlock(&lock); return; }
    fprintf(out, "{\"kind\":\"memory_perturb\",\"phase\":"); json_string(out, label);
    fprintf(out, ",\"instrumentation_enabled\":true,\"configuration_valid\":%s,\"configured_group\":", config_valid ? "true" : "false");
    json_string(out, all_groups ? "all" : selected < 0 ? "none" : groups[selected]);
    fprintf(out, ",\"pad_bytes\":%zu,\"max_added_bytes\":%zu,\"scope\":\"cumulative allocation requests, not live memory\",\"groups\":{", pad_bytes, max_added_bytes);
    for (i = 0; i < NGROUPS; i++) {
        struct counter *c = &counters[i];
        fprintf(out, "%s\"%s\":{\"calls\":%" PRIu64 ",\"requested_bytes\":%" PRIu64 ",\"successful_calls\":%" PRIu64 ",\"failed_calls\":%" PRIu64 ",\"added_bytes\":%" PRIu64 ",\"injected_calls\":%" PRIu64 ",\"skipped_cap_calls\":%" PRIu64 ",\"overflow_failures\":%" PRIu64 "}", i ? "," : "", groups[i], c->calls, c->requested_bytes, c->successful_calls, c->failed_calls, c->added_bytes, c->injected_calls, c->skipped_cap_calls, c->overflow_failures);
    }
    fputs("}}\n", out);
    fclose(out);
    pthread_mutex_unlock(&lock);
}
