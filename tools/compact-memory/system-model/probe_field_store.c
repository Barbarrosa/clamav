/* SPDX-License-Identifier: GPL-2.0-only
 * Independent native field-provider replay and CPU microbenchmark.
 * Source pointer words remain private identity values. This does not measure
 * address resolution, scanner latency, physical page reclamation or engine RSS.
 * CLI: IMAGE NATIVE SPEC REPEATS
 * SPEC: rows stride fields, then offset width_bytes for each image field.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_FIELDS 512
#define NIL UINT32_MAX
#define QUERIES 100000
enum { STORE_XOR, CONSTANT, ROW_AFFINE, ALIAS_XOR, ALIAS_ADD, STORE_BASE_NULL, SPARSE };
struct file { unsigned char *data; size_t size; };
struct descriptor {
    unsigned op, width, bits;
    uint32_t parent;
    uint64_t arg, offset, count;
    unsigned depth;
};
struct store {
    struct file image;
    uint32_t rows, fields;
    struct descriptor descriptor[MAX_FIELDS];
};
struct member { size_t offset; unsigned width; };
static void fail(const char *message) {
    fprintf(stderr, "field-provider probe: %s\n", message);
    exit(2);
}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t u64(const unsigned char *p) {
    return (uint64_t)u32(p) | ((uint64_t)u32(p + 4) << 32);
}
static uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1; }
static size_t align8(size_t value) { return (value + 7) & ~(size_t)7; }
static size_t packed_size(uint64_t count, unsigned width) {
    if (!width) return 0;
    if (count > (SIZE_MAX - 127) / width) fail("packed size overflow");
    return align8((size_t)((count * width + 7) / 8)) + 8;
}
static size_t bitmap_size(uint32_t count) { return align8(((size_t)count + 7) / 8) + 8; }
static size_t rank_size(uint32_t count) { return align8((((size_t)count + 511) / 512 + 1) * 4); }
static struct file map_file(const char *path) {
    struct file result = {0};
    struct stat info;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 0 ||
        (uint64_t)info.st_size > UINT64_C(4) * 1024 * 1024 * 1024) fail("invalid input file");
    result.size = (size_t)info.st_size;
    if (result.size) {
        result.data = mmap(NULL, result.size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (result.data == MAP_FAILED) fail("mapping failed");
    }
    if (close(fd)) fail("close failed");
    return result;
}
static unsigned reads(uint32_t rows, unsigned width) {
    unsigned result = 0;
    uint32_t count = rows < 64 ? rows : 64;
    for (uint32_t i = 0; i < count; i++) {
        unsigned value = 1 + (((uint64_t)i * width) % 64 + width > 64);
        if (value > result) result = value;
    }
    return result;
}
static unsigned depth(struct store *s, uint32_t field, unsigned char *state) {
    struct descriptor *d = &s->descriptor[field];
    if (state[field] == 1) fail("cyclic field program");
    if (state[field] == 2) return d->depth;
    state[field] = 1;
    unsigned result = 0;
    switch (d->op) {
        case CONSTANT: break;
        case ROW_AFFINE: result = 1 + (d->count != 0 && d->count != 1) + (d->arg != 0); break;
        case STORE_XOR: result = reads(s->rows, d->width) + (d->arg != 0); break;
        case STORE_BASE_NULL: result = reads(s->rows, d->width) + 2; break;
        case ALIAS_XOR:
        case ALIAS_ADD: result = depth(s, d->parent, state) + 1 + (d->arg != 0); break;
        case SPARSE: result = depth(s, d->parent, state) + 13; break;
        default: fail("unknown program");
    }
    if (result > 64) fail("field work exceeds experiment limit");
    state[field] = 2;
    d->depth = result;
    return result;
}
static uint64_t packed(const struct store *s, size_t offset, unsigned width, uint64_t row) {
    if (!width) return 0;
    uint64_t bit = row * width;
    size_t at = offset + (size_t)(bit / 64) * 8;
    unsigned shift = (unsigned)(bit % 64);
    uint64_t value = u64(s->image.data + at) >> shift;
    if (shift + width > 64) value |= u64(s->image.data + at + 8) << (64 - shift);
    return value & mask(width);
}
static struct store load_store(const char *path) {
    struct store s = {0};
    s.image = map_file(path);
    if (s.image.size < 16 || memcmp(s.image.data, "FIELDS1\0", 8)) fail("invalid field header");
    s.rows = u32(s.image.data + 8); s.fields = u32(s.image.data + 12);
    if (s.fields > MAX_FIELDS || 16 + (size_t)s.fields * 32 > s.image.size) fail("invalid field count");
    size_t position = 16 + (size_t)s.fields * 32;
    for (uint32_t i = 0; i < s.fields; i++) {
        const unsigned char *p = s.image.data + 16 + (size_t)i * 32;
        struct descriptor *d = &s.descriptor[i];
        d->op = p[0]; d->width = p[1]; d->bits = p[2]; d->parent = u32(p + 4);
        d->arg = u64(p + 8); d->offset = u64(p + 16); d->count = u64(p + 24);
        if (d->op > SPARSE || p[3] || !d->bits || d->bits > 64 || d->width > d->bits)
            fail("invalid field descriptor");
        int dependent = d->op == ALIAS_XOR || d->op == ALIAS_ADD || d->op == SPARSE;
        if (dependent ? d->parent >= s.fields || d->parent == i : d->parent != NIL)
            fail("invalid field dependency");
        size_t size = 0;
        if (d->op == STORE_XOR || d->op == STORE_BASE_NULL) {
            if (!d->width) fail("stored field width is zero");
            size = packed_size(s.rows, d->width);
        } else if (d->op == SPARSE) {
            if (d->count > s.rows) fail("sparse count exceeds row count");
            size = bitmap_size(s.rows) + rank_size(s.rows) + packed_size(d->count, d->width);
        } else if (d->width || d->offset) fail("nonstored field has payload");
        if (size) {
            if (d->offset != position || size > s.image.size - position) fail("field payload bounds differ");
            position += size;
        }
    }
    if (position != s.image.size) fail("trailing field payload");
    unsigned char state[MAX_FIELDS] = {0};
    for (uint32_t i = 0; i < s.fields; i++) (void)depth(&s, i, state);
    for (uint32_t i = 0; i < s.fields; i++) {
        const struct descriptor *d = &s.descriptor[i];
        if (d->op != SPARSE) continue;
        size_t rank_at = (size_t)d->offset + bitmap_size(s.rows);
        uint32_t running = 0;
        uint64_t blocks = ((uint64_t)s.rows + 511) / 512;
        for (uint64_t block = 0; block < blocks; block++) {
            if (u32(s.image.data + rank_at + 4 * (size_t)block) != running) fail("invalid sparse rank");
            uint64_t first = block * 512, remaining = s.rows - first;
            if (remaining > 512) remaining = 512;
            for (uint64_t at = 0; at < remaining; at += 64) {
                unsigned n = (unsigned)(remaining - at); if (n > 64) n = 64;
                uint64_t word = u64(s.image.data + d->offset + (size_t)((first + at) / 64) * 8);
                running += (uint32_t)__builtin_popcountll(word & mask(n));
            }
        }
        if (running != d->count || u32(s.image.data + rank_at + 4 * (size_t)blocks) != running)
            fail("sparse exception count differs");
    }
    return s;
}
static uint64_t get(const struct store *s, uint32_t field, uint32_t row) {
    const struct descriptor *d = &s->descriptor[field];
    uint64_t value = 0;
    switch (d->op) {
        case CONSTANT: value = d->arg; break;
        case ROW_AFFINE: value = (uint64_t)row * d->count + d->arg; break;
        case STORE_XOR: value = packed(s, (size_t)d->offset, d->width, row) ^ d->arg; break;
        case STORE_BASE_NULL:
            value = packed(s, (size_t)d->offset, d->width, row);
            if (value) value += d->arg - 1;
            break;
        case ALIAS_XOR: value = get(s, d->parent, row) ^ d->arg; break;
        case ALIAS_ADD: value = get(s, d->parent, row) + d->arg; break;
        case SPARSE: {
            uint64_t word = u64(s->image.data + d->offset + (size_t)(row / 64) * 8);
            if (!((word >> (row % 64)) & 1)) { value = get(s, d->parent, row); break; }
            uint32_t block = row / 512;
            size_t rank_at = (size_t)d->offset + bitmap_size(s->rows);
            uint32_t rank = u32(s->image.data + rank_at + (size_t)block * 4);
            for (uint32_t i = block * 8; i < row / 64; i++)
                rank += (uint32_t)__builtin_popcountll(u64(s->image.data + d->offset + (size_t)i * 8));
            rank += (uint32_t)__builtin_popcountll(word & (row % 64 ? mask(row % 64) : 0));
            size_t payload = rank_at + rank_size(s->rows);
            value = packed(s, payload, d->width, rank) ^ d->arg;
            break;
        }
        default: fail("invalid GET program");
    }
    return value & mask(d->bits);
}
static uint64_t native_get(const struct file *native, const struct member *member, size_t stride,
                           uint32_t field, uint32_t row) {
    uint64_t value = 0;
    memcpy(&value, native->data + (size_t)row * stride + member[field].offset, member[field].width);
    return value;
}
static double seconds(clockid_t clock) {
    struct timespec time;
    if (clock_gettime(clock, &time)) fail("clock read failed");
    return (double)time.tv_sec + (double)time.tv_nsec * 1e-9;
}
static uint64_t random_u64(uint64_t *state) {
    *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17; return *state;
}
static volatile uint64_t sink;
int main(int argc, char **argv) {
    if (argc != 5) { fprintf(stderr, "usage: %s IMAGE NATIVE SPEC REPEATS\n", argv[0]); return 2; }
    uint64_t order_check = 1;
    if (*(const unsigned char *)&order_check != 1) fail("little-endian native input required");
    char *end;
    errno = 0;
    unsigned long repeats = strtoul(argv[4], &end, 10);
    if (errno || *end || !repeats || repeats > 100) fail("invalid repeat count");
    struct store store = load_store(argv[1]);
    struct file native = map_file(argv[2]);
    FILE *spec = fopen(argv[3], "r");
    unsigned long long spec_rows, spec_stride, spec_fields;
    if (!spec || fscanf(spec, "%llu %llu %llu", &spec_rows, &spec_stride, &spec_fields) != 3 ||
        spec_rows != store.rows || spec_fields != store.fields || !spec_stride || spec_stride > 4096 ||
        (store.rows && spec_stride > SIZE_MAX / store.rows) ||
        native.size != (size_t)spec_stride * store.rows) fail("invalid native schema");
    size_t stride = (size_t)spec_stride;
    struct member members[MAX_FIELDS];
    unsigned char occupied[4096] = {0};
    for (uint32_t i = 0; i < store.fields; i++) {
        unsigned long long offset, width;
        if (fscanf(spec, "%llu %llu", &offset, &width) != 2 ||
            (width != 1 && width != 2 && width != 4 && width != 8) ||
            offset > stride || width > stride - offset || store.descriptor[i].bits != width * 8)
            fail("invalid native member");
        for (size_t j = (size_t)offset; j < offset + width; j++) {
            if (occupied[j]) fail("overlapping native members");
            occupied[j] = 1;
        }
        members[i].offset = (size_t)offset; members[i].width = (unsigned)width;
    }
    char extra;
    if (fscanf(spec, " %c", &extra) != EOF || fclose(spec)) fail("trailing native schema");
    uint64_t verified = 0, verification_checksum = UINT64_C(14695981039346656037);
    for (uint32_t field = 0; field < store.fields; field++)
        for (uint32_t row = 0; row < store.rows; row++) {
            uint64_t value = get(&store, field, row);
            if (value != native_get(&native, members, stride, field, row)) fail("source field differs");
            verification_checksum = (verification_checksum ^ value) * UINT64_C(1099511628211);
            verified++;
        }
    uint32_t *rows = malloc(QUERIES * sizeof(*rows)), *fields = malloc(QUERIES * sizeof(*fields));
    if (!rows || !fields) fail("query allocation failed");
    printf("{\"scope\":\"native field-provider microbenchmark; identity resolution and scanner work excluded\","
           "\"native_baseline\":\"schema-driven memcpy of a captured native member, not specialized scanner code\","
           "\"timing_state\":\"after complete value verification; no cold-cache claim\","
           "\"rows\":%" PRIu32 ",\"fields\":%" PRIu32 ",\"image_bytes\":%zu,\"native_bytes\":%zu,"
           "\"all_values_verified\":%" PRIu64 ",\"verification_checksum\":\"%016" PRIx64 "\",\"trials\":[",
           store.rows, store.fields, store.image.size, native.size, verified, verification_checksum);
    unsigned emitted = 0;
    for (unsigned trace = 0; trace < 2 && store.rows && store.fields; trace++) {
        uint64_t state = 378;
        for (uint32_t i = 0; i < QUERIES; i++) {
            fields[i] = trace ? (uint32_t)(random_u64(&state) % store.fields) : i % store.fields;
            rows[i] = trace ? (uint32_t)(random_u64(&state) % store.rows) : i % store.rows;
        }
        for (unsigned long trial = 0; trial < repeats; trial++) {
            double cpu[2], wall[2]; uint64_t sums[2];
            for (unsigned position = 0; position < 2; position++) {
                unsigned mode = position ^ (trial & 1);
                uint64_t sum = UINT64_C(14695981039346656037);
                double w = seconds(CLOCK_MONOTONIC), c = seconds(CLOCK_PROCESS_CPUTIME_ID);
                for (uint32_t i = 0; i < QUERIES; i++) {
                    uint64_t value = mode ? get(&store, fields[i], rows[i]) :
                        native_get(&native, members, stride, fields[i], rows[i]);
                    sum = (sum ^ value) * UINT64_C(1099511628211);
                }
                cpu[mode] = seconds(CLOCK_PROCESS_CPUTIME_ID) - c;
                wall[mode] = seconds(CLOCK_MONOTONIC) - w;
                sums[mode] = sum; sink = sum;
            }
            if (sums[0] != sums[1]) fail("query trace checksum differs");
            printf("%s{\"trace\":\"%s\",\"trial\":%lu,\"queries\":%u,\"native_cpu_seconds\":%.9f,"
                   "\"field_cpu_seconds\":%.9f,\"native_wall_seconds\":%.9f,\"field_wall_seconds\":%.9f,"
                   "\"checksum\":\"%016" PRIx64 "\"}", emitted++ ? "," : "", trace ? "random" : "sequential",
                   trial, QUERIES, cpu[0], cpu[1], wall[0], wall[1], sums[0]);
        }
    }
    puts("]}");
    free(rows); free(fields);
    if (store.image.size) munmap(store.image.data, store.image.size);
    if (native.size) munmap(native.data, native.size);
    return 0;
}
