/* SPDX-License-Identifier: GPL-2.0-only
 * Standalone joint-dictionary decoder experiment; never linked into ClamAV.
 * RSS below is this diagnostic process, not scanner or service memory.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct image {
    unsigned char *bytes;
    size_t size;
    uint32_t rows, dictionaries;
    const unsigned char *dictionary_offsets, *row_offsets, *lengths, *flags;
    const unsigned char *dictionary_data, *row_data;
    size_t dictionary_bytes, row_bytes, maximum_length;
    unsigned char *scratch;
};
static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static void fatal(const char *message)
{
    fprintf(stderr, "joint-dictionary probe: %s\n", message);
    exit(2);
}
static double clock_seconds(clockid_t clock_id)
{
    struct timespec t;
    if (clock_gettime(clock_id, &t)) fatal("clock failed");
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}
static long rss_kib(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long value = -1;
    if (!f) return -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "VmRSS: %ld kB", &value) == 1) break;
    fclose(f);
    return value;
}
static long peak_kib(void)
{
    struct rusage value;
    if (getrusage(RUSAGE_SELF, &value)) fatal("rusage failed");
    return value.ru_maxrss;
}
static uint64_t hash_byte(uint64_t value, unsigned char byte)
{
    return (value ^ byte) * UINT64_C(1099511628211);
}
static uint64_t hash_row(uint64_t value, const unsigned char *bytes, size_t size, unsigned wide)
{
    for (unsigned i = 0; i < 8; i++) value = hash_byte(value, (unsigned char)((uint64_t)size >> (8 * i)));
    value = hash_byte(value, (unsigned char)wide);
    for (size_t i = 0; i < size; i++) value = hash_byte(value, bytes[i]);
    return value;
}
static uint64_t random_u64(uint64_t *seed)
{
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    return *seed;
}
static unsigned char *read_image(const char *path, size_t *size)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 24 ||
        (uintmax_t)st.st_size > SIZE_MAX || st.st_size > 16 * 1024 * 1024)
        fatal("invalid image file or 16 MiB experiment limit exceeded");
    *size = (size_t)st.st_size;
    unsigned char *data = malloc(*size);
    if (!data) fatal("image allocation failed");
    size_t done = 0;
    while (done < *size) {
        ssize_t got = read(fd, data + done, *size - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) fatal("truncated image read");
        done += (size_t)got;
    }
    if (close(fd)) fatal("image close failed");
    return data;
}
static struct image load(const char *path, uint64_t bound)
{
    struct image image = {0};
    image.bytes = read_image(path, &image.size);
    if (memcmp(image.bytes, "JTDICT1\0", 8) || u32(image.bytes + 20)) fatal("invalid header");
    image.rows = u32(image.bytes + 8);
    image.dictionaries = u32(image.bytes + 12);
    uint32_t declared_maximum = u32(image.bytes + 16);
    if (image.rows > 256 || declared_maximum > 4096) fatal("experiment resource limit exceeded");
    if (image.dictionaries > 65280) fatal("dictionary code space exceeded");
    size_t pos = 24;
    uint64_t directory_size = ((uint64_t)image.dictionaries + 1) * 4;
    if (directory_size > image.size - pos) fatal("truncated dictionary directory");
    image.dictionary_offsets = image.bytes + pos;
    pos += (size_t)directory_size;
    if (u32(image.dictionary_offsets)) fatal("invalid initial dictionary offset");
    for (uint32_t i = 0; i < image.dictionaries; i++)
        if (u32(image.dictionary_offsets + 4 * (size_t)i) >= u32(image.dictionary_offsets + 4 * ((size_t)i + 1)))
            fatal("invalid dictionary offsets");
    image.dictionary_bytes = u32(image.dictionary_offsets + 4 * (size_t)image.dictionaries);
    if (image.dictionary_bytes > image.size - pos) fatal("truncated dictionary payload");
    image.dictionary_data = image.bytes + pos;
    pos += image.dictionary_bytes;
    directory_size = ((uint64_t)image.rows + 1) * 4;
    if (directory_size > image.size - pos) fatal("truncated row directory");
    image.row_offsets = image.bytes + pos;
    pos += (size_t)directory_size;
    if (u32(image.row_offsets)) fatal("invalid initial row offset");
    for (uint32_t i = 0; i < image.rows; i++)
        if (u32(image.row_offsets + 4 * (size_t)i) > u32(image.row_offsets + 4 * ((size_t)i + 1)))
            fatal("invalid row offsets");
    directory_size = (uint64_t)image.rows * 4;
    if (directory_size > image.size - pos) fatal("truncated decoded lengths");
    image.lengths = image.bytes + pos;
    pos += (size_t)directory_size;
    if (image.rows > image.size - pos) fatal("truncated row flags");
    image.flags = image.bytes + pos;
    pos += image.rows;
    image.row_bytes = u32(image.row_offsets + 4 * (size_t)image.rows);
    if (image.row_bytes != image.size - pos) fatal("truncated or trailing row payload");
    image.row_data = image.bytes + pos;
    for (uint32_t i = 0; i < image.rows; i++) {
        uint32_t length = u32(image.lengths + 4 * (size_t)i);
        if ((image.flags[i] & ~3U) || ((image.flags[i] & 2) && (length & 1)))
            fatal("invalid row flags or wide-token size");
        if (length > image.maximum_length) image.maximum_length = length;
    }
    if (image.maximum_length != declared_maximum) fatal("invalid maximum decoded length");
    /* Validate expansion before allocating output scratch. No malformed declared
       length can force a large output buffer before its code stream is checked. */
    for (uint32_t row = 0; row < image.rows; row++) {
        size_t start = u32(image.row_offsets + 4 * (size_t)row);
        size_t stop = u32(image.row_offsets + 4 * ((size_t)row + 1));
        size_t expected = u32(image.lengths + 4 * (size_t)row);
        uint64_t work = expected;
        if (image.flags[row] & 1) {
            if (stop - start != expected) fatal("raw row length mismatch");
        } else {
            if ((stop - start) & 1) fatal("odd encoded row length");
            work += (stop - start) / 2;
            uint64_t expanded = 0;
            for (size_t at = start; at < stop; at += 2) {
                uint16_t code = u16(image.row_data + at);
                if (code < 256) expanded++;
                else {
                    uint32_t entry = code - 256;
                    if (entry >= image.dictionaries) fatal("invalid dictionary reference");
                    expanded += u32(image.dictionary_offsets + 4 * ((size_t)entry + 1)) -
                                u32(image.dictionary_offsets + 4 * (size_t)entry);
                }
                if (expanded > expected) fatal("expansion exceeds decoded size");
            }
            if (expanded != expected) fatal("decoded length mismatch");
        }
        if (bound != UINT64_MAX && work > bound) fatal("decode work bound exceeded");
    }
    image.scratch = malloc(image.maximum_length ? image.maximum_length : 1);
    if (!image.scratch) fatal("scratch allocation failed");
    return image;
}

static const unsigned char *decode(struct image *image, uint32_t row, uint64_t bound)
{
    if (row >= image->rows) fatal("invalid row index");
    uint32_t start = u32(image->row_offsets + 4 * (size_t)row);
    uint32_t end = u32(image->row_offsets + 4 * ((size_t)row + 1));
    uint32_t length = u32(image->lengths + 4 * (size_t)row);
    unsigned flags = image->flags[row];
    const unsigned char *input = image->row_data + start;
    if (flags & 1) {
        if ((size_t)(end - start) != length || (bound != UINT64_MAX && length > bound))
            fatal("invalid raw row or decode bound");
        return input;
    }
    if ((end - start) & 1) fatal("odd encoded row length");
    if (bound != UINT64_MAX && (uint64_t)length + (end - start) / 2 > bound)
        fatal("decode work bound exceeded");
    size_t out = 0;
    for (size_t at = 0; at < end - start; at += 2) {
        uint16_t code = u16(input + at);
        if (code < 256) {
            if (out >= length) fatal("literal expansion overflow");
            image->scratch[out++] = (unsigned char)code;
        } else {
            uint32_t entry = code - 256;
            if (entry >= image->dictionaries) fatal("invalid dictionary reference");
            uint32_t begin = u32(image->dictionary_offsets + 4 * (size_t)entry);
            uint32_t stop = u32(image->dictionary_offsets + 4 * ((size_t)entry + 1));
            size_t count = stop - begin;
            if (out > length || count > length - out) fatal("dictionary expansion overflow");
            memcpy(image->scratch + out, image->dictionary_data + begin, count);
            out += count;
        }
    }
    if (out != length) fatal("decoded length mismatch");
    return image->scratch;
}
static void release(struct image *image)
{
    free(image->scratch);
    free(image->bytes);
    memset(image, 0, sizeof(*image));
}
int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s IMAGE REPEATS [MAX_DECODE_STEPS]\n", argv[0]);
        return 2;
    }
    char *end;
    errno = 0;
    unsigned long repeats = strtoul(argv[2], &end, 10);
    if (errno || *end || !repeats || repeats > 1000000) fatal("invalid repeats");
    uint64_t bound = UINT64_MAX;
    if (argc == 4) {
        errno = 0;
        bound = strtoull(argv[3], &end, 10);
        if (errno || *end || argv[3][0] == '-') fatal("invalid decode bound");
    }
    long baseline = rss_kib();
    struct image image = load(argv[1], bound);
    long loaded = rss_kib();
    uint64_t digest = UINT64_C(14695981039346656037);
    for (uint32_t row = 0; row < image.rows; row++) {
        const unsigned char *bytes = decode(&image, row, bound);
        digest = hash_row(digest, bytes, u32(image.lengths + 4 * (size_t)row), (image.flags[row] >> 1) & 1);
    }
    long hydrated = rss_kib();
    printf("{\"kind\":\"joint_dictionary_probe\",\"rows\":%" PRIu32 ",\"dictionary_entries\":%" PRIu32 ",\"image_bytes\":%zu,\"scratch_bytes\":%zu,\"decoded_cache_bytes\":0,\"rss_before_kib\":%ld,\"rss_loaded_no_decodes_kib\":%ld,\"rss_after_all_rows_kib\":%ld,\"decoded_checksum\":\"%016" PRIx64 "\",\"scope\":\"standalone byte decoder, image read eagerly; not engine or service memory\",\"timings\":[",
           image.rows, image.dictionaries, image.size, image.maximum_length, baseline, loaded, hydrated, digest);
    uint32_t longest = 0;
    for (uint32_t row = 1; row < image.rows; row++)
        if (u32(image.lengths + 4 * (size_t)row) > u32(image.lengths + 4 * (size_t)longest)) longest = row;
    for (unsigned mode = 0; mode < 4; mode++) {
        uint64_t seed = 261031, sum = UINT64_C(14695981039346656037);
        size_t queries = 0;
        double begin = clock_seconds(CLOCK_MONOTONIC);
        double cpu_begin = clock_seconds(CLOCK_PROCESS_CPUTIME_ID);
        for (unsigned long r = 0; r < repeats; r++) for (uint32_t i = 0; i < image.rows; i++) {
            uint32_t row = mode == 0 ? i : mode == 1 ? (uint32_t)(random_u64(&seed) % image.rows) :
                           mode == 2 ? longest : i % (image.rows < 8 ? image.rows : 8);
            const unsigned char *bytes = decode(&image, row, bound);
            sum = hash_row(sum, bytes, u32(image.lengths + 4 * (size_t)row), (image.flags[row] >> 1) & 1);
            queries++;
        }
        double cpu_elapsed = clock_seconds(CLOCK_PROCESS_CPUTIME_ID) - cpu_begin;
        double elapsed = clock_seconds(CLOCK_MONOTONIC) - begin;
        printf("%s{\"kind\":\"joint_dictionary_timing\",\"trace\":%u,\"queries\":%zu,\"seconds\":%.9f,\"cpu_seconds\":%.9f,\"decoded_fnv64\":\"%016" PRIx64 "\",\"includes_full_decoded_hash\":true}", mode ? "," : "", mode, queries, elapsed, cpu_elapsed, sum);
    }
    struct image replacement = load(argv[1], bound);
    for (uint32_t row = 0; row < replacement.rows; row++) (void)decode(&replacement, row, bound);
    long reloaded = rss_kib();
    long observed = baseline;
    if (loaded > observed) observed = loaded;
    if (hydrated > observed) observed = hydrated;
    if (reloaded > observed) observed = reloaded;
    printf("],\"reload\":{\"kind\":\"joint_dictionary_reload\",\"simultaneous_images\":2,\"image_bytes\":%zu,\"scratch_bytes\":%zu,\"rss_kib\":%ld,\"rusage_maxrss_kib\":%ld,\"max_observed_rss_kib\":%ld,\"scope\":\"old and replacement standalone images, not scanner engine reload\"}}\n",
           image.size + replacement.size, image.maximum_length + replacement.maximum_length, reloaded, peak_kib(), observed);
    release(&replacement);
    release(&image);
    return 0;
}
