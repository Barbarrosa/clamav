/* SPDX-License-Identifier: GPL-2.0-only
 * Linux benchmark for an unmodified or compact libclamav. Uses public APIs only.
 * Build and invocation are documented in docs/compact-resident-engine.md.
 */
#include "clamav.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static double seconds(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        abort();
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static long resident_kib(void)
{
    char line[256];
    long value = -1;
    FILE *f    = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "VmRSS: %ld kB", &value) == 1)
            break;
    }
    fclose(f);
    return value;
}

static int failed(const char *phase, cl_error_t error, struct cl_engine *engine)
{
    fprintf(stderr, "%s: %s\n", phase, cl_strerror(error));
    if (engine)
        cl_engine_free(engine);
    return 2;
}

int main(int argc, char **argv)
{
    struct cl_engine *engine;
    struct cl_scan_options options = {0};
    struct rusage usage;
    cl_error_t status, expected = CL_CLEAN;
    unsigned signatures   = 0, i, iterations;
    unsigned long scanned = 0;
    double start, load_seconds, compile_seconds, scan_seconds;
    long compiled_rss;
    char *end;
    unsigned long requested;

    if (argc != 5) {
        fprintf(stderr, "usage: %s DATABASE INPUT ITERATIONS CERTS_DIRECTORY\n", argv[0]);
        return 2;
    }
    requested = strtoul(argv[3], &end, 10);
    if (*end || !requested || requested > 100000)
        return 2;
    iterations = (unsigned)requested;
    if ((status = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS)
        return failed("init", status, NULL);
    engine = cl_engine_new();
    if (!engine)
        return failed("engine", CL_EMEM, NULL);
    /* Repeat real matching, rather than measuring clean-file cache hits. */
    if ((status = cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1)) != CL_SUCCESS)
        return failed("cache option", status, engine);
    if ((status = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, argv[4])) != CL_SUCCESS)
        return failed("certificate directory", status, engine);
    start = seconds();
    if ((status = cl_load(argv[1], engine, &signatures, CL_DB_STDOPT)) != CL_SUCCESS)
        return failed("load", status, engine);
    load_seconds = seconds() - start;
    start        = seconds();
    if ((status = cl_engine_compile(engine)) != CL_SUCCESS)
        return failed("compile", status, engine);
    compile_seconds = seconds() - start;
    compiled_rss    = resident_kib();
    options.parse   = ~0U;
    options.general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_HEURISTICS;
    start           = seconds();
    for (i = 0; i < iterations; i++) {
        const char *name = NULL;
        status           = cl_scanfile(argv[2], &name, &scanned, engine, &options);
        if (status != CL_CLEAN && status != CL_VIRUS)
            return failed("scan", status, engine);
        if (!i)
            expected = status;
        else if (status != expected)
            return failed("inconsistent scan verdict", status, engine);
    }
    scan_seconds = seconds() - start;
    if (getrusage(RUSAGE_SELF, &usage))
        return failed("rusage", CL_ERROR, engine);
    printf("{\"signatures\":%u,\"iterations\":%u,\"verdict\":%d,"
           "\"load_seconds\":%.9f,\"compile_seconds\":%.9f,\"scan_seconds\":%.9f,"
           "\"compiled_rss_kib\":%ld,\"peak_rss_kib\":%ld}\n",
           signatures, iterations, expected, load_seconds, compile_seconds,
           scan_seconds, compiled_rss, usage.ru_maxrss);
    cl_engine_free(engine);
    return 0;
}
