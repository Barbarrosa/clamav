/* SPDX-License-Identifier: GPL-2.0-only
 * Whole-engine qualification adapter. No engine internals or rule filtering.
 * Reuses the existing timed scanner and exact callback transcript collector.
 */
#define PERFORMANCE_PROBE_NO_MAIN
#include "../../subset-selector/performance/performance_probe.c"
#include <pthread.h>
#include <sched.h>

struct worker {
    struct cl_engine *engine;
    char **paths;
    size_t count;
    int index;
    int allmatch;
};
static void *worker_scan(void *opaque)
{
    struct worker *worker = opaque;
    run_batch(worker->engine, worker->paths, worker->count, 1, worker->allmatch,
              "concurrent_scan", worker->index);
    return NULL;
}
static void limits_identity(void)
{
    struct rlimit limit;
    json_object *o = json_object_new_object();
    add(o, "kind", "resource_limits");
    CHECK(!getrlimit(RLIMIT_AS, &limit));
    if (limit.rlim_cur != RLIM_INFINITY) num(o, "address_space_bytes", limit.rlim_cur);
    CHECK(!getrlimit(RLIMIT_CPU, &limit));
    if (limit.rlim_cur != RLIM_INFINITY) num(o, "cpu_soft_seconds", limit.rlim_cur);
    if (limit.rlim_max != RLIM_INFINITY) num(o, "cpu_hard_seconds", limit.rlim_max);
    cpu_set_t set;
    CHECK(!sched_getaffinity(0, sizeof(set), &set));
    json_object *cpus = json_object_new_array();
    for (unsigned i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, &set)) json_object_array_add(cpus, json_object_new_int(i));
    json_object_object_add(o, "cpu_affinity", cpus);
    num(o, "maximum_concurrency_claimed", 0);
    add(o, "scope", "observed process limits; concurrency is a declared test value, not a supported deployment maximum");
    emit(o);
}
static void modules_identity(void)
{
    FILE *maps = fopen("/proc/self/maps", "r"); CHECK(maps);
    char line[PATH_MAX + 256], observed[2][PATH_MAX] = {{0}};
    json_object *o = json_object_new_object(), *modules = json_object_new_array();
    while (fgets(line, sizeof(line), maps)) {
        int kind = strstr(line, "/libclamunrar_iface.so") ? 0 : strstr(line, "/libclamunrar.so") ? 1 : -1;
        if (kind < 0 || observed[kind][0]) continue;
        char *start = strchr(line, '/'), *end = strchr(start, '\n');
        if (end) *end = 0;
        CHECK(realpath(start, observed[kind]));
        int fd = open(observed[kind], O_RDONLY | O_NOFOLLOW); char hash[65]; CHECK(fd >= 0);
        digest_fd(fd, hash); close(fd);
        json_object *module = json_object_new_object();
        add(module, "kind", kind ? "unrar" : "iface"); add(module, "path", observed[kind]);
        add(module, "sha256", hash); json_object_array_add(modules, module);
    }
    fclose(maps); CHECK(observed[0][0] && observed[1][0]);
    add(o, "kind", "runtime_modules"); json_object_object_add(o, "modules", modules); emit(o);
}
static void identify_update(void *symbol)
{
    Dl_info info;
    char resolved[PATH_MAX], hash[65];
    CHECK(dladdr(symbol, &info) && info.dli_fname && realpath(info.dli_fname, resolved));
    int fd = open(resolved, O_RDONLY | O_NOFOLLOW);
    CHECK(fd >= 0); digest_fd(fd, hash); close(fd);
    json_object *o = json_object_new_object();
    add(o, "kind", "update_runtime"); add(o, "library_path", resolved);
    add(o, "library_sha256", hash); emit(o);
}
int main(int argc, char **argv)
{
    if (argc != 10) {
        fprintf(stderr, "usage: %s DB CERTS FILELIST CASE DBLIST DB_CACHE REPEATS CONCURRENCY ALLMATCH\n", argv[0]);
        return 2;
    }
    const char *mode = argv[4];
    int repeats = atoi(argv[7]), workers = atoi(argv[8]), allmatch = atoi(argv[9]);
    CHECK(!strcmp(mode, "scan") || !strcmp(mode, "reload") ||
          !strcmp(mode, "update") || !strcmp(mode, "concurrency"));
    CHECK(repeats >= 1 && repeats <= 20 && workers >= 1 && workers <= 64);
    CHECK(allmatch == 0 || allmatch == 1);
    CHECK(!strcmp(argv[6], "empty") || !strcmp(argv[6], "hydrated"));
    result_cache_enabled = 0;
    size_t database_count = 0, file_count = 0;
    char **databases = read_paths(argv[5], &database_count);
    char **files = read_paths(argv[3], &file_count);
    prepare_files(databases, database_count, !strcmp(argv[6], "hydrated"), "before_load");
    CHECK(cl_init(CL_INIT_DEFAULT) == CL_SUCCESS);
    require_unrar_modules(); runtime_identity(); modules_identity(); limits_identity();
    struct sample a = sample();
    struct cl_engine *engine = load_engine(argv[1], argv[2], "-", "engine");
    struct sample b = sample();
    json_object *o = json_object_new_object();
    add(o, "kind", "startup"); add(o, "case", mode);
    measurements(o, a, b); memory_fields(o); num(o, "unrar_modules_verified", 1);
    num(o, "result_cache_enabled", 0); num(o, "metadata", 1); num(o, "allmatch", allmatch); emit(o);
    if (!strcmp(mode, "scan")) {
        prepare_files(files, file_count, 0, "before_first_scan");
        run_batch(engine, files, file_count, 1, allmatch, "file_cache_empty", 0);
        for (int round = 1; round <= repeats; round++) {
            prepare_files(files, file_count, 1, "before_hydrated_scan");
            run_batch(engine, files, file_count, 1, allmatch, "file_cache_hydrated", round);
        }
    } else if (!strcmp(mode, "concurrency")) {
        pthread_t threads[64]; struct worker contexts[64];
        prepare_files(files, file_count, 1, "before_concurrent_scan");
        a = sample();
        for (int i = 0; i < workers; i++) {
            contexts[i] = (struct worker){engine, files, file_count, i, allmatch};
            CHECK(!pthread_create(&threads[i], NULL, worker_scan, &contexts[i]));
        }
        for (int i = 0; i < workers; i++) CHECK(!pthread_join(threads[i], NULL));
        b = sample(); o = json_object_new_object(); add(o, "kind", "concurrency");
        num(o, "workers", workers); measurements(o, a, b); memory_fields(o);
        add(o, "cpu_scope", "one process envelope; overlapping per-file process CPU values must not be summed"); emit(o);
    } else {
        const char *replacement_path = getenv("QUAL_RELOAD_DB");
        if (!replacement_path) replacement_path = argv[1];
        a = sample();
        struct cl_engine *replacement = load_engine(replacement_path, argv[2], "-", "reload_overlap");
        b = sample(); o = json_object_new_object(); add(o, "kind", "reload");
        add(o, "replacement_database", replacement_path);
        measurements(o, a, b); memory_fields(o); emit(o);
        if (!strcmp(mode, "update")) {
            const char *library = getenv("BENCH_FRESHCLAM_LIBRARY");
            const char *database = getenv("BENCH_FRESHCLAM_DATABASE");
            CHECK(library && database);
            void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL); CHECK(handle);
            void *symbol = dlsym(handle, "fc_test_database_ex"); CHECK(symbol);
            identify_update(symbol);
            int (*test)(const char *, int, char *) = (int (*)(const char *, int, char *))symbol;
            a = sample(); int rc = test(database, 1, argv[2]); b = sample();
            o = json_object_new_object(); add(o, "kind", "update_validation");
            add(o, "database", database); num(o, "return_code", rc);
            measurements(o, a, b); memory_fields(o);
            add(o, "hwm_scope", "cumulative process high water through in-process validation with two engines retained"); emit(o);
            CHECK(!rc); dlclose(handle);
        }
        cl_engine_free(engine); engine = replacement;
        o = json_object_new_object(); add(o, "kind", "old_engine_freed"); memory_fields(o); emit(o);
    }
    cl_engine_free(engine);
    o = json_object_new_object(); add(o, "kind", "all_engines_freed"); memory_fields(o); emit(o);
    for (size_t i = 0; i < database_count; i++) free(databases[i]);
    for (size_t i = 0; i < file_count; i++) free(files[i]);
    free(databases); free(files);
    return 0;
}
