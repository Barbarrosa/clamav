/* SPDX-License-Identifier: GPL-2.0-only
 * Experimental full-database allocation-sensitivity harness.
 * Reuses the established public-API scanner callbacks and measurements.
 * The optional perturbation hook is test-only; ordinary builds remain usable.
 */
#define PERFORMANCE_PROBE_NO_MAIN
#include "../../subset-selector/performance/performance_probe.c"

typedef void (*perturb_snapshot_fn)(const char *);
typedef int (*pool_stats_fn)(const struct cl_engine *, size_t *, size_t *);
static perturb_snapshot_fn perturb_snapshot;
static pool_stats_fn pool_stats;

static void snapshot(const char *phase, struct cl_engine *first, struct cl_engine *second)
{
    json_object *o = json_object_new_object();
    add(o, "kind", "memory_snapshot");
    add(o, "phase", phase);
    memory_fields(o);
    num(o, "engines_live", !!first + !!second);
    num(o, "perturb_snapshot_available", perturb_snapshot != NULL);
    size_t carved = 0, mapped = 0;
    int known = pool_stats != NULL;
    const struct cl_engine *engines[] = {first, second};
    for (unsigned i = 0; i < 2; i++) {
        if (engines[i] && known) {
            size_t used = 0, total = 0;
            if (pool_stats(engines[i], &used, &total)) known = 0;
            else { carved += used; mapped += total; }
        }
    }
    if (known) {
        num(o, "pool_carved_extent_bytes", (int64_t)carved);
        num(o, "pool_mapped_extent_bytes", (int64_t)mapped);
    }
    num(o, "pool_extents_available", known);
    add(o, "pool_extent_scope", "pool carved/mapped extents, including metadata and retained free chunks; not live payload or RSS");
    struct rlimit limit;
    CHECK(!getrlimit(RLIMIT_AS, &limit));
    if (limit.rlim_cur != RLIM_INFINITY) num(o, "address_space_limit_bytes", (int64_t)limit.rlim_cur);
    CHECK(!getrlimit(RLIMIT_CPU, &limit));
    if (limit.rlim_cur != RLIM_INFINITY) num(o, "cpu_limit_seconds", (int64_t)limit.rlim_cur);
    emit(o);
    if (perturb_snapshot) perturb_snapshot(phase);
}

static struct cl_engine *new_engine(const char *db, const char *certs,
                                    const char *prefix, struct cl_engine *old)
{
    struct sample a = sample();
    struct cl_engine *e = cl_engine_new();
    CHECK(e);
    CHECK(cl_engine_set_str(e, CL_ENGINE_CVDCERTSDIR, certs) == CL_SUCCESS);
    CHECK(cl_engine_set_num(e, CL_ENGINE_DISABLE_CACHE, 1) == CL_SUCCESS);
    unsigned signatures = 0;
    cl_error_t rc = cl_load(db, e, &signatures, CL_DB_STDOPT);
    struct sample b = sample();
    json_object *o = json_object_new_object();
    add(o, "kind", "engine_load"); add(o, "engine", prefix);
    num(o, "return_code", rc); num(o, "signatures", signatures);
    measurements(o, a, b); emit(o); CHECK(rc == CL_SUCCESS);
    snapshot(old ? "reload_loaded" : "loaded", e, old);
    a = sample(); rc = cl_engine_compile(e); b = sample();
    o = json_object_new_object();
    add(o, "kind", "engine_compile"); add(o, "engine", prefix);
    num(o, "return_code", rc); measurements(o, a, b); emit(o);
    CHECK(rc == CL_SUCCESS);
    snapshot(old ? "reload_compiled" : "compiled", e, old);
    cl_engine_set_scan_callback(e, prehash, CL_SCAN_CALLBACK_PRE_HASH);
    cl_engine_set_scan_callback(e, prescan, CL_SCAN_CALLBACK_PRE_SCAN);
    cl_engine_set_scan_callback(e, postscan, CL_SCAN_CALLBACK_POST_SCAN);
    cl_engine_set_scan_callback(e, filetype, CL_SCAN_CALLBACK_FILE_TYPE);
    cl_engine_set_scan_callback(e, alert, CL_SCAN_CALLBACK_ALERT);
    cl_engine_set_clcb_virus_found(e, legacy);
    cl_engine_set_clcb_meta(e, meta);
    cl_engine_set_clcb_file_props(e, props);
    return e;
}

int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "usage: %s DB CERTS FILELIST RELOAD(0|1) SCAN_PASSES(0..5) REQUIRE_PERTURB(0|1)\n", argv[0]);
        return 2;
    }
    CHECK(!strcmp(argv[4], "0") || !strcmp(argv[4], "1"));
    CHECK(strlen(argv[5]) == 1 && argv[5][0] >= '0' && argv[5][0] <= '5');
    CHECK(!strcmp(argv[6], "0") || !strcmp(argv[6], "1"));
    perturb_snapshot = (perturb_snapshot_fn)dlsym(RTLD_DEFAULT, "cm_perturb_snapshot");
    pool_stats = (pool_stats_fn)dlsym(RTLD_DEFAULT, "cm_perturb_pool_stats");
    if (!pool_stats) pool_stats = (pool_stats_fn)dlsym(RTLD_DEFAULT, "mpool_getstats");
    CHECK(!atoi(argv[6]) || perturb_snapshot);
    CHECK(cl_init(CL_INIT_DEFAULT) == CL_SUCCESS);
    require_unrar_modules(); runtime_identity();
    snapshot("initial", NULL, NULL);
    struct cl_engine *e = new_engine(argv[1], argv[2], "primary", NULL);
    size_t count = 0;
    char **paths = read_paths(argv[3], &count);
    for (int pass = 0; pass < atoi(argv[5]); pass++)
        run_batch(e, paths, count, 1, 1, "fixture_scan", pass);
    snapshot("scanned", e, NULL);
    if (atoi(argv[4])) {
        struct cl_engine *replacement = new_engine(argv[1], argv[2], "replacement", e);
        cl_engine_free(e);
        snapshot("reload_old_freed", replacement, NULL);
        e = replacement;
    }
    cl_engine_free(e);
    snapshot("all_freed", NULL, NULL);
    for (size_t i = 0; i < count; i++) free(paths[i]);
    free(paths);
    return 0;
}
