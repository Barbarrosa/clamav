/* SPDX-License-Identifier: GPL-2.0-only
 * Pure native unit fixtures. CI_PREPARE_TEST excludes signature verification;
 * production must additionally reject these unsigned fixture transports.
 */
#define CI_PREPARE_TEST
#include "../native/prepare.c"
#include <assert.h>

struct test_member { const char *name, *text; };

static void test_archive(const char *path, const struct test_member *members,
                         size_t count, int compressed, int corrupt)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    unsigned char zero[1024] = {0};
    assert(write(fd, zero, 512) == 512);
    gzFile out = gzdopen(fd, compressed ? "wb" : "wbT");
    assert(out);
    for (size_t n = 0; n < count; ++n) {
        unsigned char header[512] = {0};
        size_t length = strlen(members[n].text);
        assert(length <= UINT_MAX);
        assert(strlen(members[n].name) < 100);
        memcpy(header, members[n].name, strlen(members[n].name));
        snprintf((char *)header + 100, 8, "%07o", 0600);
        snprintf((char *)header + 108, 8, "%07o", 0);
        snprintf((char *)header + 116, 8, "%07o", 0);
        snprintf((char *)header + 124, 12, "%011o", (unsigned)length);
        snprintf((char *)header + 136, 12, "%011o", 0);
        memset(header + 148, ' ', 8);
        header[156] = '0';
        memcpy(header + 257, "ustar", 5);
        unsigned sum = 0;
        for (size_t i = 0; i < sizeof(header); ++i) sum += header[i];
        snprintf((char *)header + 148, 8, "%06o", sum);
        header[155] = ' ';
        if (corrupt == 1 && !n) header[0] ^= 1;
        assert(gzwrite(out, header, sizeof(header)) == (int)sizeof(header));
        assert(gzwrite(out, members[n].text, (unsigned)length) == (int)length);
        unsigned padding = (unsigned)((512 - length % 512) % 512);
        if (padding) assert(gzwrite(out, zero, padding) == (int)padding);
    }
    if (corrupt == 3) {
        unsigned char partial[31];
        memset(partial, 'X', sizeof(partial));
        assert(gzwrite(out, partial, sizeof(partial)) == (int)sizeof(partial));
    } else if (corrupt != 2) assert(gzwrite(out, zero, sizeof(zero)) == (int)sizeof(zero));
    assert(gzclose(out) == Z_OK);
}

static void test_decision(const char *format, const char *original, int expected,
                          const char *namespace_name)
{
    char *line = strdup(original);
    struct ci_decision d;
    assert(ci_classify(format, line, &d) == 1);
    assert(d.eligible == expected);
    if (namespace_name) assert(!strcmp(d.format, namespace_name));
    free(line);
}

static void test_classifier(void)
{
    assert(ci_official_signature_name("main-1.cvd.sign"));
    assert(ci_official_signature_name("daily-4294967295.cvd.sign"));
    assert(!ci_official_signature_name("daily-4294967296.cvd.sign"));
    assert(!ci_official_signature_name("main-1.cdiff.sign"));
    assert(!ci_official_signature_name("../main-1.cvd.sign"));
    assert(!ci_official_signature_name("custom-1.cvd.sign"));
    test_decision("ndb", "Rule:1:*:41424344", 1, "ndb");
    test_decision("ndb", "Rule:0:*:41424344", 0, NULL);
    test_decision("ndu", "Rule:1:*:41424344", 1, "ndb");
    test_decision("ndb", "Rule:01:*:41424344", 0, NULL);
    test_decision("ndb", "Rule:1:$1$:41424344", 0, NULL);
    test_decision("ldb", "Rule;Engine:90-255,Target:1;0;41424344", 1, NULL);
    test_decision("ldu", "Rule;Target:1;0;41424344", 1, "ldb");
    test_decision("ldb", "Rule;Target:1,HandlerType:CL_TYPE_PDF;0;41424344", 0, NULL);
    test_decision("ldb", "Rule;Target:1,Future:4;0;41424344", 0, NULL);
    test_decision("ldb", "Rule;Target:1,Target:1;0;41424344", 0, NULL);
    test_decision("ldb", "Rule;Target:1,,Engine:90-255;0;41424344", 0, NULL);
    test_decision("ldb", "Rule;Target:1;0;${1-2}3$", 0, NULL);
    test_decision("ldb", "Rule;Target:0;0;41424344", 0, NULL);
    char invalid[] = "Bad\tName:1:*:41424344";
    struct ci_decision d;
    assert(ci_classify("ndb", invalid, &d) == -1);
}

static int test_eligible(sqlite3 *db, const char *format, const char *name)
{
    sqlite3_stmt *query = NULL;
    assert(sqlite3_prepare_v2(db, "SELECT eligible FROM names WHERE format=?1 AND name=?2", -1, &query, NULL) == SQLITE_OK);
    sqlite3_bind_text(query, 1, format, -1, SQLITE_STATIC);
    sqlite3_bind_text(query, 2, name, -1, SQLITE_STATIC);
    assert(sqlite3_step(query) == SQLITE_ROW);
    int value = sqlite3_column_int(query, 0);
    sqlite3_finalize(query);
    return value;
}

static void test_inventory(const char *base)
{
    char path[PATH_MAX], dbdir[PATH_MAX], generation[PATH_MAX];
    assert(snprintf(generation, sizeof(generation), "%s/generation", base) < (int)sizeof(generation));
    assert(mkdir(generation, 0700) == 0);
    assert(snprintf(dbdir, sizeof(dbdir), "%s/databases", generation) < (int)sizeof(dbdir));
    assert(mkdir(dbdir, 0700) == 0);
    const struct test_member main_members[] = {
        {"main.ndb", "OnlyPE:1:*:41424344\nCollision:1:*:41424344\nMacro:1:$1$:41424344\n"},
        {"main.ldb", "Ordinary;Target:1;0;41424344\nProtected;Target:1;0;41424344\nHandler;Target:1,HandlerType:CL_TYPE_PDF;0;41424344\n"},
        {"main.mdb", "4:12345678901234567890123456789012:Section\n"},
        {"COPYING", "license\n"}};
    assert(snprintf(path, sizeof(path), "%s/main.cvd", dbdir) < (int)sizeof(path));
    test_archive(path, main_members, sizeof(main_members)/sizeof(main_members[0]), 1, 0);
    const struct test_member daily_members[] = {{"daily.ndb", "Collision:0:*:41424344\n"}, {"daily.imp", "12345678901234567890123456789012:*:Import\n"}};
    assert(snprintf(path, sizeof(path), "%s/daily.cld", dbdir) < (int)sizeof(path));
    test_archive(path, daily_members, 2, 0, 2);
    const struct test_member bytecode_members[] = {{"rule.cbc", "Header\nProtected;Target:1;0;41424344\nBody\n"}, {"startup.cbc", "Header\n\nBody\n"}};
    assert(snprintf(path, sizeof(path), "%s/bytecode.cvd", dbdir) < (int)sizeof(path));
    test_archive(path, bytecode_members, 2, 1, 0);
    assert(snprintf(path,sizeof(path),"%s/main-1.cvd.sign",dbdir)<(int)sizeof(path));
    int signature=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(signature>=0);
    assert(write(signature,"test-only unsigned metadata",27)==27);assert(!close(signature));
    assert(ci_prepare_generation(generation, "/unused-test-certs") == 0);
    assert(snprintf(path, sizeof(path), "%s/profile/skip.tsv", generation) < (int)sizeof(path));
    FILE *skip = fopen(path, "r");
    assert(skip);
    char actual[1024] = {0};
    size_t bytes = fread(actual, 1, sizeof(actual) - 1, skip);
    assert(!ferror(skip) && bytes < sizeof(actual) - 1);
    fclose(skip);
    assert(!strcmp(actual, "imp\t*\nldb\tOrdinary\nmdb\t*\nndb\tOnlyPE\n"));
    assert(snprintf(path, sizeof(path), "%s/profile/ledger.sqlite", generation) < (int)sizeof(path));
    sqlite3 *db = NULL;
    assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
    assert(test_eligible(db, "ndb", "Collision") == 0);
    assert(test_eligible(db, "ldb", "Protected") == 0);
    assert(test_eligible(db, "ndb", "OnlyPE") == 1);
    sqlite3_close(db);
    assert(snprintf(path, sizeof(path), "%s/profile/validation.json", generation) < (int)sizeof(path));
    json_object *validation = json_object_from_file(path), *qualified = NULL, *native = NULL;
    assert(validation);
    assert(json_object_object_get_ex(validation, "coverage_qualified", &qualified));
    assert(!json_object_get_boolean(qualified));
    assert(json_object_object_get_ex(validation, "native_syntax_validation", &native));
    assert(!strcmp(json_object_get_string(native), "not-performed"));
    json_object_put(validation);
    assert(ci_prepare_generation(generation, "/unused-test-certs") == 2);
}

static void test_rejected_archives(const char *base)
{
    const struct test_member cases[][2] = {
        {{"bad.new", "unknown"}, {NULL, NULL}},
        {{"same.ndb", "Rule:1:*:41424344\n"}, {"same.ndb", "Rule:0:*:41424344\n"}},
        {{"../bad.ndb", "Rule:1:*:41424344\n"}, {NULL, NULL}},
        {{"bad.ndb", "Rule:1:*:41424344\n"}, {NULL, NULL}},
        {{"partial.ndb", "Rule:1:*:41424344\n"}, {NULL, NULL}}};
    for (unsigned n = 0; n < 5; ++n) {
        char path[PATH_MAX], ledger[PATH_MAX];
        assert(snprintf(path, sizeof(path), "%s/rejected-%u.cvd", base, n) < (int)sizeof(path));
        assert(snprintf(ledger, sizeof(ledger), "%s/rejected-%u.sqlite", base, n) < (int)sizeof(ledger));
        test_archive(path, cases[n], n == 1 ? 2 : 1, n % 2, n == 3 ? 1 : n == 4 ? 3 : 0);
        struct ci_preparation p = {0};
        assert(ci_open_ledger(&p, ledger) == 0);
        int fd = open(path, O_RDONLY);
        assert(fd >= 0);
        assert(ci_archive(&p, fd, "main.cvd") == -1);
        assert(p.error[0]);
        close(fd);
        ci_close_ledger(&p);
    }
}

static void test_line_limits(const char *base)
{
    const size_t length = 70000;
    const char prefix[] = "Large:1:*:";
    char *text = malloc(length + 2);
    assert(text);
    memcpy(text, prefix, sizeof(prefix) - 1);
    memset(text + sizeof(prefix) - 1, '4', length - sizeof(prefix) + 1);
    text[length] = '\n'; text[length + 1] = 0;
    char archive_path[PATH_MAX];
    assert(snprintf(archive_path, sizeof(archive_path), "%s/long-line.cvd", base) < (int)sizeof(archive_path));
    const struct test_member member = {"long.ndb", text};
    test_archive(archive_path, &member, 1, 1, 2);
    free(text);
    const uint64_t limits[] = {32768, length - 1, length, length + 1};
    for (unsigned i = 0; i < 4; ++i) {
        struct ci_preparation p = {0};
        char ledger[PATH_MAX];
        assert(snprintf(ledger, sizeof(ledger), "%s/line-limit-%u.sqlite", base, i) < (int)sizeof(ledger));
        assert(ci_line_budget(&p, limits[i]) == 0);
        assert(ci_open_ledger(&p, ledger) == 0);
        int fd = open(archive_path, O_RDONLY);
        assert(fd >= 0);
        assert(ci_archive(&p, fd, "main.cvd") == (i < 2 ? -1 : 0));
        if (i < 2) assert(strstr(p.error, "configured inventory limit"));
        else assert(test_eligible(p.db, "ndb", "Large") == 1);
        close(fd);
        ci_close_ledger(&p);
    }
    struct ci_preparation invalid = {0};
    assert(ci_line_budget(&invalid, 0) == -1);
    assert(ci_line_budget(&invalid, UINT64_MAX) == -1);
    assert(ci_line_budget(&invalid, (uint64_t)INT_MAX / 2 + 1) == -1);
    assert(invalid.line == NULL);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    test_classifier();
    test_inventory(argv[1]);
    test_rejected_archives(argv[1]);
    test_line_limits(argv[1]);
    puts("native preparation fixtures passed");
    return 0;
}
