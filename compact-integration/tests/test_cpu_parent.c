/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production resource and parent-death helpers in isolated
 * processes. CPU burns use process CPU time, not elapsed wall time. */
#define _GNU_SOURCE
#include "../native/limits.h"
#include <assert.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>

static uint64_t usage_microseconds(const struct rusage *usage)
{
    return (uint64_t)usage->ru_utime.tv_sec * 1000000
        + (uint64_t)usage->ru_utime.tv_usec
        + (uint64_t)usage->ru_stime.tv_sec * 1000000
        + (uint64_t)usage->ru_stime.tv_usec;
}

static uint64_t reference_total_cpu(void)
{
    struct rusage self, children;
    assert(!getrusage(RUSAGE_SELF, &self));
    assert(!getrusage(RUSAGE_CHILDREN, &children));
    return usage_microseconds(&self) + usage_microseconds(&children);
}

static void burn_cpu(uint64_t microseconds)
{
    struct timespec start, now;
    assert(!clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start));
    uint64_t elapsed;
    do {
        for (volatile unsigned i = 0; i < 100000; i++) {}
        assert(!clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now));
        elapsed = (uint64_t)(now.tv_sec - start.tv_sec) * 1000000;
        if (now.tv_nsec >= start.tv_nsec)
            elapsed += (uint64_t)(now.tv_nsec - start.tv_nsec) / 1000;
        else
            elapsed -= (uint64_t)(start.tv_nsec - now.tv_nsec) / 1000;
    } while (elapsed < microseconds);
}

static void wait_success(pid_t child)
{
    int status;
    while (waitpid(child, &status, 0) < 0) assert(errno == EINTR);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_effective_inherited_cpu(void)
{
    struct rlimit inherited = {1, 1}, actual;
    assert(!setrlimit(RLIMIT_CPU, &inherited));
    struct ci_limits limits = {64ULL * 1024 * 1024, 10, 20, 1024 * 1024};
    assert(!ci_limits_apply(&limits));
    assert(limits.cpu_seconds == 1);
    assert(!getrlimit(RLIMIT_CPU, &actual));
    assert(actual.rlim_cur == 1 && actual.rlim_max == 1);
    burn_cpu(50000);
    uint64_t remaining = UINT64_MAX;
    /* Less than one effective second remains; another batch cannot be funded
     * by the original requested ten-second value. */
    assert(ci_cpu_budget_remaining(&limits, &remaining) < 0);
}

static void test_fractional_cumulative_cpu(void)
{
    struct rlimit inherited = {3, 3};
    assert(!setrlimit(RLIMIT_CPU, &inherited));
    struct ci_limits limits = {64ULL * 1024 * 1024, 3, 25, 1024 * 1024};
    assert(!ci_limits_apply(&limits));
    assert(!ci_cpu_budget_check(&limits));
    burn_cpu(600000);
    unsigned passed = 0;
    for (;;) {
        uint64_t before = reference_total_cpu(), measured = 0;
        assert(!ci_total_cpu_microseconds(&measured));
        uint64_t after = reference_total_cpu();
        assert(measured >= before && measured <= after);
        uint64_t remaining = UINT64_MAX;
        if (ci_cpu_budget_remaining(&limits, &remaining) < 0) break;
        assert(passed < 4 && remaining >= 1 && remaining < 3);
        struct ci_limits child_limits = limits;
        child_limits.cpu_seconds = remaining;
        pid_t expected_parent = getpid();
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            if (ci_limits_apply_for_parent(&child_limits, expected_parent)) _exit(10);
            burn_cpu(600000);
            _exit(0);
        }
        wait_success(child);
        passed++;
        if (passed == 1) {
            /* Self and waited-child fractions total at least 1.2 seconds.
             * Summing only tv_sec then adding one incorrectly leaves two. */
            uint64_t total = 0;
            assert(!ci_total_cpu_microseconds(&total));
            assert(total >= 1200000);
            if (total < 2000000) {
                assert(!ci_cpu_budget_remaining(&limits, &remaining));
                assert(remaining == 1);
            }
        }
    }
    uint64_t total = 0, remaining = UINT64_MAX;
    assert(!ci_total_cpu_microseconds(&total));
    assert(passed >= 1 && passed <= 3);
    assert(total <= 3000000);
    assert(ci_cpu_budget_remaining(&limits, &remaining) < 0);
    struct ci_limits exhausted = limits;
    exhausted.cpu_seconds = 1;
    assert(ci_cpu_budget_check(&exhausted) < 0);
}

#ifdef __linux__
static void transfer(int fd, void *data, size_t size, int writing)
{
    size_t done = 0;
    while (done < size) {
        ssize_t amount = writing
            ? write(fd, (unsigned char *)data + done, size - done)
            : read(fd, (unsigned char *)data + done, size - done);
        if (amount < 0 && errno == EINTR) continue;
        assert(amount > 0);
        done += (size_t)amount;
    }
}

static void test_adopted_parent(int full_limits)
{
    assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
    int ready[2], release[2], result[2];
    assert(!pipe(ready) && !pipe(release) && !pipe(result));
    pid_t adopter = getpid();
    pid_t original = fork();
    assert(original >= 0);
    if (!original) {
        close(ready[0]); close(release[1]); close(result[0]);
        alarm(10);
        pid_t expected_parent = getpid(); /* Captured before fork. */
        pid_t guarded = fork();
        if (guarded < 0) _exit(11);
        if (!guarded) {
            alarm(10);
            pid_t identity = getpid();
            transfer(ready[1], &identity, sizeof(identity), 1);
            char token;
            transfer(release[0], &token, sizeof(token), 0);
            struct ci_limits limits = {64ULL * 1024 * 1024, 3, 10, 1024 * 1024};
            int values[2] = {full_limits
                ? ci_limits_apply_for_parent(&limits, expected_parent)
                : ci_parent_death(expected_parent), getppid()};
            transfer(result[1], values, sizeof(values), 1);
            _exit(0);
        }
        close(ready[1]); close(release[0]); close(result[1]);
        for (;;) pause();
    }
    close(ready[1]); close(release[0]); close(result[1]);
    pid_t guarded = 0;
    transfer(ready[0], &guarded, sizeof(guarded), 0);
    assert(!kill(original, SIGKILL));
    int status;
    while (waitpid(original, &status, 0) < 0) assert(errno == EINTR);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    char token = 1;
    transfer(release[1], &token, sizeof(token), 1);
    int values[2];
    transfer(result[0], values, sizeof(values), 0);
    wait_success(guarded); /* Reap before asserting a regression failure. */
    assert(values[1] == adopter && values[0] < 0);
    close(ready[0]); close(release[1]); close(result[0]);
}

static void test_adopted_primitive(void) { test_adopted_parent(0); }
static void test_adopted_limits(void) { test_adopted_parent(1); }

static void test_registered_parent_death(void)
{
    assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
    int ready[2]; assert(!pipe(ready));
    pid_t original = fork();
    assert(original >= 0);
    if (!original) {
        close(ready[0]);
        alarm(10);
        pid_t expected_parent = getpid();
        pid_t guarded = fork();
        if (guarded < 0) _exit(12);
        if (!guarded) {
            alarm(10);
            if (ci_parent_death(expected_parent)) _exit(13);
            pid_t identity = getpid();
            transfer(ready[1], &identity, sizeof(identity), 1);
            for (;;) pause();
        }
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    pid_t guarded;
    transfer(ready[0], &guarded, sizeof(guarded), 0);
    assert(!kill(original, SIGKILL));
    int status;
    while (waitpid(original, &status, 0) < 0) assert(errno == EINTR);
    while (waitpid(guarded, &status, 0) < 0) assert(errno == EINTR);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    close(ready[0]);
}
#endif

static void run_case(void (*test)(void), const char *name)
{
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        alarm(30);
        test();
        _exit(0);
    }
    wait_success(child);
    printf("%s passed\n", name);
}

int main(void)
{
    struct rlimit no_core = {0, 0};
    assert(!setrlimit(RLIMIT_CORE, &no_core));
    assert(!unsetenv("COMPACT_PARENT_PID"));
    char *arguments[] = {"test", "scan", "--as-bytes", "67108864", "--cpu-seconds", "3",
                         "--wall-seconds", "25", "--file-bytes", "1048576", NULL};
    struct ci_limits parsed;
    assert(!ci_limits_parse(10, arguments, &parsed));
    run_case(test_effective_inherited_cpu, "effective inherited CPU");
    run_case(test_fractional_cumulative_cpu, "fractional cumulative CPU");
#ifdef __linux__
    run_case(test_adopted_primitive, "subreaper adoption before parent registration");
    run_case(test_adopted_limits, "subreaper adoption before limits registration");
    run_case(test_registered_parent_death, "registered parent death");
#endif
    puts("native CPU and parent regression tests passed");
    return 0;
}
