/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CI_LIMITS_H
#define CI_LIMITS_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
struct ci_limits { uint64_t as_bytes, cpu_seconds, wall_seconds, file_bytes; };
static inline void ci_emergency_write(const char *record,size_t length) {
    /* A fatal handler must reach _exit even when its supervisor stopped reading.
     * fcntl/write are async-signal-safe; failure and EAGAIN are intentionally
     * ignored because absence of a result cannot approve a scan. */
    int flags=fcntl(STDOUT_FILENO,F_GETFL);
    if(flags>=0&&fcntl(STDOUT_FILENO,F_SETFL,flags|O_NONBLOCK)==0)
        (void)write(STDOUT_FILENO,record,length);
}
static inline void ci_limit_alarm(int signal_number) {
    (void)signal_number;
    static const char output[] = "{\"protocol\":1,\"status\":\"failed\",\"completed\":false,\"applicability_proven\":false,\"coverage_qualified\":false,\"sha256\":null,\"size\":0,\"engine_version\":null,\"generation_id\":null,\"requested_profile\":null,\"effective_profile\":null,\"findings\":[],\"reason_codes\":[\"native-resource-limit\"]}\n";
    ci_emergency_write(output,sizeof(output)-1);
    _exit(2);
}
static inline int ci_positive_number(const char *s,uint64_t *out) {
    if(!s||!*s)return -1;
    for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return -1;
    char *end=NULL;errno=0;unsigned long long n=strtoull(s,&end,10);
    if(errno||!end||*end||!n)return -1;
    *out=(uint64_t)n;return 0;
}
static inline const char *ci_option(int argc,char **argv,const char *name) {
    for(int i=2;i+1<argc;i++) {
        if(!strcmp(argv[i],name))return argv[i+1];
    }
    return NULL;
}
static inline int ci_limits_parse(int argc,char **argv,struct ci_limits *limits) {
    if(ci_positive_number(ci_option(argc,argv,"--as-bytes"),&limits->as_bytes)
       ||ci_positive_number(ci_option(argc,argv,"--cpu-seconds"),&limits->cpu_seconds)
       ||ci_positive_number(ci_option(argc,argv,"--wall-seconds"),&limits->wall_seconds)
       ||ci_positive_number(ci_option(argc,argv,"--file-bytes"),&limits->file_bytes))return -1;
    if(limits->as_bytes<16*1024*1024||limits->cpu_seconds>UINT_MAX-5
       ||limits->wall_seconds>UINT_MAX||limits->as_bytes>=(uint64_t)RLIM_INFINITY
       ||limits->file_bytes>=(uint64_t)RLIM_INFINITY)return -1;
    return 0;
}
static inline int ci_set_bounded_limit(int resource,rlim_t soft,rlim_t hard) {
    struct rlimit inherited;
    if(getrlimit(resource,&inherited))return -1;
    if(inherited.rlim_max!=RLIM_INFINITY&&hard>inherited.rlim_max)hard=inherited.rlim_max;
    if(soft>hard)soft=hard;
    struct rlimit requested={soft,hard};return setrlimit(resource,&requested);
}
static inline int ci_expected_parent(pid_t *parent) {
    const char *provided=getenv("COMPACT_PARENT_PID");uint64_t value=0;
    if(provided){
        if(ci_positive_number(provided,&value)||value<=1||value>INT_MAX)return -1;
        *parent=(pid_t)value;
    }else *parent=getppid();
    return *parent>1?0:-1;
}
static inline int ci_parent_death(pid_t expected_parent) {
    if(expected_parent<=1||getppid()!=expected_parent)return -1;
#ifdef __linux__
    if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=expected_parent)return -1;
#endif
    return 0;
}
static inline int ci_timeval_microseconds(const struct timeval *value,uint64_t *out) {
    if(value->tv_sec<0||value->tv_usec<0||value->tv_usec>=1000000
       ||(uint64_t)value->tv_sec>(UINT64_MAX-(uint64_t)value->tv_usec)/1000000)return -1;
    *out=(uint64_t)value->tv_sec*1000000+(uint64_t)value->tv_usec;return 0;
}
static inline int ci_usage_microseconds(const struct rusage *usage,uint64_t *out) {
    uint64_t user=0,system=0;
    if(ci_timeval_microseconds(&usage->ru_utime,&user)||ci_timeval_microseconds(&usage->ru_stime,&system)
       ||user>UINT64_MAX-system)return -1;
    *out=user+system;return 0;
}
static inline int ci_total_cpu_microseconds(uint64_t *out) {
    struct rusage self,children;uint64_t own=0,reaped=0;
    if(getrusage(RUSAGE_SELF,&self)||getrusage(RUSAGE_CHILDREN,&children)
       ||ci_usage_microseconds(&self,&own)||ci_usage_microseconds(&children,&reaped)
       ||own>UINT64_MAX-reaped)return -1;
    *out=own+reaped;return 0;
}
static inline int ci_cpu_effective_seconds(const struct ci_limits *limits,uint64_t *seconds) {
    struct rlimit actual;
    if(!limits->cpu_seconds||limits->cpu_seconds>UINT64_MAX/1000000||getrlimit(RLIMIT_CPU,&actual))return -1;
    *seconds=limits->cpu_seconds;
    if(actual.rlim_cur!=RLIM_INFINITY&&(uint64_t)actual.rlim_cur<*seconds)*seconds=(uint64_t)actual.rlim_cur;
    if(actual.rlim_max!=RLIM_INFINITY&&(uint64_t)actual.rlim_max<*seconds)*seconds=(uint64_t)actual.rlim_max;
    return *seconds?0:-1;
}
static inline int ci_cpu_budget_check(const struct ci_limits *limits) {
    uint64_t seconds=0,used=0;
    return ci_cpu_effective_seconds(limits,&seconds)||ci_total_cpu_microseconds(&used)
        ||used>=seconds*1000000?-1:0;
}
static inline int ci_cpu_budget_remaining(const struct ci_limits *limits,uint64_t *remaining_seconds) {
    uint64_t seconds=0,used=0;
    if(ci_cpu_effective_seconds(limits,&seconds)||ci_total_cpu_microseconds(&used)||used>=seconds*1000000)return -1;
    /* Kernel CPU limits use whole seconds. Rounding down is conservative across
     * repeated forks; unused fractions cannot buy another full child budget. */
    *remaining_seconds=(seconds*1000000-used)/1000000;
    return *remaining_seconds?0:-1;
}
static inline int ci_limits_apply_for_parent(struct ci_limits *limits,pid_t expected_parent) {
    if(ci_parent_death(expected_parent))return -1;
#ifdef __linux__
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -1;
#endif
    if(getpgrp()!=getpid()&&setsid()<0)return -1;
    if(ci_set_bounded_limit(RLIMIT_AS,(rlim_t)limits->as_bytes,(rlim_t)limits->as_bytes)
       ||ci_set_bounded_limit(RLIMIT_CPU,(rlim_t)limits->cpu_seconds,(rlim_t)limits->cpu_seconds+5)
       ||ci_set_bounded_limit(RLIMIT_FSIZE,(rlim_t)limits->file_bytes,(rlim_t)limits->file_bytes)
       ||ci_set_bounded_limit(RLIMIT_CORE,0,0))return -1;
    struct rlimit cpu;
    if(getrlimit(RLIMIT_CPU,&cpu)||cpu.rlim_cur==RLIM_INFINITY||!cpu.rlim_cur)return -1;
    limits->cpu_seconds=(uint64_t)cpu.rlim_cur;
    struct sigaction action;memset(&action,0,sizeof(action));action.sa_handler=ci_limit_alarm;
    if(sigemptyset(&action.sa_mask)||sigaction(SIGALRM,&action,NULL)||sigaction(SIGXCPU,&action,NULL)||sigaction(SIGXFSZ,&action,NULL))return -1;
    alarm((unsigned)limits->wall_seconds);return 0;
}
static inline int ci_limits_apply(struct ci_limits *limits) {
    pid_t expected_parent;
    return ci_expected_parent(&expected_parent)||ci_limits_apply_for_parent(limits,expected_parent)?-1:0;
}
#endif
