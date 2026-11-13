/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CI_LIMITS_H
#define CI_LIMITS_H
#include <errno.h>
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
static void ci_limit_alarm(int signal_number) {
    (void)signal_number;
    static const char output[] = "{\"protocol\":1,\"status\":\"failed\",\"completed\":false,\"applicability_proven\":false,\"coverage_qualified\":false,\"sha256\":null,\"size\":0,\"engine_version\":null,\"generation_id\":null,\"requested_profile\":null,\"effective_profile\":null,\"findings\":[],\"reason_codes\":[\"native-resource-limit\"]}\n";
    (void)write(STDOUT_FILENO,output,sizeof(output)-1);
    _exit(2);
}
static int ci_positive_number(const char *s,uint64_t *out) {
    if(!s||!*s)return -1;
    for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return -1;
    char *end=NULL;errno=0;unsigned long long n=strtoull(s,&end,10);
    if(errno||!end||*end||!n)return -1;
    *out=(uint64_t)n;return 0;
}
static const char *ci_option(int argc,char **argv,const char *name) {
    for(int i=2;i+1<argc;i++) {
        if(!strcmp(argv[i],name))return argv[i+1];
    }
    return NULL;
}
static int ci_limits_parse(int argc,char **argv,struct ci_limits *limits) {
    if(ci_positive_number(ci_option(argc,argv,"--as-bytes"),&limits->as_bytes)
       ||ci_positive_number(ci_option(argc,argv,"--cpu-seconds"),&limits->cpu_seconds)
       ||ci_positive_number(ci_option(argc,argv,"--wall-seconds"),&limits->wall_seconds)
       ||ci_positive_number(ci_option(argc,argv,"--file-bytes"),&limits->file_bytes))return -1;
    if(limits->as_bytes<16*1024*1024||limits->cpu_seconds>UINT_MAX-5
       ||limits->wall_seconds>UINT_MAX||limits->as_bytes>=(uint64_t)RLIM_INFINITY
       ||limits->file_bytes>=(uint64_t)RLIM_INFINITY)return -1;
    return 0;
}
static int ci_set_bounded_limit(int resource,rlim_t soft,rlim_t hard) {
    struct rlimit inherited;
    if(getrlimit(resource,&inherited))return -1;
    if(inherited.rlim_max!=RLIM_INFINITY&&hard>inherited.rlim_max)hard=inherited.rlim_max;
    if(soft>hard)soft=hard;
    struct rlimit requested={soft,hard};return setrlimit(resource,&requested);
}
static int ci_limits_apply(const struct ci_limits *limits) {
    pid_t parent=getppid();
    if(parent<=1)return -1;
#ifdef __linux__
    if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)return -1;
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -1;
#endif
    if(getpgrp()!=getpid()&&setsid()<0)return -1;
    if(ci_set_bounded_limit(RLIMIT_AS,(rlim_t)limits->as_bytes,(rlim_t)limits->as_bytes)
       ||ci_set_bounded_limit(RLIMIT_CPU,(rlim_t)limits->cpu_seconds,(rlim_t)limits->cpu_seconds+5)
       ||ci_set_bounded_limit(RLIMIT_FSIZE,(rlim_t)limits->file_bytes,(rlim_t)limits->file_bytes)
       ||ci_set_bounded_limit(RLIMIT_CORE,0,0))return -1;
    struct sigaction action;memset(&action,0,sizeof(action));action.sa_handler=ci_limit_alarm;
    if(sigemptyset(&action.sa_mask)||sigaction(SIGALRM,&action,NULL)||sigaction(SIGXCPU,&action,NULL)||sigaction(SIGXFSZ,&action,NULL))return -1;
    alarm((unsigned)limits->wall_seconds);return 0;
}
#endif
