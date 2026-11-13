/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "../native/limits.h"
#include <assert.h>
#include <sys/wait.h>
int main(void) {
    uint64_t n;
    assert(ci_positive_number("0",&n));assert(ci_positive_number("-1",&n));
    assert(ci_positive_number("1e5",&n));assert(ci_positive_number("18446744073709551616",&n));
    assert(!ci_positive_number("671088640",&n)&&n==671088640);
    char *args[]={"test","scan","--as-bytes","671088640","--cpu-seconds","2","--wall-seconds","1","--file-bytes","104857600",NULL};
    struct ci_limits limits;
    assert(!ci_limits_parse(10,args,&limits));
    int pipefd[2];assert(!pipe(pipefd));pid_t pid=fork();assert(pid>=0);
    if(!pid){close(pipefd[0]);assert(dup2(pipefd[1],STDOUT_FILENO)>=0);close(pipefd[1]);
        struct rlimit inherited_cpu={2,2};assert(!setrlimit(RLIMIT_CPU,&inherited_cpu));
        assert(!ci_limits_apply(&limits));struct rlimit actual;assert(!getrlimit(RLIMIT_AS,&actual));assert(actual.rlim_cur==671088640);
        assert(!getrlimit(RLIMIT_CPU,&actual));assert(actual.rlim_cur==2&&actual.rlim_max==2);
        for(;;)pause();}
    close(pipefd[1]);char buf[1024]={0};ssize_t count=read(pipefd[0],buf,sizeof(buf)-1);assert(count>0);
    assert(strstr(buf,"native-resource-limit"));assert(strstr(buf,"\"completed\":false"));close(pipefd[0]);
    int status;assert(waitpid(pid,&status,0)==pid);assert(WIFEXITED(status)&&WEXITSTATUS(status)==2);
    return 0;
}
