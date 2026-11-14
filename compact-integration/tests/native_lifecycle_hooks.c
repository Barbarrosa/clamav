/* SPDX-License-Identifier: GPL-2.0-only
 * Standalone diagnostic LD_PRELOAD hooks, never installed or accepted through
 * the production PHP/gateway environment. Native parsing/authentication stays
 * enabled; these hooks only observe module loading and delay I/O/cleanup.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void record(const char *event) {
    const char *name=getenv("TEST_NATIVE_AUDIT");if(!name)return;
    int fd=open(name,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);if(fd<0)_exit(130);
    if(write(fd,event,strlen(event))<0||write(fd,"\n",1)<0)_exit(130);
    close(fd);
}
static void gate(const char *variable) {
    const char *name=getenv(variable);if(!name)return;
    for(unsigned i=0;i<3000;i++){
        if(access(name,F_OK)==0)return;
        struct timespec delay={0,10000000};nanosleep(&delay,NULL);
    }
    _exit(131);
}
static void cleanup(void) {
    if(!getenv("TEST_NATIVE_HOLD"))return;
    record("atexit-enter");gate("TEST_NATIVE_EXIT_GATE");
}
__attribute__((constructor)) static void initialize(void) {
    if(atexit(cleanup))_exit(132);
}
void *dlopen(const char *filename,int flags) {
    void *(*original)(const char *,int)=dlsym(RTLD_NEXT,"dlopen");if(!original)_exit(133);
    if(filename&&strstr(filename,"libclamunrar"))record("module-bootstrap");
    return original(filename,flags);
}
int cl_engine_free(void *engine) {
    int (*original)(void *)=dlsym(RTLD_NEXT,"cl_engine_free");if(!original)_exit(133);
    if(getenv("TEST_NATIVE_HOLD")){record("free-enter");gate("TEST_NATIVE_FREE_GATE");}
    return original(engine);
}
int fgetc(FILE *stream) {
    static int waiting;
    int (*original)(FILE *)=dlsym(RTLD_NEXT,"fgetc");if(!original)_exit(133);
    if(stream==stdin&&!waiting){waiting=1;record("stdin-wait");}
    return original(stream);
}
static void slow_input(int fd,int64_t offset) {
    static unsigned delays;
    int wall_delay=getenv("TEST_NATIVE_SLOW")!=NULL,cpu_delay=getenv("TEST_NATIVE_CPU")!=NULL;
    if((!wall_delay&&!cpu_delay)||offset)return;
    char descriptor[64],target[4096];snprintf(descriptor,sizeof(descriptor),"/proc/self/fd/%d",fd);
    ssize_t length=readlink(descriptor,target,sizeof(target)-1);if(length<0)return;target[length]=0;
    const char suffix[]="/slow-input.pdf";size_t n=strlen(target);
    if(n<sizeof(suffix)-1||strcmp(target+n-(sizeof(suffix)-1),suffix))return;
    if(wall_delay&&delays<2){delays++;struct timespec delay={0,700000000};nanosleep(&delay,NULL);}
    if(cpu_delay){
        struct timespec start,now;if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&start))_exit(134);
        do{
            if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&now))_exit(134);
        }while((double)(now.tv_sec-start.tv_sec)+(double)(now.tv_nsec-start.tv_nsec)/1e9<0.15);
    }
}
ssize_t pread(int fd,void *buffer,size_t length,off_t offset) {
    ssize_t (*original)(int,void *,size_t,off_t)=dlsym(RTLD_NEXT,"pread");if(!original)_exit(133);
    slow_input(fd,offset);return original(fd,buffer,length,offset);
}
ssize_t pread64(int fd,void *buffer,size_t length,off64_t offset) {
    ssize_t (*original)(int,void *,size_t,off64_t)=dlsym(RTLD_NEXT,"pread64");if(!original)_exit(133);
    slow_input(fd,offset);return original(fd,buffer,length,offset);
}
