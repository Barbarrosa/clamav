/* SPDX-License-Identifier: GPL-2.0-only
 * Public-API measurement harness. Same source links to upstream and retained engines.
 * It reuses the delivered policy callbacks; cache diagnostics never authorize release.
 */
#define _GNU_SOURCE
#include "clamav.h"
static int result_cache_enabled;
static cl_error_t measured_set_num(struct cl_engine *e, enum cl_engine_field f, long long n) {
    if (f == CL_ENGINE_DISABLE_CACHE) n = result_cache_enabled ? 0 : 1;
    return cl_engine_set_num(e, f, n);
}
#define cl_engine_set_num measured_set_num
#define main original_probe_main
#include "../scan_probe.c"
#undef main
#undef cl_engine_set_num
#include <dirent.h>

struct sample { double wall,user,system; long minor,major,inblock,outblock; };
static struct sample sample(void) {
    struct sample s={0};struct rusage u;CHECK(!getrusage(RUSAGE_SELF,&u));
    s.wall=now();s.user=u.ru_utime.tv_sec+u.ru_utime.tv_usec*1e-6;s.system=u.ru_stime.tv_sec+u.ru_stime.tv_usec*1e-6;
    s.minor=u.ru_minflt;s.major=u.ru_majflt;s.inblock=u.ru_inblock;s.outblock=u.ru_oublock;
    return s;
}
static double cpu_elapsed(struct sample a,struct sample b) {
    /* Difference each monotonic counter before summing. Summing the absolute
     * counters first can give a negative rounded result for a zero-CPU scan. */
    return (b.user-a.user)+(b.system-a.system);
}
static void memory_fields(json_object *o) {
    long pss=0,uss=0,anon=0,file=0;
    FILE *f=fopen("/proc/self/smaps_rollup","r");CHECK(f);char line[256];long v;
    while(fgets(line,sizeof line,f)) {
        if(sscanf(line,"Pss: %ld kB",&v)==1)pss=v;
        else if(sscanf(line,"Pss_Anon: %ld kB",&v)==1)anon=v;
        else if(sscanf(line,"Pss_File: %ld kB",&v)==1)file=v;
        else if(sscanf(line,"Private_Clean: %ld kB",&v)==1)uss+=v;
        else if(sscanf(line,"Private_Dirty: %ld kB",&v)==1)uss+=v;
    }fclose(f);CHECK(pss>0);
    num(o,"rss_kib",rss());num(o,"hwm_kib",peak());num(o,"pss_kib",pss);num(o,"uss_kib",uss);
    num(o,"anon_pss_kib",anon);num(o,"file_pss_kib",file);
}
static void measurements(json_object *o,struct sample a,struct sample b) {
    real(o,"wall_seconds",b.wall-a.wall);real(o,"user_cpu_seconds",b.user-a.user);real(o,"system_cpu_seconds",b.system-a.system);
    real(o,"cpu_seconds",cpu_elapsed(a,b));
    real(o,"cpu_percent_one_core",100*cpu_elapsed(a,b)/(b.wall-a.wall));
    num(o,"minor_faults",b.minor-a.minor);num(o,"major_faults",b.major-a.major);
    num(o,"block_read_bytes",512*(b.inblock-a.inblock));num(o,"block_write_bytes",512*(b.outblock-a.outblock));
}
static unsigned long file_pages(const char *path,unsigned long *total) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW);CHECK(fd>=0);struct stat st;CHECK(!fstat(fd,&st)&&S_ISREG(st.st_mode));
    size_t len=(size_t)st.st_size,page=(size_t)sysconf(_SC_PAGESIZE),n=(len+page-1)/page;*total+=n;
    if(!len){close(fd);return 0;}void *map=mmap(NULL,len,PROT_READ,MAP_SHARED,fd,0);CHECK(map!=MAP_FAILED);
    unsigned char *vec=malloc(n);CHECK(vec);CHECK(!mincore(map,len,vec));unsigned long resident=0;
    for(size_t i=0;i<n;i++){resident+=!!(vec[i]&1);}free(vec);munmap(map,len);close(fd);return resident;
}
static void prepare_files(char **paths,size_t count,int warm,const char *label) {
    for(size_t i=0;i<count;i++) {
        int fd=open(paths[i],O_RDONLY|O_NOFOLLOW);CHECK(fd>=0);
        if(warm){char buf[65536];ssize_t n;while((n=read(fd,buf,sizeof buf))>0){}CHECK(n==0);}
        else {CHECK(!fsync(fd));CHECK(!posix_fadvise(fd,0,0,POSIX_FADV_DONTNEED));}
        close(fd);
    }
    unsigned long total=0,resident=0;
    for(size_t i=0;i<count;i++)resident+=file_pages(paths[i],&total);
    json_object *o=json_object_new_object();add(o,"kind","page_cache");add(o,"phase",label);num(o,"requested_warm",warm);
    num(o,"pages",total);num(o,"resident_pages",resident);num(o,"resident_bytes",resident*sysconf(_SC_PAGESIZE));
    real(o,"resident_percent",total?100.0*resident/total:0);emit(o);
    CHECK(warm?resident==total:resident==0);
}
static char **read_paths(const char *path,size_t *count) {
    FILE *f=fopen(path,"r");CHECK(f);char **paths=NULL,*line=NULL;size_t cap=0,len=0;ssize_t n;
    while((n=getline(&line,&len,f))>=0){CHECK(n>0&&line[n-1]=='\n');line[n-1]=0;
        if(*count==cap){cap=cap?cap*2:128;paths=realloc(paths,cap*sizeof(char*));CHECK(paths);}
        paths[(*count)++]=strdup(line);CHECK(paths[*count-1]);}
    free(line);fclose(f);return paths;
}
static void require_unrar_modules(void) {
    FILE *f=fopen("/proc/self/maps","r");CHECK(f);char line[2048];int iface=0,unrar=0;
    while(fgets(line,sizeof line,f)) {
        iface|=strstr(line,"/libclamunrar_iface.so")!=NULL;
        unrar|=strstr(line,"/libclamunrar.so")!=NULL;
    }
    fclose(f);CHECK(iface&&unrar);
}
static void run_batch(struct cl_engine *e,char **paths,size_t count,int metadata,int allmatch,const char *phase,int round) {
    struct sample start=sample();uint64_t bytes=0;unsigned hits=0,held=0,detected=0,failed=0;
    for(size_t i=0;i<count;i++) {
        struct context c={json_object_new_array(),0,0,0};struct stat before,after;char hash[65]={0},after_hash[65]={0};
        struct sample a=sample();int fd=open(paths[i],O_RDONLY|O_NOFOLLOW|O_NONBLOCK);CHECK(fd>=0);CHECK(!fstat(fd,&before)&&S_ISREG(before.st_mode));
        digest_fd(fd,hash);cl_verdict_t verdict=CL_VERDICT_NOTHING_FOUND;const char *name=NULL;char *type=NULL;uint64_t scanned=0;
        struct cl_scan_options opts={0};opts.parse=~0U;
        opts.general=CL_SCAN_GENERAL_HEURISTICS|(allmatch?CL_SCAN_GENERAL_ALLMATCHES:0)|(metadata?CL_SCAN_GENERAL_COLLECT_METADATA:0);
        opts.heuristic=CL_SCAN_HEURISTIC_EXCEEDS_MAX|CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE|CL_SCAN_HEURISTIC_ENCRYPTED_DOC|CL_SCAN_HEURISTIC_BROKEN|CL_SCAN_HEURISTIC_BROKEN_MEDIA;
        struct sample core_start=sample();
        cl_error_t rc=cl_scandesc_ex(fd,paths[i],&verdict,&name,&scanned,e,&opts,&c,NULL,NULL,NULL,NULL,&type);
        struct sample core_end=sample();digest_fd(fd,after_hash);CHECK(!fstat(fd,&after));close(fd);
        if(strcmp(hash,after_hash)||before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec)c.holds|=512;
        if(!type||!allowed(type,c.broad))c.holds|=2;
        const char *outcome=(rc!=CL_SUCCESS&&!(rc==CL_VIRUS&&(verdict==CL_VERDICT_STRONG_INDICATOR||verdict==CL_VERDICT_POTENTIALLY_UNWANTED)))?"failed":c.holds?"held":(verdict==CL_VERDICT_STRONG_INDICATOR||verdict==CL_VERDICT_POTENTIALLY_UNWANTED)?"detected":"clean";
        int pre=0,typed=0;
        for(size_t j=0;j<json_object_array_length(c.events);j++){
            json_object *ev=json_object_array_get_idx(c.events,j),*k=NULL,*d=NULL;
            if(json_object_object_get_ex(ev,"event",&k)&&json_object_object_get_ex(ev,"depth",&d)&&json_object_get_int(d)==0){
                pre+=!strcmp(json_object_get_string(k),"pre_scan");typed+=!strcmp(json_object_get_string(k),"file_type");
            }
        }
        int hit=result_cache_enabled&&!metadata&&typed&&!pre&&!strcmp(outcome,"clean");hits+=hit;
        held+=!strcmp(outcome,"held");detected+=!strcmp(outcome,"detected");failed+=!strcmp(outcome,"failed");bytes+=(uint64_t)before.st_size;
        struct sample b=sample();json_object *o=json_object_new_object();add(o,"kind","scan");add(o,"phase",phase);num(o,"round",round);
        add(o,"path",paths[i]);num(o,"allmatch",allmatch);num(o,"return_code",rc);num(o,"verdict",verdict);add(o,"final_name",name);add(o,"root_type",type);
        add(o,"sha256",hash);add(o,"after_sha256",after_hash);num(o,"hold_bits",c.holds);add(o,"candidate_outcome",outcome);num(o,"scanned_bytes",scanned);
        num(o,"input_bytes",before.st_size);num(o,"root_cache_hit",hit);num(o,"root_prescan_callbacks",pre);measurements(o,a,b);
        real(o,"engine_scan_wall_seconds",core_end.wall-core_start.wall);real(o,"engine_scan_cpu_seconds",cpu_elapsed(core_start,core_end));
        json_object_object_add(o,"events",c.events);emit(o);free(type);
    }
    struct sample end=sample();json_object *o=json_object_new_object();add(o,"kind","batch");add(o,"phase",phase);num(o,"round",round);
    num(o,"files",count);num(o,"bytes",bytes);num(o,"root_cache_hits",hits);num(o,"held",held);num(o,"detected",detected);num(o,"failed",failed);
    measurements(o,start,end);memory_fields(o);emit(o);
}
#ifndef PERFORMANCE_PROBE_NO_MAIN
int main(int argc,char **argv) {
    if(argc!=10){fprintf(stderr,"usage: %s DB CERTS SKIP|- LIST CASE DBLIST CACHE_STATE REPEATS ALLMATCH\n",argv[0]);return 2;}
    const char *mode=argv[5];int diagnostic=!strcmp(mode,"result-cache");int repeats=atoi(argv[8]),allmatch=atoi(argv[9]);CHECK(repeats>0&&repeats<101);
    CHECK(!strcmp(mode,"scan")||diagnostic||!strcmp(mode,"reload")||!strcmp(mode,"update"));
    result_cache_enabled=diagnostic;
    size_t nd=0,nf=0;char **dbfiles=read_paths(argv[6],&nd),**files=read_paths(argv[4],&nf);
    CHECK(!strcmp(argv[7],"empty")||!strcmp(argv[7],"hydrated"));
    prepare_files(dbfiles,nd,!strcmp(argv[7],"hydrated"),"before_load");
    CHECK(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);require_unrar_modules();struct sample a=sample();struct cl_engine *e=load_engine(argv[1],argv[2],argv[3],"engine");struct sample b=sample();
    json_object *o=json_object_new_object();add(o,"kind","startup");add(o,"case",mode);measurements(o,a,b);memory_fields(o);int err=0;
    num(o,"result_cache_enabled",result_cache_enabled);num(o,"cache_capacity",cl_engine_get_num(e,CL_ENGINE_CACHE_SIZE,&err));num(o,"metadata",!diagnostic);num(o,"allmatch",allmatch);num(o,"unrar_modules_verified",1);emit(o);
    if(!strcmp(mode,"reload")||!strcmp(mode,"update")) {
        a=sample();struct cl_engine *replacement=load_engine(argv[1],argv[2],argv[3],"reload_overlap");b=sample();
        o=json_object_new_object();add(o,"kind","reload");measurements(o,a,b);memory_fields(o);emit(o);
        if(!strcmp(mode,"update")) {
            const char *lib=getenv("BENCH_FRESHCLAM_LIBRARY");CHECK(lib);void *h=dlopen(lib,RTLD_NOW|RTLD_LOCAL);CHECK(h);
            int(*test)(const char*,int,char*)=(int(*)(const char*,int,char*))dlsym(h,"fc_test_database_ex");CHECK(test);
            const char *input=getenv("BENCH_FRESHCLAM_DATABASE");CHECK(input);a=sample();int rc=test(input,1,argv[2]);b=sample();
            o=json_object_new_object();add(o,"kind","update_validation");add(o,"database",input);num(o,"return_code",rc);measurements(o,a,b);memory_fields(o);emit(o);CHECK(!rc);dlclose(h);
        }
        cl_engine_free(replacement);
    } else {
        prepare_files(files,nf,diagnostic,"before_first_scan");
        run_batch(e,files,nf,!diagnostic,allmatch,diagnostic?"result_cache_empty":"file_cache_empty",0);
        for(int round=1;round<=repeats;round++) {
            prepare_files(files,nf,1,"before_hydrated_scan");
            run_batch(e,files,nf,!diagnostic,allmatch,diagnostic?"result_cache_hydrated":"file_cache_hydrated",round);
        }
    }
    for(size_t i=0;i<nd;i++){free(dbfiles[i]);}for(size_t i=0;i<nf;i++){free(files[i]);}free(dbfiles);free(files);cl_engine_free(e);return 0;
}
#endif
