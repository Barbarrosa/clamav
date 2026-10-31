/* SPDX-License-Identifier: GPL-2.0-only
 * ClamAV 1.4 compatibility adapter, legacy public API only. NEVER authorizes reduced release.
 * CLI: db certs skip.tsv|- files.txt repeats broad action overlap [both|first|all]
 */
#define _GNU_SOURCE
#include "clamav.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <dlfcn.h>
#include <limits.h>

struct skiplist { char *data; size_t bytes, count; char **keys; unsigned long skipped, calls; };
struct context { json_object *events; unsigned holds; int broad, action; char *root_type; };
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static long rss(void){FILE *f=fopen("/proc/self/status","r");char s[256];long n=-1;if(!f)return n;while(fgets(s,sizeof s,f))if(sscanf(s,"VmRSS: %ld kB",&n)==1)break;fclose(f);return n;}
static long peak(void){struct rusage u;getrusage(RUSAGE_SELF,&u);return u.ru_maxrss;}
static void fail(const char *msg){fprintf(stderr,"subset-probe: %s\n",msg);exit(2);}
#define CHECK(x) do {if(!(x)) fail(#x);}while(0)
static void add(json_object *o,const char *k,const char *v){json_object_object_add(o,k,v?json_object_new_string(v):NULL);}
static void num(json_object *o,const char *k,int64_t v){json_object_object_add(o,k,json_object_new_int64(v));}
static void real(json_object *o,const char *k,double v){json_object_object_add(o,k,json_object_new_double(v));}
static void emit(json_object *o){puts(json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN));json_object_put(o);fflush(stdout);}
static int keycmp(const char *fmt,const char *name,const char *key){size_t len=strlen(fmt);int c=strncmp(fmt,key,len);if(c)return c;if(key[len]!='\t')return -1;return strcmp(name,key+len+1);}
static int contains(struct skiplist *s,const char *fmt,const char *name){size_t l=0,r=s->count;while(l<r){size_t m=l+(r-l)/2;int c=keycmp(fmt,name,s->keys[m]);if(c==0)return 1;if(c<0)r=m;else l=m+1;}return 0;}
static int sigload(const char *type,const char *name,unsigned custom,void *v){(void)custom;struct skiplist*s=v;s->calls++;int yes=0;
    if(!strcmp(type,"ndb")||!strcmp(type,"ldb"))yes=contains(s,type,name);
    else if(!strcmp(type,"mdb")||!strcmp(type,"msb")||!strcmp(type,"imp"))yes=contains(s,type,"*");
    s->skipped+=yes;return yes;
}
static void open_skips(struct skiplist *s,const char *path){memset(s,0,sizeof *s);if(!strcmp(path,"-"))return;
    int fd=open(path,O_RDONLY|O_NOFOLLOW);CHECK(fd>=0);struct stat st;CHECK(!fstat(fd,&st)&&S_ISREG(st.st_mode));
    CHECK(st.st_size>=0 && st.st_size<512*1024*1024);s->bytes=(size_t)st.st_size;
    if(!s->bytes){close(fd);return;}
    s->data=mmap(NULL,s->bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);close(fd);CHECK(s->data!=MAP_FAILED);
    CHECK(s->data[s->bytes-1]=='\n');for(size_t i=0;i<s->bytes;i++){CHECK(s->data[i]);if(s->data[i]=='\n')s->count++;}
    s->keys=calloc(s->count,sizeof(char*));CHECK(s->keys);size_t k=0;char*start=s->data;
    for(size_t i=0;i<s->bytes;i++)if(s->data[i]=='\n'){s->data[i]=0;CHECK(strchr(start,'\t'));s->keys[k++]=start;start=s->data+i+1;}
    for(size_t i=1;i<s->count;i++)CHECK(strcmp(s->keys[i-1],s->keys[i])<0);
}
static void close_skips(struct skiplist*s){free(s->keys);if(s->bytes)munmap(s->data,s->bytes);s->keys=NULL;s->data=NULL;}
static int allowed(const char*t,int broad){
    const char*basic[]={"CL_TYPE_PDF","CL_TYPE_JPEG","CL_TYPE_PNG",NULL};
    const char*more[]={"CL_TYPE_MSOLE2","CL_TYPE_MSOXML","CL_TYPE_OOXML_WORD","CL_TYPE_OOXML_PPT","CL_TYPE_OOXML_XL","CL_TYPE_OOXML_HWP","CL_TYPE_MAIL","CL_TYPE_ZIP","CL_TYPE_RAR","CL_TYPE_7Z","CL_TYPE_RTF",NULL};
    for(int i=0;basic[i];i++)if(!strcmp(t,basic[i]))return 1;
    if(broad)for(int i=0;more[i];i++)if(!strcmp(t,more[i]))return 1;
    return 0;
}
static int policy_alert(const char*n){return n&&(strstr(n,"Heuristics.Limits.")||strstr(n,"Heuristics.Encrypted.")||strstr(n,"Heuristics.Broken."));}
static cl_error_t inspection(int fd,const char *t,const char **ancestors,size_t parent_size,const char *filename,size_t size,const char *buffer,uint32_t depth,uint32_t attributes,void *v){
    (void)fd;(void)ancestors;(void)parent_size;(void)filename;(void)size;(void)buffer;
    struct context *c=v;if(!t){c->holds|=64;return CL_SUCCESS;}
    if(depth==0 && !c->root_type){c->root_type=strdup(t);CHECK(c->root_type);}
    if(!strcmp(t,"CL_TYPE_MSEXE")){
#ifdef SUBSET_BOUNDARY_TEST
        if(!getenv("SUBSET_TEST_DISABLE_PE_HOLD"))
#endif
        c->holds|=1;
    }
    if(depth==0&&!allowed(t,c->broad))c->holds|=2;
    if(depth>0&&(!strcmp(t,"CL_TYPE_ANY")||!strcmp(t,"CL_TYPE_OTHER")||!strcmp(t,"CL_TYPE_ERROR")))c->holds|=4;
    json_object *o=json_object_new_object();add(o,"event","legacy_file_inspection");add(o,"type",t);num(o,"depth",depth);num(o,"attributes",attributes);json_object_object_add(o,"object_id",NULL);add(o,"name",NULL);json_object_array_add(c->events,o);
    return CL_SUCCESS;
}
static void legacy(int fd,const char*n,void*v){(void)fd;struct context*c=v;json_object*o=json_object_new_object();add(o,"event","legacy_virus");add(o,"name",n);json_object_array_add(c->events,o);if(policy_alert(n))c->holds|=8;}
static cl_error_t meta(const char*t,unsigned long fs,const char*n,unsigned long size,int encrypted,unsigned pos,void*v){(void)t;(void)fs;(void)n;(void)size;(void)pos;if(encrypted)((struct context*)v)->holds|=16;return CL_SUCCESS;}
static void inspect_json(json_object*j,struct context*c){if(!j)return;
    if(json_object_is_type(j,json_type_object)){json_object_object_foreach(j,k,val){
        if(!strcmp(k,"ParseErrors")&&((json_object_is_type(val,json_type_array)&&json_object_array_length(val)>0)||(!json_object_is_type(val,json_type_array)&&json_object_get_boolean(val))))c->holds|=32;
        if(!strcmp(k,"Encrypted")&&json_object_get_boolean(val))c->holds|=16;
        inspect_json(val,c);
    }}else if(json_object_is_type(j,json_type_array)){for(size_t i=0;i<json_object_array_length(j);i++)inspect_json(json_object_array_get_idx(j,i),c);}}
static int props(const char*s,int rc,void*v){(void)rc;json_object*j=json_tokener_parse(s);if(!j)((struct context*)v)->holds|=64;else{inspect_json(j,v);json_object_put(j);}return 0;}
static struct cl_engine*load_engine(const char*db,const char*certs,const char*skips,const char*label){
    struct skiplist s;open_skips(&s,skips);size_t keybytes=s.bytes+s.count*sizeof(char*);double t=now();
    struct cl_engine*e=cl_engine_new();CHECK(e);(void)certs; /* 1.4 verifies CVD signatures with its built-in verifier. */
    CHECK(cl_engine_set_num(e,CL_ENGINE_DISABLE_CACHE,1)==CL_SUCCESS);
    #ifdef SUBSET_BOUNDARY_TEST
    if(getenv("SUBSET_TEST_MAX_EMBEDDED_PE")){CHECK(cl_engine_set_num(e,CL_ENGINE_MAX_EMBEDDEDPE,atoll(getenv("SUBSET_TEST_MAX_EMBEDDED_PE")))==CL_SUCCESS);}
#endif
    if(getenv("SUBSET_TEST_MAX_FILESIZE")){CHECK(cl_engine_set_num(e,CL_ENGINE_MAX_FILESIZE,atoll(getenv("SUBSET_TEST_MAX_FILESIZE")))==CL_SUCCESS);}
    if(s.count)cl_engine_set_clcb_sigload(e,sigload,&s);
    unsigned n=0;CHECK(cl_load(db,e,&n,CL_DB_STDOPT)==CL_SUCCESS);double loaded=now();
    cl_engine_set_clcb_sigload(e,NULL,NULL);close_skips(&s);
    CHECK(cl_engine_compile(e)==CL_SUCCESS);double compiled=now();
    json_object*o=json_object_new_object();add(o,"kind",label);num(o,"signatures",n);num(o,"skipped",s.skipped);num(o,"sigload_calls",s.calls);num(o,"selector_mapping_and_index_bytes",keybytes);real(o,"load_seconds",loaded-t);real(o,"compile_seconds",compiled-loaded);num(o,"compiled_rss_kib",rss());num(o,"construction_hwm_kib",peak());int err=0;num(o,"max_file_bytes",cl_engine_get_num(e,CL_ENGINE_MAX_FILESIZE,&err));num(o,"max_scan_bytes",cl_engine_get_num(e,CL_ENGINE_MAX_SCANSIZE,&err));num(o,"max_recursion",cl_engine_get_num(e,CL_ENGINE_MAX_RECURSION,&err));num(o,"max_files",cl_engine_get_num(e,CL_ENGINE_MAX_FILES,&err));emit(o);
    cl_engine_set_clcb_file_inspection(e,inspection);cl_engine_set_clcb_virus_found(e,legacy);cl_engine_set_clcb_meta(e,meta);cl_engine_set_clcb_file_props(e,props);return e;
}
static void digest_fd(int fd,char out[65]){EVP_MD_CTX*h=EVP_MD_CTX_new();CHECK(h);CHECK(EVP_DigestInit_ex(h,EVP_sha256(),NULL));unsigned char b[65536],d[32];unsigned n;off_t off=0;ssize_t got;
    while((got=pread(fd,b,sizeof b,off))>0){CHECK(EVP_DigestUpdate(h,b,(size_t)got));off+=got;}CHECK(got==0);CHECK(EVP_DigestFinal_ex(h,d,&n));EVP_MD_CTX_free(h);for(unsigned i=0;i<32;i++)sprintf(out+2*i,"%02x",d[i]);}
static void runtime_identity(void){
    Dl_info info;char resolved[PATH_MAX],hash[65];CHECK(dladdr((void*)cl_init,&info)&&info.dli_fname);
    CHECK(realpath(info.dli_fname,resolved));int fd=open(resolved,O_RDONLY|O_NOFOLLOW);CHECK(fd>=0);digest_fd(fd,hash);close(fd);
    FILE *maps=fopen("/proc/self/maps","r");CHECK(maps);char line[4096];int iface=0,unrar=0;
    while(fgets(line,sizeof line,maps)){iface|=strstr(line,"/libclamunrar_iface.so")!=NULL;unrar|=strstr(line,"/libclamunrar.so")!=NULL;}fclose(maps);
    json_object *o=json_object_new_object();add(o,"kind","runtime");add(o,"engine_path",resolved);add(o,"engine_sha256",hash);add(o,"engine_version",cl_retver());add(o,"scan_api","legacy-1.4");num(o,"unrar_modules_verified",iface&&unrar);emit(o);
}
#ifdef SUBSET_BOUNDARY_TEST
/* Independent instrumented engine observes holds at matcher entry. Test-only. */
void subset_boundary_witness(void *v,const char *site){
    struct context *c=v;json_object *o=json_object_new_object();
    add(o,"event","boundary_witness");add(o,"site",site);num(o,"hold_bits_before",c->holds);json_object_array_add(c->events,o);
}
#endif
int main(int argc,char**argv){
    if(argc!=9&&argc!=10){fprintf(stderr,"usage: %s db certs skips|- filelist repeats broad action overlap [both|first|all]\n",argv[0]);return 2;}
    unsigned first_mode=0,end_mode=2;
    if(argc==10){
        if(!strcmp(argv[9],"first"))end_mode=1;
        else if(!strcmp(argv[9],"all"))first_mode=1;
        else if(strcmp(argv[9],"both"))fail("invalid scan mode (use both, first or all)");
    }
    CHECK(atoi(argv[7])==0); /* legacy API cannot emulate modern alert-return overrides */
    CHECK(cl_init(CL_INIT_DEFAULT)==CL_SUCCESS);struct cl_engine*e=load_engine(argv[1],argv[2],argv[3],"engine");
    struct cl_engine*old=NULL;
    if(atoi(argv[8])){old=e;e=load_engine(argv[1],argv[2],argv[3],"reload_overlap");}
    if(getenv("SUBSET_FRESHCLAM_LIBRARY")){
        void*handle=dlopen(getenv("SUBSET_FRESHCLAM_LIBRARY"),RTLD_NOW|RTLD_LOCAL);CHECK(handle);
        int(*test_db)(const char*,int,char*)=(int(*)(const char*,int,char*))dlsym(handle,"fc_test_database_ex");CHECK(test_db);
        const char*path=getenv("SUBSET_FRESHCLAM_DATABASE");if(!path)path=argv[1];double start=now();
        int result=test_db(path,1,argv[2]);json_object*o=json_object_new_object();add(o,"kind","freshclam_load_test_overlap");add(o,"tested_path",path);num(o,"return_code",result);real(o,"seconds",now()-start);num(o,"hwm_kib",peak());num(o,"rss_after_helper_free_kib",rss());emit(o);CHECK(result==0);dlclose(handle);
    }
    if(old){cl_engine_free(old);}
    runtime_identity();
    FILE*f=fopen(argv[4],"r");CHECK(f);char**paths=NULL;size_t npaths=0,cap=0;char*line=NULL;size_t len=0;ssize_t got;
    while((got=getline(&line,&len,f))>=0){CHECK(got>0&&line[got-1]=='\n');line[got-1]=0;if(npaths==cap){cap=cap?cap*2:128;paths=realloc(paths,cap*sizeof(char*));CHECK(paths);}paths[npaths++]=strdup(line);CHECK(paths[npaths-1]);}free(line);fclose(f);
    const char**borrowed=calloc(npaths*2+1,sizeof(char*));char**copies=calloc(npaths*2+1,sizeof(char*));CHECK(borrowed&&copies);size_t saved=0;
    unsigned rounds=(unsigned)atoi(argv[5]);CHECK(rounds>0&&rounds<10001);
    for(unsigned round=0;round<rounds;round++)for(unsigned mode=first_mode;mode<end_mode;mode++){
        double batch=now();
        for(size_t i=0;i<npaths;i++){
            struct context c={.events=json_object_new_array(),.broad=atoi(argv[6]),.action=atoi(argv[7])};struct stat before,after;char hash[65]={0},hash_after[65]={0};
            int fd=open(paths[i],O_RDONLY|O_NOFOLLOW|O_NONBLOCK);cl_error_t rc=CL_EOPEN;const char*name=NULL;char*type=NULL;uint64_t scanned=0;double start=now();
            if(fd>=0){if(fstat(fd,&before)||!S_ISREG(before.st_mode)){c.holds|=512;rc=CL_ESTAT;}else{
                digest_fd(fd,hash);struct cl_scan_options opts={0};opts.parse=~0U;opts.general=CL_SCAN_GENERAL_HEURISTICS|CL_SCAN_GENERAL_COLLECT_METADATA|(mode?CL_SCAN_GENERAL_ALLMATCHES:0);opts.heuristic=CL_SCAN_HEURISTIC_EXCEEDS_MAX|CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE|CL_SCAN_HEURISTIC_ENCRYPTED_DOC|CL_SCAN_HEURISTIC_BROKEN|CL_SCAN_HEURISTIC_BROKEN_MEDIA;
                unsigned long legacy_scanned=0;
                rc=cl_scandesc_callback(fd,paths[i],&name,&legacy_scanned,e,&opts,&c);
                scanned=(uint64_t)legacy_scanned*CL_COUNT_PRECISION;type=c.root_type;c.root_type=NULL;
                digest_fd(fd,hash_after);CHECK(!fstat(fd,&after));if(strcmp(hash,hash_after)||before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec)c.holds|=512;
                if(!type||!allowed(type,c.broad))c.holds|=2;
            }close(fd);}
            const char*outcome=(rc!=CL_SUCCESS&&rc!=CL_VIRUS)?"failed":c.holds?"held":rc==CL_VIRUS?"detected":"clean";
            json_object*o=json_object_new_object();add(o,"kind","scan");add(o,"path",paths[i]);num(o,"round",round);num(o,"allmatch",mode);num(o,"return_code",rc);json_object_object_add(o,"verdict",NULL);add(o,"verdict_source","legacy-return-code; severity not exposed");num(o,"scanned_bytes_precision",CL_COUNT_PRECISION);add(o,"final_name",name);add(o,"root_type",type);add(o,"sha256",hash);add(o,"after_sha256",hash_after);num(o,"hold_bits",c.holds);add(o,"candidate_outcome",outcome);
            /* Detection order may differ. Parser completeness still cannot authorize reduced release. */
            add(o,"outcome",(!strcmp(argv[3],"-")||strcmp(outcome,"clean"))?outcome:"held");
            add(o,"release_blocker",strcmp(argv[3],"-")?"parser-completeness-unproven":NULL);num(o,"scanned_bytes",scanned);real(o,"seconds",now()-start);json_object_object_add(o,"events",c.events);emit(o);free(type);
            if(round==0&&name){borrowed[saved]=name;copies[saved]=strdup(name);CHECK(copies[saved]);saved++;}
        }
        json_object*o=json_object_new_object();add(o,"kind","batch");num(o,"round",round);num(o,"allmatch",mode);real(o,"seconds",now()-batch);num(o,"rss_kib",rss());num(o,"scan_hwm_kib",peak());emit(o);
    }
    for(size_t i=0;i<saved;i++){CHECK(!strcmp(borrowed[i],copies[i]));free(copies[i]);}free(borrowed);free(copies);
    for(size_t i=0;i<npaths;i++){free(paths[i]);}
    free(paths);cl_engine_free(e);return 0;
}
