/* SPDX-License-Identifier: GPL-2.0-only
 * Included by scan.c: the production selector and fixed engine options are the
 * single authority. No alternative signature grammar is implemented here.
 * Each successful batch compiles all retained rules and whole selected native
 * callback occurrences. Aggregate counters are conservative upper bounds, not
 * a claim that a combined omitted PE trie has been materialized.
 */
#include <sys/wait.h>
#include <time.h>

struct ci_batch_result {
    uint64_t events, eligible, included, counters[CL_SUBSET_VALIDATION_COUNTERS];
    uint64_t peak_rss_kib;
    unsigned char transcript[32];
    int native_status, success, resource_failure;
};
struct ci_batch_context {
    struct skips *skips;
    EVP_MD_CTX *digest;
    uint64_t start, count;
    struct ci_batch_result result;
    bool error;
};
static bool ci_hash_u64(EVP_MD_CTX *digest,uint64_t value) {
    unsigned char bytes[8];
    for(unsigned i=0;i<8;i++)bytes[i]=(unsigned char)(value>>(8*i));
    return EVP_DigestUpdate(digest,bytes,sizeof(bytes))==1;
}
static int ci_batch_callback(const char *format,const char *name,unsigned custom,void *opaque) {
    struct ci_batch_context *context=opaque;
    bool eligible=sigload(format,name,custom,context->skips)!=0;
    size_t format_len=strlen(format),name_len=strlen(name);
    if(context->result.events==UINT64_MAX||context->result.eligible==UINT64_MAX
       ||!ci_hash_u64(context->digest,format_len)
       ||EVP_DigestUpdate(context->digest,format,format_len)!=1
       ||!ci_hash_u64(context->digest,name_len)
       ||EVP_DigestUpdate(context->digest,name,name_len)!=1
       ||!ci_hash_u64(context->digest,custom)||!ci_hash_u64(context->digest,eligible))context->error=true;
    context->result.events++;
    if(!eligible)return 0;
    uint64_t ordinal=context->result.eligible++;
    bool include=ordinal>=context->start&&ordinal-context->start<context->count;
    if(include)context->result.included++;
    return !include;
}
/* Stock validation's PUA/enhanced superset is loaded here, with bytecode always
 * enabled. The actual scanner's STDOPT engine is compiled again by self-test. */
static void ci_batch_child(const char *generation,const char *certs,struct skips *skips,
                           uint64_t start,uint64_t count,int pipefd,const struct ci_limits *limits) {
    struct ci_batch_context context={0};context.skips=skips;context.start=start;context.count=count;
    int nullfd=open("/dev/null",O_WRONLY|O_CLOEXEC);
    if(nullfd<0||dup2(nullfd,STDOUT_FILENO)<0)_exit(120);
    close(nullfd);
    if(ci_limits_apply(limits))_exit(120);
    context.digest=EVP_MD_CTX_new();
    struct cl_engine *engine=cl_engine_new();
    char databases[PATH_MAX];
    cl_error_t status=CL_EMEM;unsigned loaded=0,digest_len=0;
    if(!context.digest||!engine)goto done;
    if(EVP_DigestInit_ex(context.digest,EVP_sha256(),NULL)!=1)goto done;
    if(snprintf(databases,sizeof(databases),"%s/databases",generation)>=(int)sizeof(databases)){status=CL_EARG;goto done;}
    if(cl_engine_set_str(engine,CL_ENGINE_CVDCERTSDIR,certs)!=CL_SUCCESS
       ||cl_engine_set_num(engine,CL_ENGINE_DISABLE_CACHE,1)!=CL_SUCCESS
       ||cl_engine_set_num(engine,CL_ENGINE_MAX_FILESIZE,CI_MAX_FILE)!=CL_SUCCESS
       ||cl_engine_set_num(engine,CL_ENGINE_MAX_SCANSIZE,CI_MAX_SCAN)!=CL_SUCCESS
       ||cl_engine_set_num(engine,CL_ENGINE_MAX_FILES,10000)!=CL_SUCCESS
       ||cl_engine_set_num(engine,CL_ENGINE_MAX_RECURSION,17)!=CL_SUCCESS
       ||cl_engine_set_num(engine,CL_ENGINE_MAX_SCANTIME,90000)!=CL_SUCCESS){status=CL_EARG;goto done;}
    cl_engine_set_clcb_sigload(engine,ci_batch_callback,&context);
    errno=0;
    status=cl_load(databases,engine,&loaded,CL_DB_STDOPT|CL_DB_PUA|CL_DB_ENHANCED);
    if(status!=CL_SUCCESS||!loaded||context.error)goto done;
    cl_engine_set_clcb_sigload(engine,NULL,NULL);
    status=cl_engine_compile(engine);
    if(status!=CL_SUCCESS)goto done;
    status=cl_subset_validation_stats(engine,context.result.counters);
    if(status!=CL_SUCCESS)goto done;
    context.result.counters[19]=loaded;
    if(EVP_DigestFinal_ex(context.digest,context.result.transcript,&digest_len)!=1||digest_len!=32){status=CL_ESTATE;goto done;}
    context.result.success=1;
done:
    context.result.native_status=status;
    context.result.resource_failure=status==CL_EMEM||(status!=CL_SUCCESS&&errno==ENOMEM);
    /* Freeing can itself fail after a resource limit. The receipt is sent only
     * after the native engine and its allocator have been torn down. */
    if(engine)cl_engine_free(engine);
    if(context.digest)EVP_MD_CTX_free(context.digest);
    const unsigned char *bytes=(const unsigned char *)&context.result;
    size_t sent=0;
    while(sent<sizeof(context.result)){
        ssize_t n=write(pipefd,bytes+sent,sizeof(context.result)-sent);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)_exit(120);
        sent+=(size_t)n;
    }
    close(pipefd);_exit(0);
}
static int ci_batch_run(const char *generation,const char *certs,struct skips *skips,
                        uint64_t start,uint64_t count,const struct ci_limits *limits,
                        struct ci_batch_result *result,int *termination) {
    int fds[2];if(pipe2(fds,O_CLOEXEC))return -1;
    struct rusage self,children;
    if(getrusage(RUSAGE_SELF,&self)||getrusage(RUSAGE_CHILDREN,&children)){close(fds[0]);close(fds[1]);return -1;}
    uint64_t used=(uint64_t)self.ru_utime.tv_sec+(uint64_t)self.ru_stime.tv_sec
        +(uint64_t)children.ru_utime.tv_sec+(uint64_t)children.ru_stime.tv_sec+1;
    if(used>=limits->cpu_seconds){close(fds[0]);close(fds[1]);return -1;}
    struct ci_limits remaining=*limits;remaining.cpu_seconds-=used;
    pid_t child=fork();
    if(child<0){close(fds[0]);close(fds[1]);return -1;}
    if(!child){close(fds[0]);ci_batch_child(generation,certs,skips,start,count,fds[1],&remaining);}
    close(fds[1]);size_t received=0;memset(result,0,sizeof(*result));
    while(received<sizeof(*result)){
        ssize_t n=read(fds[0],(unsigned char *)result+received,sizeof(*result)-received);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        received+=(size_t)n;
    }
    close(fds[0]);int status=0;struct rusage usage={0};
    while(wait4(child,&status,0,&usage)<0){if(errno!=EINTR)return -1;}
    result->peak_rss_kib=(uint64_t)usage.ru_maxrss;
    *termination=status;
    if(WIFEXITED(status)&&WEXITSTATUS(status)==0&&received==sizeof(*result))
        return result->success?0:result->resource_failure?1:-1;
    if(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGKILL||WTERMSIG(status)==SIGXCPU||WTERMSIG(status)==SIGALRM))return 1;
    /* The native limit handler writes a failed JSON to /dev/null and exits2. */
    if(WIFEXITED(status)&&WEXITSTATUS(status)==2&&received==0)return 1;
    return -1;
}
static int ci_string_compare(const void *left,const void *right) {
    return strcmp(*(const char *const *)left,*(const char *const *)right);
}
/* Hash the complete original member set plus the independently prepared selector
 * inputs. Receipts are intentionally excluded. Every load uses the original
 * signed context, and every pass rechecks this fingerprint. */
static bool ci_bounded_fingerprint(int root,char output[65]) {
    int fd=open_relative(root,"databases");if(fd<0)return false;
    DIR *dir=fdopendir(fd);if(!dir){close(fd);return false;}
    char *names[259]={0};size_t count=0;bool ok=true;unsigned families[3]={0};
    struct dirent *entry;
    while((entry=readdir(dir))){
        const char *name=entry->d_name;
        if(!strcmp(name,".")||!strcmp(name,".."))continue;
        if(count>=256){ok=false;break;}
        if(!strcmp(name,"main.cvd")||!strcmp(name,"main.cld"))families[0]++;
        else if(!strcmp(name,"daily.cvd")||!strcmp(name,"daily.cld"))families[1]++;
        else if(!strcmp(name,"bytecode.cvd")||!strcmp(name,"bytecode.cld"))families[2]++;
        else if(!ci_official_signature_name(name)){ok=false;break;}
        if(asprintf(&names[count],"databases/%s",name)<0){ok=false;break;}count++;
    }
    closedir(dir);
    if(families[0]!=1||families[1]!=1||families[2]!=1)ok=false;
    const char *profile_names[]={"profile/skip.tsv","profile/ledger.sqlite","profile/validation.json"};
    for(unsigned i=0;i<3&&ok;i++){names[count]=strdup(profile_names[i]);if(!names[count])ok=false;else count++;}
    qsort(names,count,sizeof(*names),ci_string_compare);
    EVP_MD_CTX *digest=EVP_MD_CTX_new();unsigned char raw[32];unsigned len=0;
    if(!digest||EVP_DigestInit_ex(digest,EVP_sha256(),NULL)!=1)ok=false;
    for(size_t i=0;i<count&&ok;i++){
        fd=open_relative(root,names[i]);struct stat st;char hash[65];uint64_t size=0;
        ok=fd>=0&&!fstat(fd,&st)&&S_ISREG(st.st_mode)&&digest_fd(fd,hash,&size)
            &&ci_hash_u64(digest,strlen(names[i]))&&EVP_DigestUpdate(digest,names[i],strlen(names[i]))==1
            &&ci_hash_u64(digest,size)&&EVP_DigestUpdate(digest,hash,64)==1;
        if(fd>=0)close(fd);
    }
    if(ok)ok=EVP_DigestFinal_ex(digest,raw,&len)==1&&len==32;
    if(ok){for(unsigned i=0;i<32;i++)snprintf(output+2*i,3,"%02x",raw[i]);}
    if(digest)EVP_MD_CTX_free(digest);
    for(size_t i=0;i<count;i++)free(names[i]);
    return ok;
}
static void ci_batch_record(int fd,uint64_t start,uint64_t count,int status,int termination,
                            const struct ci_batch_result *result) {
    json_object *row=json_object_new_object(),*counters=json_object_new_array();
    add_n(row,"start",(int64_t)start);add_n(row,"count",(int64_t)count);
    add_s(row,"status",status==0?"passed":status==1?"resource-failed":"rejected");
    add_n(row,"termination",termination);add_n(row,"native_status",result->native_status);
    add_n(row,"events",(int64_t)result->events);add_n(row,"eligible",(int64_t)result->eligible);
    add_n(row,"included",(int64_t)result->included);
    add_n(row,"peak_rss_kib",(int64_t)result->peak_rss_kib);
    char transcript[65];for(unsigned i=0;i<32;i++)snprintf(transcript+2*i,3,"%02x",result->transcript[i]);
    add_s(row,"transcript_sha256",transcript);
    for(unsigned i=0;i<CL_SUBSET_VALIDATION_COUNTERS;i++)json_object_array_add(counters,json_object_new_int64((int64_t)result->counters[i]));
    json_object_object_add(row,"counters",counters);
    const char *text=json_object_to_json_string_ext(row,JSON_C_TO_STRING_PLAIN);
    if(dprintf(fd,"%s\n",text)<0)set_error("bounded-receipt-write-failed");
    json_object_put(row);
}
static uint64_t ci_counter_limit(unsigned counter) {
    /* BM suffix-chain counts are uint16_t. Bounding the total also bounds
     * every possible combined chain without materializing the full table. */
    return counter==0?UINT16_MAX:(uint64_t)INT_MAX-1024;
}
static int ci_validate_bounded(const char *generation,const char *certs,struct ci_limits *limits) {
    int root=open(generation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),log=-1,receipt=-1;
    error_reason[0]=0;
    struct skips skips={0};char fingerprint[65]={0},after[65]={0};
    struct ci_batch_result baseline={0},batch={0};uint64_t aggregate[CL_SUBSET_VALIDATION_COUNTERS]={0};
    uint64_t attempts=0,passed=0;int termination=0,code=2;
    json_object *out=json_object_new_object();add_n(out,"protocol",1);add_s(out,"status","failed");
    add_s(out,"mode","bounded-native-records");add_b(out,"combined_full_PE_compile_performed",false);
    add_n(out,"native_validation_db_options",CL_DB_STDOPT|CL_DB_PUA|CL_DB_ENHANCED);
    char engine_hash[65]={0},option_hash[65]={0};options_hash(option_hash);
    if(!engine_identity(engine_hash)){set_error("bounded-engine-identity-unavailable");goto done;}
    add_s(out,"engine_sha256",engine_hash);add_s(out,"scan_options_sha256",option_hash);
    if(root<0||!ci_bounded_fingerprint(root,fingerprint)||!load_skips(&skips,root)){set_error("bounded-prepared-inventory-invalid");goto done;}
    int profile=open_relative(root,"profile");
    if(profile<0){set_error("bounded-profile-directory-invalid");goto done;}
    log=openat(profile,"bounded-batches.jsonl",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    receipt=openat(profile,"bounded-validation.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    close(profile);
    if(log<0||receipt<0){set_error("bounded-receipt-already-exists-or-unwritable");goto done;}
    int status=ci_batch_run(generation,certs,&skips,0,0,limits,&baseline,&termination);attempts++;
    ci_batch_record(log,0,0,status,termination,&baseline);
    if(status||*error_reason){set_error("bounded-retained-baseline-rejected");goto done;}
    memcpy(aggregate,baseline.counters,sizeof(aggregate));
    for(unsigned i=0;i<CL_SUBSET_VALIDATION_COUNTERS;i++)
        if(aggregate[i]>ci_counter_limit(i)){set_error("bounded-baseline-native-counter-unsupported");goto done;}
    struct ci_window{uint64_t start,count;} windows[65];unsigned depth=0;
    if(baseline.eligible)windows[depth++]=(struct ci_window){0,baseline.eligible};
    while(depth){
        struct ci_window window=windows[--depth];
        if(!ci_bounded_fingerprint(root,after)||strcmp(fingerprint,after)){set_error("bounded-generation-changed");goto done;}
        status=ci_batch_run(generation,certs,&skips,window.start,window.count,limits,&batch,&termination);attempts++;
        ci_batch_record(log,window.start,window.count,status,termination,&batch);
        if(*error_reason)goto done;
        if(status==1){
            if(window.count<2||depth+2>65){set_error("bounded-indivisible-record-exceeds-budget");goto done;}
            uint64_t left=window.count/2;
            windows[depth++]=(struct ci_window){window.start+left,window.count-left};
            windows[depth++]=(struct ci_window){window.start,left};continue;
        }
        if(status||batch.events!=baseline.events||batch.eligible!=baseline.eligible
           ||batch.included!=window.count||memcmp(batch.transcript,baseline.transcript,32)){
            set_error("bounded-native-record-or-transcript-rejected");goto done;
        }
        for(unsigned i=0;i<CL_SUBSET_VALIDATION_COUNTERS;i++){
            if(batch.counters[i]<baseline.counters[i]||aggregate[i]>ci_counter_limit(i)
               ||batch.counters[i]-baseline.counters[i]>ci_counter_limit(i)-aggregate[i]){
                set_error("bounded-aggregate-native-counter-unsupported");goto done;
            }
            aggregate[i]+=batch.counters[i]-baseline.counters[i];
        }
        passed+=window.count;
    }
    if(passed!=baseline.eligible||!ci_bounded_fingerprint(root,after)||strcmp(fingerprint,after)){
        set_error("bounded-coverage-or-generation-mismatch");goto done;
    }
    add_s(out,"status","passed");add_s(out,"snapshot_sha256",fingerprint);
    char transcript[65];for(unsigned i=0;i<32;i++)snprintf(transcript+2*i,3,"%02x",baseline.transcript[i]);
    add_s(out,"transcript_sha256",transcript);
    add_n(out,"callback_events",(int64_t)baseline.events);add_n(out,"eligible_occurrences",(int64_t)baseline.eligible);
    add_n(out,"validated_occurrences",(int64_t)passed);add_n(out,"attempts",(int64_t)attempts);
    json_object *counters=json_object_new_array();
    for(unsigned i=0;i<CL_SUBSET_VALIDATION_COUNTERS;i++)json_object_array_add(counters,json_object_new_int64((int64_t)aggregate[i]));
    json_object_object_add(out,"aggregate_counter_upperbounds",counters);
    add_s(out,"scope","all retained records compiled together in every pass; whole omitted callback occurrences compiled in complete disjoint windows; aggregate overflow bounds; no combined full PE compile");
    code=0;
done:
    if(code)add_s(out,"reason",*error_reason?error_reason:"bounded-validation-failed");
    if(receipt>=0){const char *text=json_object_to_json_string_ext(out,JSON_C_TO_STRING_PRETTY);
        if(dprintf(receipt,"%s\n",text)<0||fsync(receipt)||fchmod(receipt,0400))code=2;
        close(receipt);}
    if(log>=0){if(fsync(log)||fchmod(log,0400))code=2;close(log);}
    if(root>=0)close(root);
    free(skips.keys);free(skips.bytes);
    if(code)add_s(out,"status","failed");
    emit(out);return code;
}
