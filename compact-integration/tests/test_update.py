#!/usr/bin/env python3
"""Updater orchestration/fault tests. Crypto/parser correctness uses real Rust tests.
The fake libfreshclam below never contacts the network or authenticates data.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADERS = {
    "clamav.h": r'''
#include <stdint.h>
#include <time.h>
#define CL_INIT_DEFAULT 0
#define CL_SUCCESS 0
struct cl_cvd { unsigned fl; unsigned long stime; };
int cl_init(unsigned);
int cl_cvdverify_ex(const char *,const char *,uint32_t);
struct cl_cvd *cl_cvdhead(const char *);
void cl_cvdfree(struct cl_cvd *);
unsigned cl_retflevel(void);
const char *cl_retver(void);
''',
    "libfreshclam.h": r'''
#include <stdint.h>
#define FC_CONFIG_MSG_QUIET 4
typedef enum { FC_SUCCESS=0,FC_UPTODATE=1,FC_ERETRYLATER=18,FC_EMEM=20,FC_ETESTFAIL=21 } fc_error_t;
typedef struct {
 uint32_t msgFlags,maxAttempts,connectTimeout,requestTimeout,bCompressLocalDatabase;
 const char *databaseDirectory,*tempDirectory,*certsDirectory;
} fc_config;
fc_error_t fc_initialize(fc_config *);
void fc_cleanup(void);
void fc_set_fccb_download_complete(void *);
fc_error_t fc_dns_query_update_info(const char *,char **,char **);
fc_error_t fc_update_databases(char **,uint32_t,char **,uint32_t,int,const char *,int,void *,uint32_t *);
fc_error_t fc_test_database_ex(const char *,int,char *);
''',
}
STUB = r'''
#include <stdbool.h>
#include "clamav.h"
#include "libfreshclam.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char cache[1024];
static void audit(const char *event,const char *value) {
 const char *p=getenv("TEST_AUDIT");
 if(p){FILE*f=fopen(p,"a");fprintf(f,"%ld %s %s\n",(long)getpid(),event,value);fclose(f);}
}
int cl_init(unsigned n){(void)n;return 0;}
const char *cl_retver(void){return "fixture-runtime";}
unsigned cl_retflevel(void){return 999;}
int cl_cvdverify_ex(const char*p,const char*c,uint32_t o){(void)c;(void)o;
 return getenv("TEST_BAD_DB") && strstr(p,getenv("TEST_BAD_DB")) ? 2 : 0;}
struct cl_cvd *cl_cvdhead(const char*p){(void)p;struct cl_cvd*h=calloc(1,sizeof(*h));h->fl=1;
 h->stime=strtoull(getenv("TEST_DB_TIME"),NULL,10);return h;}
void cl_cvdfree(struct cl_cvd*h){free(h);}
fc_error_t fc_initialize(fc_config*c){
 if(strlen(c->databaseDirectory)>=sizeof(cache))abort();
 strcpy(cache,c->databaseDirectory);char path[4096];
 if(snprintf(path,sizeof(path),"%s/freshclam.dat",cache)>=(int)sizeof(path))abort();
 struct state {uint32_t version;char uuid[37];time_t retry_after;} s={1,"fixture-identity",0};
 FILE*f=fopen(path,"rb");if(f){fseek(f,13,SEEK_SET);if(fread(&s,sizeof(s),1,f)!=1)abort();fclose(f);}
 if(getenv("TEST_RETRY_AFTER"))s.retry_after=strtoull(getenv("TEST_RETRY_AFTER"),NULL,10);
 f=fopen(path,"wb");fwrite("FreshClamData",13,1,f);fwrite(&s,sizeof(s),1,f);fclose(f);return 0;
}
void fc_cleanup(void){}
void fc_set_fccb_download_complete(void*p){if(p)abort();}
fc_error_t fc_dns_query_update_info(const char*d,char**a,char**b){
 if(strcmp(d,"current.cvd.clamav.net"))abort();
 *a=NULL;*b=NULL;return 0;}
fc_error_t fc_update_databases(char**db,uint32_t n,char**servers,uint32_t ns,int priv,const char*dns,int inc,void*ctx,uint32_t*updated){
 (void)dns;(void)ctx;if(n!=3||ns!=1||priv||!inc||strcmp(servers[0],"https://database.clamav.net"))abort();
 audit("fetch","official");
 if(getenv("TEST_FETCH_SLEEP"))sleep(3);
 if(getenv("TEST_RETRY_AFTER"))return FC_ERETRYLATER;
 for(unsigned i=0;i<n;i++){char path[4096];
 if(snprintf(path,sizeof(path),"%s/%s.cvd",cache,db[i])>=(int)sizeof(path))abort();
 FILE*f=fopen(path,"wb");fprintf(f,"official-fixture-%s-%s",db[i],getenv("TEST_DB_VERSION"));fclose(f);}
 *updated=3;return 0;
}
fc_error_t fc_test_database_ex(const char*p,int b,char*c){(void)b;(void)c;audit("validate",p);
 if(getenv("TEST_MEMORY_DB") && strstr(p,getenv("TEST_MEMORY_DB")))return FC_EMEM;
 if(getenv("TEST_SEMANTIC_DB") && strstr(p,getenv("TEST_SEMANTIC_DB")))return FC_ETESTFAIL;
 return 0;}
'''
SCANNER = r'''#!/usr/bin/env python3
import fcntl,json,os,sys
from pathlib import Path
args=dict(zip(sys.argv[2::2],sys.argv[3::2]))
fd=int(args['--lock-fd'])
assert os.fstat(fd).st_ino==Path(args['--state'],'job.lock').stat().st_ino
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
root=Path(args['--generation'])
if sys.argv[1]=='prepare':
 p=root/'profile';p.mkdir()
 (p/'skip.tsv').write_text('ndb\tExample\n')
 (p/'validation.json').write_text('{"status":"prepared"}\n')
 (p/'ledger.sqlite').write_bytes(b'test-ledger')
elif sys.argv[1]=='validate-bounded':
 assert (root/'profile/ledger.sqlite').is_file()
 if os.environ.get('TEST_BOUNDED_FAIL'):raise RuntimeError('bounded fixture failure')
 (root/'profile/bounded-batches.jsonl').write_text('{"status":"passed"}\n')
 (root/'profile/bounded-validation.json').write_text('{"mode":"bounded-native-records","status":"passed"}\n')
else:
 assert args['--profile']=='pdf-jpeg-png-pe-exclusions'
 m=json.loads((root/'manifest.json').read_text())
 assert m['validation']['status']=='passed'
 assert m['validation']['mode'] in ('stock-per-database','bounded-native-records')
 if m['validation']['mode']=='bounded-native-records':assert 'profile/bounded-validation.json' in m['files']
 assert m['qualification']['coverage_qualified'] is True
 for name,record in m['files'].items():
  import hashlib
  data=(root/name).read_bytes()
  assert len(data)==record['size'] and hashlib.sha256(data).hexdigest()==record['sha256']
print(json.dumps({'protocol':1,'status':'passed'}))
'''

class UpdaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('cc'):
            raise unittest.SkipTest('C compiler required')
        try:
            cls.json_flags=subprocess.check_output(['pkg-config','--cflags','--libs','json-c'],text=True).split()
        except (FileNotFoundError,subprocess.CalledProcessError):
            raise unittest.SkipTest('json-c development files required (available in compact-dev)')
        cls.build=tempfile.TemporaryDirectory(prefix='compact-update-build-')
        root=Path(cls.build.name)
        for name,text in HEADERS.items():
            (root/name).write_text(text)
        (root/'stub.c').write_text(STUB)
        cls.binary=root/'compact-update'
        compiled=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',
                        '-I',str(root),str(ROOT/'native/update.c'),str(root/'stub.c'),
                        '-lcrypto','-o',str(cls.binary),*cls.json_flags],capture_output=True,text=True)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='compact-update-test-')
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        self.state=self.root/'state'
        self.scanner=self.root/'compact-scan'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o700)
        self.audit=self.root/'audit'
        self.env=dict(os.environ,TEST_AUDIT=str(self.audit),TEST_DB_TIME=str(int(time.time())),
                      TEST_DB_VERSION='1')
        self.args=['update','--state',str(self.state),'--scanner',str(self.scanner),
                   '--certs',str(self.root),'--engine-sha256','1'*64,'--options-sha256','2'*64,
                   '--as-bytes',str(256*1024*1024),'--cpu-seconds','10','--wall-seconds','10',
                   '--file-bytes',str(16*1024*1024),'--max-line-bytes',str(1024*1024),
                   '--connect-seconds','1','--low-speed-seconds','2','--max-attempts','1',
                   '--max-age-seconds','86400','--disk-reserve-bytes','1048576']

    def call(self,args=None):
        command=list(self.args if args is None else args)
        if command[0]=='update' and '--expected-current-sha256' not in command:
            pointer=self.state/'current.json'
            expected=hashlib.sha256(pointer.read_bytes()).hexdigest() if pointer.exists() else 'absent'
            command+=['--expected-current-sha256',expected]
        result=subprocess.run([str(self.binary),*command],
                              env=self.env,text=True,capture_output=True,timeout=20)
        return result,json.loads(result.stdout.splitlines()[-1])

    def test_required_policy_has_no_mutation(self):
        result,row=self.call(self.args[:9])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(row['status'],'failed')
        self.assertFalse(self.state.exists())

    def test_success_validates_each_database_in_fresh_child(self):
        result,row=self.call()
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.assertEqual(row['status'],'updated')
        pointer=json.loads((self.state/'current.json').read_text())
        generation=self.state/'generations'/pointer['generation']
        manifest=json.loads((generation/'manifest.json').read_text())
        self.assertEqual(manifest['validation']['status'],'passed')
        self.assertEqual((generation/'manifest.json').stat().st_mode & 0o777,0o400)
        tests=[line.split(' ',2) for line in self.audit.read_text().splitlines() if ' validate ' in line]
        self.assertEqual(len(tests),3)
        self.assertEqual(len({test[0] for test in tests}),3)
        self.assertTrue((self.state/'cache/freshclam.dat').exists())

    def test_failed_validation_preserves_active_generation(self):
        self.assertEqual(self.call()[0].returncode,0)
        previous=(self.state/'current.json').read_bytes()
        self.env.update(TEST_DB_VERSION='2',TEST_BAD_DB='daily')
        result,row=self.call()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(row['status'],'failed')
        self.assertEqual((self.state/'current.json').read_bytes(),previous)

    def test_cooldown_survives_new_invocations(self):
        retry=int(time.time())+600
        self.env['TEST_RETRY_AFTER']=str(retry)
        result,row=self.call()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(row['status'],'deferred')
        self.assertEqual(row['next_attempt_after'],retry)
        count=self.audit.read_text().count(' fetch ')
        self.env.pop('TEST_RETRY_AFTER')
        result,row=self.call()
        self.assertEqual(row['reason'],'freshclam_cooldown')
        self.assertEqual(self.audit.read_text().count(' fetch '),count)

    def test_lock_contention_defers(self):
        self.state.mkdir(mode=0o700)
        with (self.state/'job.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result,row=self.call()
        self.assertEqual(row['status'],'deferred')
        self.assertEqual(row['reason'],'job_busy')
        self.assertFalse(self.audit.exists())

    def test_rollback_pointer_retains_previous_tuple(self):
        first=self.call()[1]['generation']
        self.env['TEST_DB_VERSION']='2'
        second=self.call()[1]['generation']
        self.assertNotEqual(first,second)
        self.assertEqual(json.loads((self.state/'previous.json').read_text())['generation'],first)
        self.assertTrue((self.state/'generations'/first).is_dir())

    def test_repeated_snapshot_is_idempotent(self):
        first=self.call()[1]['generation']
        result,row=self.call()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(row['status'],'up_to_date')
        self.assertEqual(row['generation'],first)
        self.assertFalse((self.state/'previous.json').exists())

    def test_code_and_database_activate_as_one_tuple(self):
        self.args += ['--program-id','pkg-'+'3'*64]
        first=self.call()[1]['generation']
        self.assertEqual(json.loads((self.state/'current.json').read_text())['program'],'pkg-'+'3'*64)
        self.args[-1]='pkg-'+'4'*64
        second=self.call()[1]['generation']
        self.assertNotEqual(first,second)
        self.assertEqual(json.loads((self.state/'previous.json').read_text())['program'],'pkg-'+'3'*64)
        self.assertEqual(json.loads((self.state/'current.json').read_text())['program'],'pkg-'+'4'*64)

    def test_database_update_preserves_program_and_unknown_pointer_fields(self):
        self.args += ['--program-id','pkg-'+'3'*64]
        self.call()
        pointer=json.loads((self.state/'current.json').read_text())
        pointer['future_metadata']={'extra':True}
        (self.state/'current.json').chmod(0o600)
        (self.state/'current.json').write_text(json.dumps(pointer))
        self.args=self.args[:-2]
        self.env['TEST_DB_VERSION']='2'
        result,row=self.call()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads((self.state/'current.json').read_text())['program'],'pkg-'+'3'*64)
        self.assertTrue(json.loads((self.state/'previous.json').read_text())['future_metadata']['extra'])

    def test_stale_database_or_candidate_selection_cannot_republish_old_runtime(self):
        self.call()
        before=(self.state/'current.json').read_bytes()
        expected=hashlib.sha256(before).hexdigest()
        pointer=json.loads(before);pointer['program']='pkg-'+'9'*64
        (self.state/'current.json').chmod(0o600)
        (self.state/'current.json').write_text(json.dumps(pointer))
        promoted=(self.state/'current.json').read_bytes()
        audit=self.audit.read_bytes()
        for extra in ([],['--program-id','pkg-'+'3'*64]):
            result,row=self.call(self.args+['--expected-current-sha256',expected]+extra)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((row['status'],row['reason']),('deferred','current_pointer_changed'))
            self.assertEqual((self.state/'current.json').read_bytes(),promoted)
            self.assertEqual(self.audit.read_bytes(),audit)
        _,row=self.call(self.args+['--expected-current-sha256','absent'])
        self.assertEqual(row['reason'],'current_pointer_changed')

    def test_only_explicit_memory_failure_uses_bounded_native_validation(self):
        self.env['TEST_MEMORY_DB']='daily'
        result,row=self.call()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        generation=self.state/'generations'/row['generation']
        manifest=json.loads((generation/'manifest.json').read_text())
        self.assertEqual(manifest['validation'],{'mode':'bounded-native-records','status':'passed'})
        self.assertIn('profile/bounded-batches.jsonl',manifest['files'])
        self.assertIn('profile/bounded-validation.json',manifest['files'])
        self.assertEqual(self.audit.read_text().count(' validate '),3)

    def test_bounded_failure_or_semantic_failure_preserves_active_tuple(self):
        self.call()
        before=(self.state/'current.json').read_bytes()
        for memory in (False,True):
            self.env['TEST_DB_VERSION']='2'
            if memory:self.env.update(TEST_MEMORY_DB='daily',TEST_BOUNDED_FAIL='1')
            else:self.env['TEST_SEMANTIC_DB']='daily'
            result,row=self.call()
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(row['status'],'failed')
            self.assertEqual((self.state/'current.json').read_bytes(),before)
            if not memory:self.env.pop('TEST_SEMANTIC_DB')

    def test_corrupt_freshclam_state_is_not_reset(self):
        self.state.mkdir(mode=0o700)
        cache=self.state/'cache';cache.mkdir(mode=0o700)
        (cache/'freshclam.dat').write_bytes(b'corrupt')
        (cache/'freshclam.dat').chmod(0o600)
        result,row=self.call()
        self.assertEqual(row['reason'],'freshclam_state_invalid')
        self.assertEqual((cache/'freshclam.dat').read_bytes(),b'corrupt')
        self.assertFalse(self.audit.exists())

    def test_wall_limit_prevents_promotion(self):
        self.env['TEST_FETCH_SLEEP']='1'
        self.args[self.args.index('--wall-seconds')+1]='1'
        result,row=self.call()
        self.assertIn(row['reason'],('stage_wall_limit','job_wall_limit'))
        self.assertFalse((self.state/'current.json').exists())

    def test_disk_reserve_defers_before_fetch(self):
        self.args[self.args.index('--disk-reserve-bytes')+1]=str(2**64-1)
        result,row=self.call()
        self.assertEqual(row['status'],'deferred')
        self.assertEqual(row['reason'],'disk_reserve')
        self.assertFalse(self.audit.exists())

    def test_internal_subcommand_cannot_skip_lock(self):
        result,row=self.call(['fetch','--state',str(self.state),'--certs',str(self.root)])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(row['status'],'failed')
        self.assertFalse(self.state.exists())


if __name__=='__main__':
    unittest.main()
