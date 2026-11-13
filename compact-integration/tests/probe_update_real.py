#!/usr/bin/env python3
"""Real native validation/preparation/promotion using authentic seeded databases.
Only upstream transport is replaced with an explicit test-only no-network shim.
No production bypass flags are added. Numeric limits are explicit probe inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

SHIM=r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int fc_dns_query_update_info(const char *name,char **dns,char **version) {
 if(strcmp(name,"current.cvd.clamav.net"))abort();
 *dns=NULL;*version=NULL;return 0;
}
int fc_update_databases(char **db,uint32_t n,char **server,uint32_t ns,int private,
 const char *dns,int scripted,void *context,uint32_t *updated) {
 (void)dns;(void)context;
 if(n!=3||ns!=1||private||!scripted||strcmp(server[0],"https://database.clamav.net")||
 strcmp(db[0],"main")||strcmp(db[1],"daily")||strcmp(db[2],"bytecode"))abort();
 *updated=0;return 1;
}
'''
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(65536),b''):h.update(block)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','scanner','database','certs','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    limits=('as-bytes','cpu-seconds','wall-seconds','file-bytes','max-line-bytes',
            'disk-reserve-bytes','max-state-bytes','max-state-inodes','connect-seconds','low-speed-seconds','max-attempts','max-age-seconds')
    for name in limits:parser.add_argument('--'+name,type=int,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output must be absent')
    args.output.mkdir(mode=0o700,parents=True)
    state=args.output/'state';state.mkdir(mode=0o700)
    cache=state/'cache';cache.mkdir(mode=0o700)
    for path in args.database.iterdir():
        if path.name in ('main.cvd','main.cld','daily.cvd','daily.cld','bytecode.cvd','bytecode.cld') or path.name.endswith('.cvd.sign'):
            target=cache/path.name
            shutil.copyfile(path,target);target.chmod(0o600)
    source=args.output/'transport-only-test-shim.c';source.write_text(SHIM)
    shim=args.output/'transport-only-test-shim.so'
    subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(source),'-o',str(shim)],check=True)
    doctor_result=subprocess.run([str(args.scanner),'doctor'],capture_output=True,text=True,check=True)
    doctor=json.loads(doctor_result.stdout.splitlines()[-1])
    command=[str(args.binary),'update','--state',str(state),'--scanner',str(args.scanner),
             '--certs',str(args.certs),'--engine-sha256',doctor['engine_sha256'],
             '--options-sha256',doctor['scan_options_sha256'],'--expected-current-sha256','absent']
    for name in limits:command+=['--'+name,str(getattr(args,name.replace('-','_')))]
    started=time.monotonic()
    result=subprocess.run(command,env=dict(os.environ,LD_PRELOAD=str(shim)),
                          capture_output=True,text=True,timeout=args.wall_seconds+10)
    (args.output/'stdout.jsonl').write_text(result.stdout)
    (args.output/'stderr.log').write_text(result.stderr)
    rows=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    final=rows[-1] if rows else {}
    report={'protocol':1,'scope':'real native pipeline with transport-only no-network test shim',
            'transport_mocked':True,'official_download_tested':False,'exit_code':result.returncode,
            'wall_seconds':time.monotonic()-started,'result':final,'doctor':doctor,
            'probe_limits':{name:getattr(args,name.replace('-','_')) for name in limits},
            'binary_sha256':sha(args.binary),'scanner_sha256':sha(args.scanner),
            'source_database_sha256':{p.name:sha(p) for p in cache.iterdir() if p.suffix in ('.cvd','.cld')}}
    if result.returncode==0 and final.get('generation'):
        generation=state/'generations'/final['generation']
        manifest=json.loads((generation/'manifest.json').read_text())
        report['manifest']=manifest
        report['all_manifest_hashes_match']=all(sha(generation/name)==record['sha256']
            and (generation/name).stat().st_size==record['size'] for name,record in manifest['files'].items())
        report['validation_mode']=manifest['validation']['mode']
        report['validation_passed']=manifest['validation']['status']=='passed'
        report['stock_validation_passed']=manifest['validation']=={'mode':'stock-per-database','status':'passed'}
        report['pointer_matches']=json.loads((state/'current.json').read_text())['generation']==final['generation']
        report['self_test_log']=(generation/'self-test.log').read_text()
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('exit_code','wall_seconds','result','all_manifest_hashes_match','stock_validation_passed','pointer_matches') if k in report}))
    raise SystemExit(0 if result.returncode==0 and report.get('all_manifest_hashes_match') and report.get('pointer_matches') else 1)

if __name__=='__main__':main()
