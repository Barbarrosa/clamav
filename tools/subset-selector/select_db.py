#!/usr/bin/env python3
"""Conservative, signed-input PE exclusion planner. Output is NOT release-qualified.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import collections
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from storage import fsync_directory

VERSION = '1.4.0-boundary-tested-experimental'
KNOWN = set('info cfg ign ign2 ftm hdb hdu hsb hsu mdb mdu msb msu imp ndb ndu ldb ldu idb fp sfp pdb wdb crb cdb cbc db sdb zmd rmd pwdb cat yara yar'.split())
PE_HASH = {'mdb', 'msb', 'imp'}
TDB_KEYS = {'Engine','Target','FileSize','EntryPoint','NumberOfSections','Container','Intermediates','IconGroup1','IconGroup2'}
NAME = re.compile(rb'^[\x20-\x7e]+$')


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()


def classify(ext, line):
    """Return callback format/name/target/candidate/reason. Uncertain => retain.
    Never infer applicability from malware names. CBC calls load_oneldb too.
    """
    line = line.rstrip(b'\r\n')
    if not line or line.startswith(b'#'): return None
    fmt = {'ndu':'ndb', 'ldu':'ldb'}.get(ext, ext)
    if ext in {'ndb','ndu'}:
        parts = line.split(b':')
        if len(parts) not in (4,5,6) or not NAME.fullmatch(parts[0]):
            return (fmt, b'', None, False, 'unparsed-retain')
        target = int(parts[1]) if parts[1].isdigit() else None
        ok = target == 1 and parts[1] == b'1' and b'$' not in line
        return (fmt, parts[0], target, ok, 'explicit-PE-pattern' if ok else 'generic-other-or-uncertain')
    if ext in {'ldb','ldu'}:
        parts = line.split(b';', 3)
        if len(parts) != 4 or not NAME.fullmatch(parts[0]):
            return (fmt, b'', None, False, 'unparsed-retain')
        attrs = parts[1].split(b','); pairs = [a.split(b':',1) for a in attrs]
        keys = [p[0].decode('ascii',errors='replace') for p in pairs]
        ts = [p[1] for p in pairs if len(p)==2 and p[0]==b'Target']
        target = int(ts[0]) if len(ts)==1 and ts[0].isdigit() else None
        ok = (target == 1 and ts == [b'1'] and len(set(keys))==len(keys)
              and all(len(p)==2 for p in pairs) and set(keys)<=TDB_KEYS and b'$' not in line)
        return (fmt, parts[0], target, ok, 'explicit-PE-logical' if ok else 'effect-generic-other-or-uncertain')
    return (fmt,b'',None,False,'format-retained')


def members(path):
    """Stream verified CVD/CLD; no filesystem extraction, no archive path trust."""
    with open(path,'rb') as f:
        f.seek(512)
        with tarfile.open(fileobj=f,mode='r|*') as t:
            seen=set()
            for m in t:
                if not m.isfile() or PurePosixPath(m.name).name != m.name or m.name in seen:
                    raise ValueError('unsafe/duplicate database member: '+m.name)
                seen.add(m.name)
                stream=t.extractfile(m)
                yield m,stream


def verify(path, lib, certs):
    api=ctypes.CDLL(str(lib))
    if hasattr(api,'cl_cvdverify_ex'):
        api.cl_cvdverify_ex.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint32]
        api.cl_cvdverify_ex.restype=ctypes.c_int
        rc=api.cl_cvdverify_ex(os.fsencode(path),os.fsencode(certs),0)
    else:
        api.cl_cvdverify.argtypes=[ctypes.c_char_p]
        api.cl_cvdverify.restype=ctypes.c_int
        rc=api.cl_cvdverify(os.fsencode(path))
    if rc: raise ValueError(f'signed database verification failed: {path.name}: {rc}')


def full_load_validate(dbdir, probe, certs):
    """Detect errors a skip callback could otherwise hide. Uses unchanged full DB.
    Child peak is recorded separately from this Python process's own RSS.
    """
    if probe is None: raise ValueError('full-database validation probe is required')
    empty=Path(dbdir).parent/'empty-validation-list.txt';empty.write_text('')
    command=[str(Path(probe).resolve()),str(Path(dbdir).resolve()),str(Path(certs).resolve()),'-',str(empty.resolve()),'1','0','0','0']
    try:
        result=subprocess.run(command,text=True,capture_output=True,timeout=300)
        if result.returncode: raise ValueError('full-database load/compile validation failed')
        rows=[json.loads(l) for l in result.stdout.splitlines() if l.startswith('{')]
        engine=next(r for r in rows if r.get('kind')=='engine')
        runtime=next(r for r in rows if r.get('kind')=='runtime')
        if runtime.get('unrar_modules_verified')!=1:raise ValueError('required RAR parser modules unavailable')
        if engine['signatures']<1:raise ValueError('empty database')
        return {'status':'passed','engine':engine,'runtime':runtime,'probe_sha256':sha(probe),
                'probe_source_sha256':sha(Path(__file__).parent/('scan_probe_legacy.c' if runtime.get('scan_api')=='legacy-1.4' else 'scan_probe.c')),
                'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest()}
    finally:empty.unlink(missing_ok=True)


def make_plan(inputs, destination, lib, certs, probe=None):
    start=time.monotonic(); dest=Path(destination).resolve()
    if dest.exists(): raise ValueError('generation destination already exists')
    dest.parent.mkdir(parents=True,exist_ok=True)
    # Nothing is published until all signatures verify and inventory completes.
    with tempfile.TemporaryDirectory(prefix='.subset-',dir=dest.parent) as temp:
        stage=Path(temp); dbdir=stage/'databases'; dbdir.mkdir()
        provenance=[]
        for src in sorted(map(Path,inputs)):
            if src.suffix.lower() not in {'.cvd','.cld'} or (dbdir/src.name).exists():
                raise ValueError('expected uniquely named signed CVD/CLD files')
            dst=dbdir/src.name; shutil.copyfile(src,dst); os.chmod(dst,0o400)
            verify(dst,lib,certs)
            with dst.open('rb') as f: header=f.read(512).rstrip(b'\0 ').decode('ascii')
            provenance.append({'name':dst.name,'sha256':sha(dst),'bytes':dst.stat().st_size,
                               'header':header,'verified':True})
        full_validation=full_load_validate(dbdir,probe,certs)
        sql=sqlite3.connect(stage/'decisions.sqlite')
        sql.execute('PRAGMA cache_size=-4096')
        sql.execute('CREATE TABLE names(fmt TEXT,name BLOB,eligible INTEGER,occurrences INTEGER,reason TEXT,PRIMARY KEY(fmt,name)) WITHOUT ROWID')
        inventory=[]; blockers=[]; protected=[]
        for src in sorted(dbdir.iterdir()):
            for m,stream in members(src):
                ext=Path(m.name).suffix[1:].lower()
                item={'database':src.name,'member':m.name,'serialized_bytes':m.size,
                      'format':ext,'records':0,'targets':{},'reasons':{},'container_constraints':{}}
                targets=collections.Counter(); reasons=collections.Counter(); containers=collections.Counter()
                if m.name=='COPYING' or ext=='info':
                    reasons['metadata-retained']+=1
                elif ext not in KNOWN:
                    blockers.append('unknown-format:'+m.name); reasons['unknown-retained-activation-blocked']+=1
                elif ext=='cbc':
                    # CBC's second line is its logical signature or hook name.
                    stream.readline(); name=stream.readline().rstrip(b'\r\n').split(b';',1)[0]
                    if not name or not NAME.fullmatch(name): blockers.append('unresolved-bytecode:'+m.name)
                    else: protected.append(name)
                    item['records']=1; reasons['signed-bytecode-and-associated-logical-retained']+=1
                else:
                    for line in stream:
                        if not line.strip() or line.startswith(b'#'): continue
                        item['records']+=1
                        decision=classify(ext,line)
                        fmt,name,target,ok,why=decision
                        targets[str(target) if target is not None else 'unclassified']+=1
                        reasons[why]+=1
                        if ext in {'ldb','ldu'}:
                            for attr in line.split(b';',2)[1:2]:
                                for c in attr.split(b','):
                                    if c.startswith((b'Container:',b'Intermediates:',b'HandlerType:')):
                                        containers[c.decode('ascii',errors='replace')]+=1
                        if fmt in {'ndb','ldb'}:
                            if not name:
                                blockers.append('unparsed-target-record:'+m.name)
                            else:
                                sql.execute('INSERT INTO names VALUES(?,?,?,?,?) ON CONFLICT(fmt,name) DO UPDATE SET eligible=min(eligible,excluded.eligible),occurrences=occurrences+1,reason=CASE WHEN excluded.eligible=0 THEN excluded.reason ELSE reason END',
                                            (fmt,name,int(ok),1,why))
                    if ext in PE_HASH: reasons={'explicit-PE-hash-family-candidate':item['records']}
                item.update(targets=dict(targets),reasons=dict(reasons),container_constraints=dict(containers))
                inventory.append(item)
        for name in protected:
            sql.execute('UPDATE names SET eligible=0,reason=? WHERE fmt=? AND name=?',('bytecode-dependency','ldb',name))
        sql.commit()
        # Names with mixed-target occurrences in the same callback namespace are never skipped.
        decision_stats=dict(sql.execute('SELECT reason,count(*) FROM names GROUP BY reason'))
        with (stage/'skip.tsv').open('wb') as out:
            keys=[(e.encode(),b'*') for e in sorted(PE_HASH) if any(i['format']==e for i in inventory)]
            # SQL order matches strcmp for validated ASCII; merge three tiny family entries.
            it=iter(sql.execute('SELECT fmt,name FROM names WHERE eligible=1 ORDER BY fmt,name'))
            current=next(it,None)
            for fmt,name in keys:
                while current and current[0].encode()<fmt:
                    out.write(current[0].encode()+b'\t'+current[1]+b'\n'); current=next(it,None)
                out.write(fmt+b'\t'+name+b'\n')
            while current:
                out.write(current[0].encode()+b'\t'+current[1]+b'\n');current=next(it,None)
        excluded_names=sql.execute('SELECT count(*) FROM names WHERE eligible=1').fetchone()[0]
        # Every decision is queryable without keeping signature text or a Python in-memory set.
        sql.close()
        profile=json.loads((Path(__file__).parent/'profiles.json').read_text())
        report={'schema':1,'selector_version':VERSION,'selector_sha256':sha(__file__),
                'engine_library_sha256':sha(lib),'profile':profile,
                'signed_databases':provenance,'full_load_validation':full_validation,'skip_sha256':sha(stage/'skip.tsv'),
                'decision_sqlite_sha256':sha(stage/'decisions.sqlite'),
                'excluded_callback_names':excluded_names,'family_exclusions':sorted(PE_HASH),
                'protected_bytecode_names':len(protected),'decision_counts':decision_stats,
                'inventory':inventory,'activation_blockers':sorted(set(blockers)),
                'release_qualified':False,'qualification_reason':'opt-in all-match scanning; automatic release held pending complete parser/limit gates',
                'elapsed_seconds':time.monotonic()-start,'selector_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
        (stage/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        for item in stage.rglob('*'):
            if item.is_file():
                os.chmod(item,0o400)
                with item.open('rb') as saved:os.fsync(saved.fileno())
        fsync_directory(dbdir);fsync_directory(stage)
        os.rename(stage,dest)
        fsync_directory(dest.parent)
    return report


def validate_generation(path, lib):
    path=Path(path)
    for name in ('manifest.json','skip.tsv','decisions.sqlite','databases'):
        if (path/name).is_symlink():raise ValueError('generation symlink is not allowed: '+name)
    m=json.loads((path/'manifest.json').read_text())
    if m['schema']!=1 or m['selector_version']!=VERSION: raise ValueError('selector version mismatch')
    if m['selector_sha256']!=sha(__file__): raise ValueError('selector changed; regenerate')
    if m['engine_library_sha256']!=sha(lib): raise ValueError('engine changed; regenerate and requalify')
    if m['skip_sha256']!=sha(path/'skip.tsv'): raise ValueError('manifest exclusion mismatch')
    if m['decision_sqlite_sha256']!=sha(path/'decisions.sqlite'): raise ValueError('decision audit changed')
    if not m['signed_databases']:raise ValueError('empty database manifest')
    names=[x['name'] for x in m['signed_databases']]
    if len(names)!=len(set(names)) or any(Path(n).name!=n or Path(n).suffix.lower() not in {'.cvd','.cld'} for n in names):raise ValueError('invalid database names')
    if m['profile']!=json.loads((Path(__file__).parent/'profiles.json').read_text()): raise ValueError('profile changed')
    actual={p.name for p in (path/'databases').iterdir()}
    if actual!={x['name'] for x in m['signed_databases']}: raise ValueError('unexpected database files')
    for x in m['signed_databases']:
        p=path/'databases'/x['name']
        if p.is_symlink() or sha(p)!=x['sha256']: raise ValueError('database changed; regenerate and requalify')
    if m.get('full_load_validation',{}).get('status')!='passed': raise ValueError('missing full-database validation')
    runtime=m['full_load_validation'].get('runtime',{})
    if runtime.get('engine_sha256')!=m['engine_library_sha256'] or runtime.get('unrar_modules_verified')!=1:raise ValueError('unverified runtime engine or parsers')
    if m['activation_blockers']: raise ValueError('unresolved database format/dependency')
    return m

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lib',type=Path,required=True);p.add_argument('--certs',type=Path,required=True)
    p.add_argument('--probe',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('databases',nargs='+',type=Path)
    a=p.parse_args();r=make_plan(a.databases,a.output,a.lib,a.certs,a.probe)
    print(json.dumps({k:r[k] for k in ['excluded_callback_names','activation_blockers','elapsed_seconds','selector_peak_rss_kib']}))
