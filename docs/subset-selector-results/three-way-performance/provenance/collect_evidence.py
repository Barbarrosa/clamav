import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
from pathlib import Path

root=Path(__file__).resolve().parent
dest=root/'fork/docs/subset-selector-results/three-way-performance'
dest.mkdir(parents=True,exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sync(p):
    with p.open('rb') as f:os.fsync(f.fileno())
def copy(src,target):
    target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target);sync(target)
def tar_gz(out,items,extra=None):
    with out.open('wb',buffering=0) as f:
        with gzip.GzipFile(fileobj=f,mode='wb',mtime=0,filename='') as g:
            with tarfile.open(fileobj=g,mode='w|') as t:
                for name,p in sorted(items):
                    data=p.read_bytes();info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;info.mtime=0
                    t.addfile(info,io.BytesIO(data))
                for name,data in (extra or {}).items():
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;info.mtime=0;t.addfile(info,io.BytesIO(data))
        os.fsync(f.fileno())
def gzip_file(src,out):
    with src.open('rb') as source,out.open('wb',buffering=0) as target:
        with gzip.GzipFile(fileobj=target,mode='wb',mtime=0,filename='') as g:shutil.copyfileobj(source,g)
        os.fsync(target.fileno())

summary=json.loads((root/'summary.json').read_text())
assert summary['completed_processes']==78 and summary['validation']['all_unrar_runtime_module_checks_passed']
copy(root/'summary.json',dest/'summary.json')
copy(root/'results/environment.json',dest/'environment.json')
copy(root/'results/plan.json',dest/'plan.json')
copy(root/'matrix.log',dest/'matrix.log')
copy(root/'analysis-validation.log',dest/'analysis-validation.log')
tar_gz(dest/'final-runs.tar.gz',[(p.name,p) for p in (root/'results').iterdir() if p.is_file()])
tar_gz(dest/'excluded-preflight-no-unrar.tar.gz',[(p.name,p) for p in (root/'results-preflight-no-unrar').iterdir() if p.is_file()])
copy(root/'matrix-preflight-no-unrar.log',dest/'excluded-preflight-matrix.log')

manifest={};items=[]
for group in ('accepted','positive','adverse'):
    manifest[group]=[]
    for i,line in enumerate((root/(group+'.txt')).read_text().splitlines()):
        p=Path(line);member=f'{group}/{i:03d}-{p.name}';items.append((member,p))
        manifest[group].append({'member':member,'source_path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)})
data=(json.dumps(manifest,indent=2)+'\n').encode()
(dest/'corpus-manifest.json').write_bytes(data)
tar_gz(dest/'corpus.tar.gz',items,{'manifest.json':data})
assert len({r['sha256'] for r in manifest['accepted']})==28
assert sum(r['bytes'] for r in manifest['accepted'])==summary['environment']['fixture_bytes']

for p in (root/'deliverables').iterdir():
    if p.is_file():copy(p,dest/'tables'/p.name)
copy(root/'generation/manifest.json',dest/'generation/manifest.json')
gzip_file(root/'generation/skip.tsv',dest/'generation/skip.tsv.gz')
gzip_file(root/'generation/decisions.sqlite',dest/'generation/decisions.sqlite.gz')

for p in (root/'provenance').iterdir():
    if p.is_file():copy(p,dest/'provenance'/p.name)
for name in ('configure.sh','build-env.sh','build-upstream.log','build-fork.log',
             'configure-upstream-final.log','configure-fork-final.log','database-fetch.log','selector.log',
             'collect_evidence.py','package_project.py'):
    copy(root/name,dest/'provenance'/name)
copy(root/'downloads/rust-provenance.json',dest/'provenance/rust-provenance.json')
packages=[{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted((root/'debs').glob('*.deb'))]
(dest/'provenance/debian-packages.json').write_text(json.dumps({'source':'Ubuntu snapshot 20260828T000000Z','packages':packages},indent=2)+'\n')
for name in ('tests-upstream.log','tests-fork.log','scanner-tests-upstream.log','scanner-tests-fork.log',
             'selector-tests.log','selector-unit-tests.log','signed-input-tests.json','signed-input-tests.log','synthetic-tests.log'):
    copy(root/name,dest/'correctness'/name)
for variant in ('upstream','fork'):
    copy(root/f'build-{variant}/Testing/Temporary/LastTest.log',dest/f'correctness/scanner-detail-{variant}.log')
tar_gz(dest/'correctness/synthetic-gates.tar.gz',[(str(p.relative_to(root/'synthetic-tests')),p)
       for p in (root/'synthetic-tests').rglob('*') if p.is_file() and p.suffix in ('.json','.jsonl','.stderr')])
copy(root/'synthetic-tests/summary.json',dest/'correctness/synthetic-summary.json')
index={str(p.relative_to(dest)):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(dest.rglob('*')) if p.is_file() and p.name!='evidence-manifest.json'}
(dest/'evidence-manifest.json').write_text(json.dumps(index,indent=2)+'\n')
for p in dest.rglob('*'):
    if p.is_file():sync(p)
print(json.dumps({'evidence_files':len(index),'bytes':sum(v['bytes'] for v in index.values()),'destination':str(dest)}))
