"""Preserve the prior archive, commit additions, verify and atomically package."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

root=Path(__file__).resolve().parent
repo=root/'fork';project=root/'project';output=root/'deliverables/ClamAV-engine-foundations.zip'
prior=root.parent/'comparison/ClamAV-engine-foundations.zip'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while chunk:=f.read(1024*1024):h.update(chunk)
    return h.hexdigest()
def sync(p):
    with p.open('rb') as f:os.fsync(f.fileno())
def git(*args,**kw):return subprocess.check_output(['git','-C',str(repo),*args],**kw)

old=json.loads((project/'revision.json').read_text());oldcommit=old['source_revision']
assert oldcommit=='9dfde0139708a1eb1a728f86baecb1d8ec1b66df'
assert sha(prior)=='69563b9c158b43521307073b7db6361971b87abb02e3c17535d821b26d30b5a0'
oldmanifest=json.loads((project/'source-manifest.json').read_text())
for path,record in oldmanifest.items():
    assert sha(project/'source'/path)==record['sha256'],path

history=project/'history/performance-analysis-input-v13';history.mkdir(parents=True,exist_ok=True)
for name in ('README.md','revision.json','source-manifest.json','archive-preservation.json'):
    shutil.copyfile(project/name,history/name)
oldrefs=git('bundle','list-heads',str(project/'source-history.bundle')).decode().splitlines()
(history/'bundle-refs.txt').write_text('\n'.join(oldrefs)+'\n')
(history/'input-archive.json').write_text(json.dumps({'library_version':13,'bytes':prior.stat().st_size,'sha256':sha(prior),'source_commit':oldcommit},indent=2)+'\n')
git('checkout','--','libclamav_rust/src/sys.rs')
git('add','tools/subset-selector/performance','docs/three-way-performance.md','tools/subset-selector/README.md')
git('add','-f','docs/subset-selector-results/three-way-performance')
changed=git('diff','--cached','--name-only').decode().splitlines()
assert changed and all(p.startswith(('tools/subset-selector/performance/','docs/subset-selector-results/three-way-performance/')) or p in ('docs/three-way-performance.md','tools/subset-selector/README.md') for p in changed)
git('-c','user.name=Codex','-c','user.email=codex@openai.com','commit','-m','Add controlled three-way ClamAV performance and cache analysis')
commit=git('rev-parse','HEAD').decode().strip();tree=git('rev-parse','HEAD^{tree}').decode().strip()
assert not git('status','--porcelain').strip()

for line in oldrefs:
    obj,ref=line.split(' ',1)
    git('cat-file','-e',obj+'^{commit}')
    archived='refs/archive/version-13/'+(ref[5:] if ref.startswith('refs/') else 'bundled-'+ref)
    git('update-ref',archived,obj)
    if ref.startswith('refs/') and ref!='refs/heads/restricted-upload-selector':
        git('update-ref','--no-deref',ref,obj)
bundle=project/'source-history.bundle.new'
git('bundle','create',str(bundle),'--all');sync(bundle)
git('bundle','verify',str(bundle),stderr=subprocess.STDOUT)
newrefs=dict(line.split(' ',1)[::-1] for line in git('bundle','list-heads',str(bundle)).decode().splitlines())
for line in oldrefs:
    obj,ref=line.split(' ',1)
    archived='refs/archive/version-13/'+(ref[5:] if ref.startswith('refs/') else 'bundled-'+ref)
    assert newrefs[archived]==obj
bundle.replace(project/'source-history.bundle')

patch=git('diff','--binary',oldcommit,commit)
(project/'performance-analysis.patch').write_bytes(patch);sync(project/'performance-analysis.patch')
with tempfile.TemporaryDirectory() as d:
    env=os.environ.copy();env['GIT_INDEX_FILE']=str(Path(d)/'index')
    git('read-tree',oldcommit,env=env)
    subprocess.run(['git','-C',str(repo),'apply','--cached','--binary','-'],input=patch,check=True,env=env)
    assert git('write-tree',env=env).decode().strip()==tree
source_tar=root/'source-final.tar'
with source_tar.open('wb',buffering=0) as f:
    subprocess.run(['git','-C',str(repo),'archive','--format=tar',commit],stdout=f,check=True);os.fsync(f.fileno())
newsource=project/'source.new';newsource.mkdir(exist_ok=True)
with tarfile.open(source_tar) as t:t.extractall(newsource,filter='data')
for raw in git('ls-files','-z').split(b'\0'):
    if raw:
        path=raw.decode();p=newsource/path
        if not p.exists():
            p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(git('show',commit+':'+path))
line_endings_preserved=[]
for path,record in oldmanifest.items():
    p=newsource/path
    if path!='tools/subset-selector/README.md' and sha(p)!=record['sha256']:
        assert git('rev-parse',oldcommit+':'+path)==git('rev-parse',commit+':'+path),path
        shutil.copyfile(project/'source'/path,p);line_endings_preserved.append(path)
shutil.rmtree(project/'source');newsource.rename(project/'source')
manifest={str(p.relative_to(project/'source')):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted((project/'source').rglob('*')) if p.is_file()}
assert len(manifest)==len(git('ls-files','-z').split(b'\0'))-1
preserved=[p for p,m in oldmanifest.items() if p in manifest and manifest[p]==m]
modified=[p for p,m in oldmanifest.items() if manifest.get(p)!=m]
assert modified==['tools/subset-selector/README.md'],modified
(project/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
s=json.loads((root/'summary.json').read_text());r=s['variants']['legal-redress']
(project/'README.md').write_text(f'''# Fresh three-way performance and cache analysis

The complete experiment compares pinned original ClamAV, the retained full engine,
and the Legal Redress profile with the same toolchain, database and workload.
All 78 final processes verify enabled RAR runtime modules. CPU time/utilization,
RSS/PSS/USS, empty/hydrated OS pages, true clean-result cache hits, startup,
reload/update peaks, detection checks and database percentages are recorded.

Start with [the fresh report](source/docs/three-way-performance.md),
[exact text and image tables](source/docs/subset-selector-results/three-way-performance/tables/),
and [reproduction instructions](source/tools/subset-selector/performance/README.md).
Legal Redress loads {r['percent_full_signature_count']:.2f}% of engine-counted
signatures, with {r['compiled_rss_kib']['mean']/1024:.1f} MiB compiled RSS and
{r['reload']['hwm_kib']['max']/1024:.1f} MiB observed reload peak. Full update validation
overlapping both reduced engines reaches {r['update_overlap_peak_kib']/1024:.1f} MiB.

Use **`--database-profile=legal-redress`** on the provided `scan.py` or `intake.py`
adapter; **`--database-profile=full` remains the default**. Reduced scanning
forces accepting all-match mode. Full mode retains its existing first-hit default;
the controlled comparison enables all-match in all variants.

Original evidence preservation, independent narrative submission and signed
database verification remain required. Reduced no-detection candidates remain
held for unproven parser completeness. Automatic reduced release is disabled.
Preparation and full update validation remain separately budgeted operations.

The engine source and runtime defaults are unchanged. Earlier reports, patches,
experimental branches and raw evidence remain preserved. The input version 13
README and metadata are in `history/performance-analysis-input-v13/`.
`performance-analysis.patch` applies to source commit `{oldcommit}`;
its resulting tree was verified against the new bundled commit. Existing patches
remain byte-for-byte unchanged.
''')
revision={**old,'source_revision':commit,'source_tree':tree,'tracked_source_blobs':len(manifest),
          'previous_revision_metadata':old,'input_library_version':13,'input_archive_sha256':sha(prior),
          'source_history_bundle_sha256':sha(project/'source-history.bundle'),
          'performance_patch_base':oldcommit,'performance_patch_sha256':sha(project/'performance-analysis.patch'),
          'status':'Fresh 78-process controlled three-way CPU/RAM/cache/performance experiment; all final runtime modules verified; engine and release policies unchanged.',
          'test_scope':'source/docs/three-way-performance.md; source/docs/subset-selector-results/three-way-performance/',
          'performance_summary_sha256':sha(root/'summary.json')}
(project/'revision.json').write_text(json.dumps(revision,indent=2)+'\n')
proof={'input_archive_sha256':sha(prior),'input_library_version':13,'prior_source_commit':oldcommit,
       'current_source_commit':commit,'current_source_tree':tree,'unchanged_prior_source_files':len(preserved),
       'modified_prior_source_files':modified,'modified_prior_files_preserved_in_git_history':True,
       'all_prior_bundle_refs_preserved':True,'old_bundle_refs':len(oldrefs),
       'engine_source_unchanged':True,'source_tree_clean':True,'patch_reproduces_committed_tree':True,
       'historical_archive_line_endings_preserved':line_endings_preserved,
       'source_files':len(manifest),'new_source_files':len(manifest)-len(oldmanifest)}
(project/'archive-preservation.json').write_text(json.dumps(proof,indent=2)+'\n')

oldzip=zipfile.ZipFile(prior)
unchanged=0
for info in oldzip.infolist():
    if info.is_dir():continue
    name=info.filename;p=project/name
    if name.startswith('source/') or name in ('README.md','revision.json','source-manifest.json','archive-preservation.json','source-history.bundle'):continue
    assert p.is_file() and hashlib.sha256(oldzip.read(info)).hexdigest()==sha(p),name
    unchanged+=1
oldzip.close();proof['unchanged_non_source_input_files']=unchanged
(project/'archive-preservation.json').write_text(json.dumps(proof,indent=2)+'\n')
for p in project.rglob('*'):
    if p.is_file():sync(p)
temp=output.with_suffix('.zip.tmp')
with temp.open('w+b',buffering=0) as f:
    with zipfile.ZipFile(f,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
        for p in sorted(project.rglob('*')):
            if p.is_file():z.write(p,str(p.relative_to(project)));os.fsync(f.fileno())
    os.fsync(f.fileno())
with zipfile.ZipFile(temp) as z:
    assert z.testzip() is None
    for path,m in manifest.items():
        data=z.read('source/'+path);assert len(data)==m['bytes'] and hashlib.sha256(data).hexdigest()==m['sha256'],path
temp.replace(output)
fd=os.open(output.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
result={'archive':str(output),'bytes':output.stat().st_size,'sha256':sha(output),'source_commit':commit,'source_tree':tree,'source_files':len(manifest)}
(root/'archive-validation.json').write_text(json.dumps(result,indent=2)+'\n');sync(root/'archive-validation.json')
print(json.dumps(result,indent=2))
