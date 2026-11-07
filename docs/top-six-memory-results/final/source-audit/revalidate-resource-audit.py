import importlib.util, hashlib, json, subprocess
from pathlib import Path
repo=Path('/workspace/clamav')
oldpath=Path('/workspace/qualify-pool-classes/directory-resource-audit.json')
oldraw=oldpath.read_bytes(); r=json.loads(oldraw)
prior='8dcd2a4'; base=r['baseline_source_revision']
def git(ref,path): return subprocess.check_output(['git','-C',str(repo),'show',ref+':'+path])
def sha(b): return hashlib.sha256(b).hexdigest()
# Recheck every whole-file identity retained by the independent audit.
whole={}
for path,expected in r['whole_files_unchanged'].items():
 data=(repo/path).read_bytes(); assert sha(data)==expected,(path,'audit hash mismatch')
 assert data==git(base,path),(path,'baseline file differs')
 whole[path]={'sha256':sha(data),'byte_equal_to_baseline':True}
for key,path in [('observed_matcher_ac_sha256','libclamav/matcher-ac.c'),('observed_mpool_sha256','libclamav/mpool.c')]:
 data=(repo/path).read_bytes(); assert sha(data)==r[key],(path,'changed since audit')
 assert data==git(prior,path),(path,'changed since prior source ref')
# Compare actual complete query function bodies against the retained baseline.
s=importlib.util.spec_from_file_location('q',repo/'tools/compact-memory/top-six-qualification/query_code_audit.py')
q=importlib.util.module_from_spec(s); s.loader.exec_module(q)
source=(repo/'libclamav/matcher-ac.c').read_text(); baseline=git(base,'libclamav/matcher-ac.c').decode()
rawbodies={}
for name in r['scan_and_context_functions_unchanged']:
 a=q.function_body(source,name); b=q.function_body(baseline,name)
 assert a==b,(name,'raw source body differs')
 rawbodies[name]={'raw_body_sha256':sha(a.encode()),'byte_equal_to_baseline':True}
# Permit exactly the requested compilation-boundary preprocessor change.
priorread=git(prior,'libclamav/readdb.c')
assert sha(priorread)==r['observed_readdb_sha256']
read=(repo/'libclamav/readdb.c').read_bytes()
old=b'#ifdef USE_MPOOL\n    /* All fallible compilation and all address-sensitive list ordering are\n'
new=b'#if defined(USE_MPOOL) && !defined(ENABLE_AC_DIRECTORY_RETENTION)\n    /* All fallible compilation and all address-sensitive list ordering are\n'
assert priorread.count(old)==1 and read.count(new)==1
assert read==priorread.replace(old,new,1),'unexpected additional readdb change'
assert read.count(b'\n')==priorread.count(b'\n')
priorcm=git(prior,'CMakeOptions.cmake'); cm=(repo/'CMakeOptions.cmake').read_bytes()
oldcm=b'option(ENABLE_AC_DIRECTORY_RETENTION\n    "Retain AC construction directories for internal census/export tools."\n    OFF)'
newcm=b'option(ENABLE_AC_DIRECTORY_RETENTION\n    "Retain AC construction directories (OFF enables unqualified retirement research)."\n    ON)'
assert priorcm.count(oldcm)==1 and cm==priorcm.replace(oldcm,newcm,1)
# Recheck pool table/layout/allocation helper region before mpool_create.
pool=(repo/'libclamav/mpool.c').read_text(); poolbase=git(base,'libclamav/mpool.c').decode()
start=pool.index('mpool_t *mpool_create') if 'mpool_t *mpool_create' in pool else pool.index('struct MP *mpool_create')
startbase=poolbase.index('mpool_t *mpool_create') if 'mpool_t *mpool_create' in poolbase else poolbase.index('struct MP *mpool_create')
assert pool[:start]==poolbase[:startbase]
r['observed_readdb_sha256']=sha(read)
r['revalidation']={
 'prior_audit_sha256':sha(oldraw),'prior_source_revision':subprocess.check_output(['git','-C',str(repo),'rev-parse',prior],text=True).strip(),
 'current_head_at_revalidation':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),
 'current_worktree_source_bound':True,'implementation_sha256':sha(Path(__file__).read_bytes()),
 'changed_files':{'libclamav/readdb.c':{'prior_sha256':sha(priorread),'current_sha256':sha(read),'exact_change':'Final retirement hook #ifdef USE_MPOOL becomes #if defined(USE_MPOOL) && !defined(ENABLE_AC_DIRECTORY_RETENTION); line count unchanged; all other bytes equal.'},'CMakeOptions.cmake':{'prior_sha256':sha(priorcm),'current_sha256':sha(cm),'exact_change':'Retention option default OFF becomes ON, with explanatory research-only OFF description; all other bytes equal.'}},
 'research_explicit_retention_OFF':{'old_gate':'defined(USE_MPOOL)','new_gate':'defined(USE_MPOOL) && !defined(ENABLE_AC_DIRECTORY_RETENTION)','equivalent_when_retention_undefined':True,'no_engine_source_change_for_this_configuration':True,'binary_rebuild_attested':False},
 'retention_ON_behavior':'The entire retirement root loop is now excluded; the original implementation called retirement helpers which were no-ops in this configuration.',
 'raw_query_function_bodies':rawbodies,'whole_files_rechecked':whole,
 'pool_prefix_before_mpool_create_byte_equal_to_baseline':True,
 'limits':'This is source revalidation with exact asserted changes, not build attestation or performance qualification. Original normalized-body hashes are retained because the entire matcher-ac.c file is byte-identical to the earlier audited file.'}
out=Path('/workspace/top-six-final-resource-audit.json');out.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'output':str(out),'sha256':sha(out.read_bytes()),'functions_rechecked':len(rawbodies),'whole_files_rechecked':len(whole),'observed_readdb_sha256':sha(read)}))
