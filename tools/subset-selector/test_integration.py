#!/usr/bin/env python3
"""Run real-engine synthetic policy and exact ordering/severity gates.
GPL-2.0-only. Requires the built scan_probe and harmless generated fixture dir.
"""
import argparse, collections, hashlib, json, os, subprocess
from pathlib import Path
from equivalence import detection_equivalent


def read(path):return [json.loads(l) for l in Path(path).read_text().splitlines() if l.startswith('{')]
def scans(path):return [r for r in read(path) if r['kind']=='scan']
def semantic(r):return {k:r[k] for k in ['return_code','verdict','final_name','root_type','scanned_bytes','events']}
def names(r):return [e['name'] for e in r['events'] if e['event']=='alert']

def run(args,db,skip,files,label,action=0,env=None):
    dest=args.output/(label+'.jsonl')
    with dest.open('w') as out,(args.output/(label+'.stderr')).open('w') as err:
        p=subprocess.run([str(args.probe),str(db),str(args.certs),str(skip),str(files),'1','0',str(action),'0'],stdout=out,stderr=err,env=env)
    if p.returncode:raise RuntimeError(f'{label}: scanner exited {p.returncode}')
    return scans(dest)

def main(a):
    a.output.mkdir(parents=True,exist_ok=True)
    # Accepted PDF with a harmless repeated marker; PE distractors change allocation sizes.
    marker=a.output/'marker.pdf';marker.write_bytes(b'%PDF-1.7\n%'+b' '*1024+b'ABCDEFGH'+b' '*1024+b'\n%%EOF\n')
    files=a.output/'files.txt';files.write_text(str(marker.resolve())+'\n')
    fixtures=[]
    for kind in ['strong','weak','pua','weak-only','pua-only']:
        db=a.output/kind;db.mkdir(exist_ok=True);skip=db/'skip.tsv'
        exclusions=[]
        with (db/'test.ndb').open('w') as f:
            for i in range(a.rules):
                prefix='Heuristics' if kind.startswith('weak') else 'PUA' if kind.startswith('pua') else 'Synthetic'
                if kind in ('weak','pua') and i==a.rules//2:prefix='Synthetic.Strong'
                f.write(f'{prefix}.Order.{i:05d}:0:*:41424344??464748\n')
                digest=hashlib.sha256(f'distractor/{i}'.encode()).hexdigest()[:24]
                f.write(f'PE.Excluded.{i:05d}:1:*:{digest[:12]}??{digest[14:]}\n');exclusions.append(f'ndb\tPE.Excluded.{i:05d}\n')
        skip.write_text(''.join(exclusions))
        for action in ([0,1,2,3] if kind=='strong' else [0]):
            full=run(a,db,'-',files,f'{kind}-{action}-full',action)
            reduced=run(a,db,skip,files,f'{kind}-{action}-reduced',action)
            for x,y in zip(full,reduced):
                fixtures.append({'kind':kind,'action':action,'allmatch':x['allmatch'],
                    'exact_equal':semantic(x)==semantic(y),'same_verdict':x['verdict']==y['verdict'],
                    'same_alert_multiset':collections.Counter(names(x))==collections.Counter(names(y)),
                    'detection_equivalent':detection_equivalent(x,y),
                    'full_first':names(x)[:1],'reduced_first':names(y)[:1],
                    'full_count':len(names(x)),'reduced_count':len(names(y)),
                    'full_holds':x['hold_bits'],'reduced_holds':y['hold_bits']})
    # Generic handler retags accepted PDF as PE without relying on extension/magic.
    db=a.output/'handler';db.mkdir(exist_ok=True)
    (db/'test.ldb').write_text('Synthetic.Handler;Engine:54-255,Target:0,HandlerType:CL_TYPE_MSEXE;0;4142434445464748\n')
    (db/'test.ndb').write_text('PE.Excluded:1:*:41424344??464748\n')
    skip=db/'skip.tsv';skip.write_text('ndb\tPE.Excluded\n')
    handler=run(a,db,skip,files,'handler-reduced')
    assert all(r['hold_bits']&1 for r in handler), 'HandlerType must set sticky PE hold'
    # False-positive trust data must retain trust verdict rather than invent a detection.
    db=a.output/'trust';db.mkdir(exist_ok=True)
    (db/'test.hdb').write_text(f'{hashlib.md5(marker.read_bytes()).hexdigest()}:{marker.stat().st_size}:Synthetic.WholeFile\n')
    (db/'test.fp').write_text(f'{hashlib.md5(marker.read_bytes()).hexdigest()}:{marker.stat().st_size}:Synthetic.Allow\n')
    (db/'test.ndb').write_text('PE.Excluded:1:*:41424344??464748\n');skip=db/'skip.tsv';skip.write_text('ndb\tPE.Excluded\n')
    full=run(a,db,'-',files,'trust-full');reduced=run(a,db,skip,files,'trust-reduced')
    assert all(semantic(x)==semantic(y) and x['verdict']==1 for x,y in zip(full,reduced))
    # Low test-only file size ceiling, applied identically. Not used for performance claims.
    env=os.environ.copy();env['SUBSET_TEST_MAX_FILESIZE']='1024'
    limited=run(a,db,skip,files,'limited-reduced',env=env)
    assert all(r['candidate_outcome']!='clean' for r in limited)
    missing=a.output/'missing.txt';missing.write_text(str(a.output/'does-not-exist.pdf')+'\n')
    err=run(a,db,skip,missing,'missing-reduced');assert all(r['candidate_outcome']=='failed' for r in err)
    # Full syntax errors must not disappear behind a selector skip.
    db=a.output/'invalid-pe-rule';db.mkdir(exist_ok=True)
    (db/'test.ndb').write_text('Generic.Keep:0:*:0102030405060708\nPE.Invalid:1:*:THIS_IS_NOT_HEX\n')
    skip=db/'skip.tsv';skip.write_text('ndb\tPE.Invalid\n')
    rejected=False
    try:run(a,db,'-',files,'invalid-rule-full')
    except RuntimeError:rejected=True
    assert rejected, 'invalid full database unexpectedly loaded'
    reduced_invalid=run(a,db,skip,files,'invalid-rule-reduced')
    assert reduced_invalid, 'demonstrate why full validation is mandatory'
    summary={'rules_per_severity_fixture':a.rules,'comparisons':fixtures,
             'invalid_PE_rule_requires_full_load_check':True,'handler_reclassification_held':True,'trust_equal':True,'limits_held':True,'missing_failed':True,
             'qualification_passed':all(f['exact_equal'] for f in fixtures),
             'accepting_allmatch_detection_equivalence_passed':all(f['detection_equivalent'] for f in fixtures if f['action']==0 and f['allmatch']==1),
             'automatic_release_qualified':False}
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
    if a.require_equivalence and not summary['qualification_passed']:raise SystemExit(3)
    if a.require_detections and not summary['accepting_allmatch_detection_equivalence_passed']:raise SystemExit(4)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for k in ['probe','certs','output']:p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--rules',type=int,default=10000);p.add_argument('--require-equivalence',action='store_true')
    p.add_argument('--require-detections',action='store_true',help='require accepting all-match detection multisets, severity and layer policy to match')
    a=p.parse_args()
    a.probe=a.probe.resolve();a.certs=a.certs.resolve();a.output=a.output.resolve();main(a)
