import json,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1];run=root/'backport-run';src=root/'stable/tools/subset-selector';sys.path.insert(0,str(src))
from equivalence import detection_equivalent
report=[]
for kind in ('strong','weak','pua','weak-only','pua-only'):
 label=kind+'-0' if kind=='strong' else kind+'-0'
 out=run/'synthetic-stable'/(kind+'-original.jsonl')
 cmd=[str(run/'probe-stable-original'),str(run/'synthetic-stable'/kind),str(root/'stable/certs'),'-',str(run/'synthetic-stable/files.txt'),'1','0','0','0']
 with out.open('w') as f,(out.with_suffix('.stderr')).open('w') as e:subprocess.run(cmd,stdout=f,stderr=e,check=True,timeout=120)
 old=[json.loads(x) for x in out.read_text().splitlines() if json.loads(x)['kind']=='scan']
 new=[json.loads(x) for x in (run/'synthetic-stable'/(label+'-full.jsonl')).read_text().splitlines() if json.loads(x)['kind']=='scan']
 assert len(old)==len(new)==2
 for x,y in zip(old,new):
  exact={k:v for k,v in x.items() if k!='seconds'}=={k:v for k,v in y.items() if k!='seconds'}
  equivalent=detection_equivalent(x,y) if x['allmatch'] else None
  report.append({'family':kind,'allmatch':x['allmatch'],'exact':exact,'detection_equivalent':equivalent})
  if x['allmatch']:assert equivalent,(kind,'allmatch detection changed')
summary={'accepting_allmatch_passed':True,'comparisons':report}
(run/'stable-original-synthetic.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
