import json,os,subprocess,sys,time
from pathlib import Path
log=Path(sys.argv[1]);t=time.time()
with log.open('wb',buffering=0) as f:
 p=subprocess.run(sys.argv[2:],stdout=f,stderr=subprocess.STDOUT);os.fsync(f.fileno())
meta={'command':sys.argv[2:],'returncode':p.returncode,'seconds':time.time()-t}
log.with_suffix(log.suffix+'.status.json').write_text(json.dumps(meta,indent=2)+'\n')
print(json.dumps(meta));sys.exit(p.returncode)
