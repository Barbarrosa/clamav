"""Synthetic intake protocol fixtures. No real engine verdicts are fabricated for reports."""
import json
from pathlib import Path
import time
import select_db


def generation(path):
    path.mkdir()
    (path/'manifest.json').write_text(json.dumps({'signed_databases':[
        {'name':'daily.cvd','header':'ClamAV-VDB:test:'+str(int(time.time()))}]}))
    return path


def result(folder, lib, profile='full', candidate='clean', holds=0):
    digest=select_db.sha(folder/'original')
    verdict=2 if candidate=='detected' else 0
    rc=2 if candidate=='failed' else 1 if verdict==2 else 0
    row=dict(kind='scan',path=str((folder/'original').resolve()),round=0,
        allmatch=int(profile=='pdf-jpeg-png-pe-exclusions'),candidate_outcome=candidate,hold_bits=holds,
        events=[],verdict=verdict,return_code=rc,scanned_bytes=10,sha256=digest,after_sha256=digest,
        final_name='Test.Detection' if verdict==2 else None,root_type='CL_TYPE_PDF',
        outcome='held' if profile=='pdf-jpeg-png-pe-exclusions' and candidate=='clean' else candidate,
        release_blocker='parser-completeness-unproven' if profile=='pdf-jpeg-png-pe-exclusions' else None)
    rows=[dict(kind='runtime',engine_sha256=select_db.sha(lib),unrar_modules_verified=1),
          dict(kind='engine',signatures=10),row,dict(kind='batch',round=0,allmatch=row['allmatch'])]
    return row, '\n'.join(map(json.dumps,rows))
