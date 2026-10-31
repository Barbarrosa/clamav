#!/usr/bin/env python3
"""Explain a callback name without loading signatures. GPL-2.0-only."""
import argparse,json,sqlite3
from pathlib import Path
from select_db import sha
p=argparse.ArgumentParser();p.add_argument('generation',type=Path);p.add_argument('format');p.add_argument('name');a=p.parse_args()
m=json.loads((a.generation/'manifest.json').read_text())
if sha(a.generation/'decisions.sqlite')!=m['decision_sqlite_sha256']:raise ValueError('decision provenance mismatch')
db=sqlite3.connect((a.generation/'decisions.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
row=db.execute('SELECT eligible,occurrences,reason FROM names WHERE fmt=? AND name=?',(a.format,a.name.encode())).fetchone()
if row:result={'candidate_skip':bool(row[0]),'occurrences':row[1],'reason':row[2]}
elif a.format in m['family_exclusions']:result={'candidate_skip':True,'reason':'PE-specific hash format; root and nested PE must be held'}
else:result={'candidate_skip':False,'reason':'unknown/unclassified/effect-bearing format is retained'}
result['release_qualified']=False;print(json.dumps(result,indent=2))
