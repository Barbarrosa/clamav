#!/usr/bin/env python3
"""Actually exercise verifier rejection and byte-for-byte intake preservation.
Run only on synthetic fixtures and the supplied public signed DB. GPL-2.0-only.
"""
import argparse,gzip,json,os,tempfile
from pathlib import Path
from select_db import sha,verify
p=argparse.ArgumentParser()
for k in ['database','lib','certs','output']:p.add_argument('--'+k,type=Path,required=True)
a=p.parse_args();verify(a.database,a.lib,a.certs)
with tempfile.TemporaryDirectory() as d:
    bad=Path(d)/'bytecode.cvd';b=bytearray(a.database.read_bytes());b[-13]^=1;bad.write_bytes(b)
    rejected=False
    try:verify(bad,a.lib,a.certs)
    except ValueError:rejected=True
    if not rejected:raise AssertionError('modified signed CVD was accepted')
    report={'valid_signature_accepted':True,'modified_signature_rejected':True,'original_sha256':sha(a.database),'tampered_sha256':sha(bad)}
with tempfile.TemporaryDirectory() as d:
    raw=a.database.read_bytes();cld=Path(d)/'bytecode.cld';cld.write_bytes(raw[:512]+gzip.decompress(raw[512:]));verify(cld,a.lib,a.certs)
    report['same_signed_members_cld_transport_verified']=True
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
