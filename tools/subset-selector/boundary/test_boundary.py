#!/usr/bin/env python3
"""Real full/subset PE exclusion contract. Blanket outcome=held never counts.
Unsigned synthetic DBs and non-executed synthetic PE data only. GPL-2.0-only.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import zipfile
import zlib

MARKER=b'SUBSET_BOUNDARY_6f3a129d'


def make_pe():
    data=bytearray(0x600)
    data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0';struct.pack_into('<HHIIIHH',data,0x84,0x14c,1,0,0,0,224,0x102)
    o=0x98;struct.pack_into('<H',data,o,0x10b)
    for offset,value in {4:0x400,16:0x1000,20:0x1000,24:0x1000,28:0x400000,32:0x1000,36:0x200,56:0x2000,60:0x200,72:0x100000,76:0x1000,80:0x100000,84:0x1000,92:16}.items():struct.pack_into('<I',data,o+offset,value)
    struct.pack_into('<H',data,o+40,4);struct.pack_into('<H',data,o+48,4);struct.pack_into('<H',data,o+68,3)
    struct.pack_into('<II',data,o+104,0x1100,40)
    sec=o+224;data[sec:sec+8]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,sec+8,0x400,0x1000,0x400,0x200);struct.pack_into('<I',data,sec+36,0x60000020)
    data[0x200]=0xc3;data[0x220:0x220+len(MARKER)]=MARKER
    struct.pack_into('<IIIII',data,0x300,0x11a0,0,0,0x1180,0x11b0)
    data[0x380:0x38d]=b'KERNEL32.dll\0'
    struct.pack_into('<II',data,0x3a0,0x11c0,0);struct.pack_into('<II',data,0x3b0,0x11c0,0)
    data[0x3c2:0x3ce]=b'ExitProcess\0'
    return bytes(data)


def zip_bytes(data):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('evidence.bin',data)
    return out.getvalue()


def pdf(payload,encoding='FlateDecode'):
    stream=zlib.compress(payload) if encoding=='FlateDecode' else payload.hex().encode()+b'>' if encoding=='ASCIIHexDecode' else payload
    filters=b'/Filter /'+encoding.encode()+b' ' if encoding else b''
    objects=[b'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(evidence.bin) 4 0 R] >> >> >>',
      b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>',
      b'<< /Type /Filespec /F (evidence.bin) /EF << /F 5 0 R >> >>',
      b'<< /Type /EmbeddedFile '+filters+b'/Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream']
    data=b'%PDF-1.7\n';offsets=[]
    for i,obj in enumerate(objects,1):offsets.append(len(data));data+=str(i).encode()+b' 0 obj\n'+obj+b'\nendobj\n'
    xref=len(data);data+=b'xref\n0 6\n0000000000 65535 f \n'+b''.join(f'{o:010d} 00000 n \n'.encode() for o in offsets)
    return data+f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()


def create_fixtures(root):
    root.mkdir(parents=True,exist_ok=True);pe=make_pe()
    from PIL import Image
    im=Image.new('RGB',(8,8),(28,88,133));png=io.BytesIO();im.save(png,format='PNG');jpg=io.BytesIO();im.save(jpg,format='JPEG')
    values={'root-pe.pdf':pe,'embedded-raw.pdf':pdf(pe,''),'embedded-flate.pdf':pdf(pe),
      'embedded-asciihex.pdf':pdf(pe,'ASCIIHexDecode'),'nested-zip.pdf':pdf(zip_bytes(pe)),
      'nested-pdf.pdf':pdf(pdf(pe)),'png-appended.png':png.getvalue()+pe,
      'jpeg-appended.jpg':jpg.getvalue()+pe,'root.zip':zip_bytes(pe),
      'clean.pdf':pdf(b'ordinary harmless text'),'clean.png':png.getvalue(),
      'broken.pdf':b'%PDF-1.7\n1 0 obj << /Type /Catalog >>\nstream\nMZ\n',
      'handler.pdf':pdf(MARKER),'raw-embedded.exe':pe+pe}
    for name,data in values.items():(root/name).write_bytes(data)
    return {name:root/name for name in values}


def execute(a,db,skips,paths,label,extra=None):
    listing=a.output/(label+'.files');listing.write_text(''.join(str(p.resolve())+'\n' for p in paths))
    env=os.environ.copy();env.update(extra or {})
    cmd=[str(a.probe),str(db),str(a.certs),str(skips),str(listing),'1','0','0','0','all']
    with (a.output/(label+'.jsonl')).open('w') as out,(a.output/(label+'.stderr')).open('w') as err:
        result=subprocess.run(cmd,stdout=out,stderr=err,env=env,timeout=120)
    if result.returncode:raise RuntimeError((label,result.returncode))
    rows=[json.loads(x) for x in (a.output/(label+'.jsonl')).read_text().splitlines() if x.startswith('{') and json.loads(x).get('kind')=='scan']
    if len(rows)!=len(paths) or [r.get('path') for r in rows]!=[str(p.resolve()) for p in paths]:
        raise AssertionError('missing, duplicate, reordered or unexpected scan rows: '+label)
    return rows


def boundary_ok(row):
    witnesses=[e for e in row['events'] if e.get('event')=='boundary_witness' and e['site']!='MaxEmbeddedPE-skip']
    return bool(witnesses) and all(e['hold_bits_before']&1 for e in witnesses) and bool(row['hold_bits']&1)


def main(a):
    a.output.mkdir(parents=True,exist_ok=False);paths=create_fixtures(a.output/'fixtures');pe=make_pe()
    names={'ndb':'Boundary.PE.NDB','ldb':'Boundary.PE.LDB','mdb':'Boundary.PE.MDB','msb':'Boundary.PE.MSB','imp':'Boundary.PE.IMP'}
    signatures={
      'ndb':f"{names['ndb']}:1:*:{MARKER.hex()}\n",
      'ldb':f"{names['ldb']};Target:1;0;{MARKER.hex()}\n",
      'mdb':f"1024:{hashlib.md5(pe[512:]).hexdigest()}:{names['mdb']}\n",
      'msb':f"1024:{hashlib.sha256(pe[512:]).hexdigest()}:{names['msb']}\n",
      'imp':f"{hashlib.md5(b'kernel32.exitprocess').hexdigest()}:20:{names['imp']}\n"}
    cases=[];all_sites=set();failures=[]
    positive_names=['root-pe.pdf','embedded-raw.pdf','embedded-flate.pdf','embedded-asciihex.pdf','nested-zip.pdf','nested-pdf.pdf','png-appended.png','root.zip','raw-embedded.exe']
    for family,sig in signatures.items():
        db=a.output/('db-'+family);db.mkdir(exist_ok=True)
        (db/'keep.ndb').write_text('Boundary.Keep:0:*:0123456789abcdef0123456789abcdef\n')
        (db/('test.'+family)).write_text(sig)
        skip=db/'skip.tsv';skip.write_text(family+'\t'+(names[family] if family in ('ndb','ldb') else '*')+'\n')
        selected=[paths[n] for n in positive_names]+[paths['clean.pdf'],paths['clean.png'],paths['broken.pdf'],paths['jpeg-appended.jpg']]
        full=execute(a,db,'-',selected,family+'-full');reduced=execute(a,db,skip,selected,family+'-reduced')
        for x,y in zip(full,reduced):
            name=Path(x['path']).name
            detection=any(e.get('name','') and e['name'].startswith(names[family]) for e in x['events'])
            absent=not any(e.get('name','') and e['name'].startswith(names[family]) for e in y['events'])
            witnesses=[e for e in y['events'] if e.get('event')=='boundary_witness']
            all_sites.update(e['site'] for r in (x,y) for e in r['events'] if e.get('event')=='boundary_witness')
            expected=name in positive_names
            passed=(detection and absent and boundary_ok(x) and boundary_ok(y)) if expected else (not detection and absent and not (y['hold_bits']&1))
            row={'family':family,'file':name,'expected_positive':expected,'full_detected_target_rule':detection,
                'reduced_omitted_target_rule':absent,'specific_pe_hold':bool(y['hold_bits']&1),
                'full_boundary_guarded':boundary_ok(x) if expected else None,
                'baseline_unobserved_content':name=='jpeg-appended.jpg',
                'witnesses':witnesses,'passed':passed,'full_candidate':x['candidate_outcome'],'reduced_candidate':y['candidate_outcome']}
            cases.append(row)
            if not passed:failures.append(family+'/'+name)
        if family=='ndb':
            mutated=execute(a,db,skip,[paths['embedded-flate.pdf']],'negative-control',{'SUBSET_TEST_DISABLE_PE_HOLD':'1'})[0]
            mutation_rejected=(any(e.get('event')=='boundary_witness' for e in mutated['events'])
                and not (mutated['hold_bits']&1) and not boundary_ok(mutated))
            # Lower just this one internal threshold; preserve normal max-file/scan limits.
            limited_full=execute(a,db,'-',[paths['raw-embedded.exe']],'embedded-limit-full',{'SUBSET_TEST_MAX_EMBEDDED_PE':'64'})[0]
            limited_reduced=execute(a,db,skip,[paths['raw-embedded.exe']],'embedded-limit-reduced',{'SUBSET_TEST_MAX_EMBEDDED_PE':'64'})[0]
            skip_seen=any(e.get('site')=='MaxEmbeddedPE-skip' for e in limited_reduced['events'])
            # Generic handler forces a PDF layer into PE semantics without relying on initial magic.
            (db/'handler.ldb').write_text('Boundary.Handler;Engine:54-255,Target:0,HandlerType:CL_TYPE_MSEXE;0;'+MARKER.hex()+'\n')
            handler_full=execute(a,db,'-',[paths['handler.pdf']],'handler-full')[0]
            handler=execute(a,db,skip,[paths['handler.pdf']],'handler-reduced')[0]
            handler_passed=boundary_ok(handler) and boundary_ok(handler_full) and any(e.get('name','') and e['name'].startswith(names['ndb']) for e in handler_full['events'])
    required_sites={'cli_scan_fmap-PE','cli_scanpe','scan_pe_imp','scan_pe_mdb'}
    summary={'passed':(not failures and len(cases)==65 and mutation_rejected and handler_passed
        and skip_seen and bool(limited_reduced['hold_bits']&1) and required_sites<=all_sites),
       'expected_cases':65,'observed_cases':len(cases),'required_witness_sites':sorted(required_sites),
       'cases':cases,'failures':failures,'witness_sites_seen':sorted(all_sites),
       'mutation_without_PE_hold_rejected':mutation_rejected,'handler_guard_passed':handler_passed,
       'embedded_limit_skip_observed':skip_seen,'embedded_limit_specific_hold':bool(limited_reduced['hold_bits']&1),
       'blanket_release_hold_not_used_as_evidence':True,'shared_baseline_limitations':['JPEG appended PE is not reached/detected by either variant; not counted as a positive coverage case.','Malformed PDF has no automatic parse-error hold in either variant.'],'automatic_release_qualified':False}
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='cases'},indent=2))
    if not summary['passed']:raise SystemExit(4)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('probe','certs','output'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args()
    for key,v in vars(a).items():setattr(a,key,v.resolve())
    main(a)
