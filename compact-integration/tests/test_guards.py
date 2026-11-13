#!/usr/bin/env python3
"""Actual production guard checks, unsigned synthetic signatures only.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse, hashlib, importlib.util, json, pathlib, subprocess, tempfile

def main():
    p=argparse.ArgumentParser();p.add_argument('--probe',required=True,type=pathlib.Path);p.add_argument('--certs',required=True,type=pathlib.Path)
    p.add_argument('--fixture-source',type=pathlib.Path,default=pathlib.Path(__file__).with_name('fixtures.py'));p.add_argument('--report',required=True,type=pathlib.Path);a=p.parse_args()
    module=importlib.util.spec_from_file_location('fixture_source',a.fixture_source);m=importlib.util.module_from_spec(module);module.loader.exec_module(m)
    cases=[]
    with tempfile.TemporaryDirectory(prefix='ci-guard-') as tmp:
        root=pathlib.Path(tmp);pe=m.make_pe();marker=m.MARKER.hex()
        files={'pe.bin':pe,'pe-renamed.pdf':pe,'raw.pdf':m.pdf(pe,''),'flate.pdf':m.pdf(pe),'hex.pdf':m.pdf(pe,'ASCIIHexDecode'),
               'nested.pdf':m.pdf(m.zip_bytes(pe)),'nested-pdf.pdf':m.pdf(m.pdf(pe)),'root.zip':m.zip_bytes(pe),
               'clean.pdf':m.pdf(b'ordinary harmless text'),'clean.txt':b'ordinary harmless text'}
        for name,data in files.items():(root/name).write_bytes(data)
        signatures={'ndb':f'Boundary.PE:1:*:{marker}\n','ldb':f'Boundary.PE;Target:1;0;{marker}\n',
                    'mdb':f'1024:{hashlib.md5(pe[512:]).hexdigest()}:Boundary.PE\n',
                    'msb':f'1024:{hashlib.sha256(pe[512:]).hexdigest()}:Boundary.PE\n',
                    'imp':f'{hashlib.md5(b"kernel32.exitprocess").hexdigest()}:20:Boundary.PE\n'}
        for family,sig in signatures.items():
            db=root/family;db.mkdir();(db/('test.'+family)).write_text(sig)
            # Retain an unrelated family to ensure a usable generic matcher with an empty PE matcher.
            (db/'keep.hdb').write_text(hashlib.md5(b'nonmatching').hexdigest()+':11:Boundary.Keep\n')
            paths=[root/n for n in files]+[root/'pe.bin',root/'clean.txt']
            def execute(guarded):
                r=subprocess.run([str(a.probe),str(db),str(a.certs),str(guarded),*map(str,paths)],check=True,text=True,capture_output=True,timeout=30)
                return [json.loads(line) for line in r.stdout.splitlines()]
            full,reduced=execute(0),execute(1)
            for name,x,y in zip(list(files)+['pe.bin','clean.txt'],full,reduced):
                positive=name not in ('clean.pdf','clean.txt')
                if positive:
                    assert any(n.startswith('Boundary.PE') for n in x['names']),(family,name,x)
                    assert y['flags']&1 and y['status']!=0,(family,name,y)
                    assert not any(n.startswith('Boundary.PE') for n in y['names'])
                else:
                    assert x['status']==y['status']==0 and y['flags']==0,(family,name,x,y)
                cases.append({'family':family,'file':name,'passed':True,'guarded':bool(y['flags']),'full_detected':bool(x['names'])})
            silent=execute(2)
            for name,y in zip(list(files)+['pe.bin','clean.txt'],silent):
                if name not in ('clean.pdf','clean.txt'):assert y['status']!=0,(family,name,y)
        # Retained HandlerType reclassification must also reach the production guard.
        db=root/'handler';db.mkdir();(db/'handler.ldb').write_text('Boundary.Handler;Engine:54-255,Target:0,HandlerType:CL_TYPE_MSEXE;0;'+marker+'\n')
        (db/'pe.ndb').write_text(signatures['ndb']);handler=root/'handler.pdf';handler.write_bytes(m.pdf(m.MARKER))
        def handler_run(mode):
            r=subprocess.run([str(a.probe),str(db),str(a.certs),str(mode),str(handler)],check=True,text=True,capture_output=True,timeout=30)
            return json.loads(r.stdout)
        full,reduced=handler_run(0),handler_run(1)
        assert any(name.startswith('Boundary.PE') for name in full['names']),full
        assert reduced['flags']&1 and reduced['status']!=0,reduced
        assert not any(name.startswith('Boundary.PE') for name in reduced['names'])
        cases.append({'family':'retained-handler','file':'handler.pdf','passed':True,'guarded':True,'full_detected':True})

    report={'protocol':1,'status':'passed','cases':len(cases),'checks':cases,'production_guard_used':True,
            'empty_target_matcher_tested':True,'repeated_scan_and_reset_tested':True,'missing_notification_tested':True,
            'cache_reenable_attempt_tested':True,'retained_handler_tested':True,'absolute_parser_completeness_claimed':False}
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='checks'}))
if __name__=='__main__':main()
