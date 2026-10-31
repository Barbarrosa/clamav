#!/usr/bin/env python3
"""Additional benign broad-profile and hostile metadata cases; GPL-2.0-only."""
import argparse,io,json,subprocess,wave,zipfile
from pathlib import Path
from email.message import EmailMessage

def create(out,base):
    out.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(base/'document.docx') as a,zipfile.ZipFile(out/'document-clean.docx','w',zipfile.ZIP_DEFLATED) as b:
        for name in a.namelist():
            if not name.endswith('.exe'):b.writestr(name,a.read(name))
    msg=EmailMessage();msg['From']='synthetic@example.invalid';msg['To']='synthetic@example.invalid';msg.set_content('Synthetic benign email')
    msg.add_attachment((base/'clean.png').read_bytes(),maintype='image',subtype='png',filename='metadata.png')
    (out/'email-clean.eml').write_bytes(msg.as_bytes())
    with wave.open(str(out/'audio.wav'),'w') as w:w.setnchannels(1);w.setsampwidth(2);w.setframerate(8000);w.writeframes(b'\0\0'*8000)
    # Password is fixed PUBLIC test data, never a credential.
    subprocess.run(['zip','-j','-q','-P','public-fixture-password',str((out/'encrypted.zip').resolve()),str((base/'clean.pdf').resolve())],check=True)
    child=(base/'clean.png').read_bytes()
    for _ in range(22):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as a:a.writestr('nested',child)
        child=buf.getvalue()
    (out/'recursion-limit.zip').write_bytes(child)
    (out/'malformed.zip').write_bytes(b'PK\x03\x04'+b'\0'*80)
    (out.parent/'extra-fixtures.txt').write_text(''.join(str(p.resolve())+'\n' for p in sorted(out.iterdir())))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('base',type=Path);a=p.parse_args();create(a.output,a.base)
