#!/usr/bin/env python3
"""Only synthetic evidence and harmless upstream ClamAV test bytes. GPL-2.0-only."""
from pathlib import Path
import argparse, base64, hashlib, io, json, struct, zipfile, zlib
from email.message import EmailMessage
from PIL import Image, PngImagePlugin
from reportlab.pdfgen import canvas
from reportlab.lib.pdfencrypt import StandardEncryption


def fixtures(out, upstream):
    out.mkdir(parents=True,exist_ok=True)
    pnginfo=PngImagePlugin.PngInfo();pnginfo.add_text('EvidenceMetadata','synthetic-original-metadata-retained')
    im=Image.new('RGB',(1024,768),(60,100,140)); im.save(out/'clean.png',pnginfo=pnginfo)
    im.save(out/'clean.jpg',quality=90,exif=b'Exif\0\0SYNTHETIC_METADATA')
    def pdf(path,encrypt=None,pages=1):
        c=canvas.Canvas(str(path),invariant=1,encrypt=encrypt)
        c.setAuthor('Synthetic evidence metadata');c.setTitle('Synthetic Legal Redress attachment')
        for i in range(pages):
            c.drawString(50,750,'Synthetic attachment; no real complaint data. '+str(i));c.showPage()
        c.save()
    pdf(out/'clean.pdf');pdf(out/'long.pdf',pages=100)
    pdf(out/'encrypted.pdf',StandardEncryption('synthetic-test-password',ownerPassword='synthetic-owner'))
    (out/'misleading-mime.exe').write_bytes((out/'clean.pdf').read_bytes())
    pe=(upstream/'clam.exe').read_bytes()
    (out/'renamed-pe.pdf').write_bytes(pe)
    (out/'plain.txt').write_text('synthetic narrative attachment, unsupported initial root')
    (out/'truncated.png').write_bytes((out/'clean.png').read_bytes()[:75])
    (out/'broken.pdf').write_bytes(b'%PDF-1.7\n1 0 obj << /Type /Catalog >>\nstream\nMZ\n')
    (out/'empty.png').write_bytes(b'')
    (out/'oversized.pdf').write_bytes(b'%PDF-1.7\n'+b'X'*(5*1024*1024))
    z=io.BytesIO()
    with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as a:a.writestr('proof.exe',pe)
    (out/'nested-pe.zip').write_bytes(z.getvalue())
    (out/'pdf-zip-polyglot.pdf').write_bytes((out/'clean.pdf').read_bytes()+z.getvalue())
    (out/'png-appended-pe.png').write_bytes((out/'clean.png').read_bytes()+pe)
    with zipfile.ZipFile(out/'clean.zip','w',zipfile.ZIP_DEFLATED) as a:a.writestr('image.png',(out/'clean.png').read_bytes())
    with zipfile.ZipFile(out/'nested.zip','w',zipfile.ZIP_DEFLATED) as a:a.writestr('inner.zip',z.getvalue())
    with zipfile.ZipFile(out/'document.docx','w',zipfile.ZIP_DEFLATED) as a:
        a.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        a.writestr('word/document.xml','<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Synthetic document</w:t></w:r></w:p></w:body></w:document>')
        a.writestr('word/embeddings/proof.exe',pe)
    email=EmailMessage();email['From']='synthetic@example.invalid';email['To']='fixture@example.invalid';email.set_content('Synthetic evidence only');email.add_attachment(pe,maintype='application',subtype='octet-stream',filename='evidence.pdf')
    (out/'nested-pe.eml').write_bytes(email.as_bytes())
    # PDF embedded file, decoded before matching; length and xref constructed exactly.
    payload=zlib.compress(pe)
    objects=[b'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(proof.exe) 4 0 R] >> >> >>',
             b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 400] >>',
             b'<< /Type /Filespec /F (proof.exe) /EF << /F 5 0 R >> >>',
             b'<< /Type /EmbeddedFile /Filter /FlateDecode /Length '+str(len(payload)).encode()+b' >>\nstream\n'+payload+b'\nendstream']
    data=b'%PDF-1.7\n';offsets=[0]
    for i,obj in enumerate(objects,1):offsets.append(len(data));data+=str(i).encode()+b' 0 obj\n'+obj+b'\nendobj\n'
    xref=len(data);data+=b'xref\n0 6\n0000000000 65535 f \n'+b''.join(f'{o:010d} 00000 n \n'.encode() for o in offsets[1:])
    data+=f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode();(out/'embedded-pe.pdf').write_bytes(data)
    # Many valid accepted files with differing contents, no scan-cache assistance.
    for i in range(20):
        p=PngImagePlugin.PngInfo();p.add_text('Fixture',str(i));im.save(out/f'photo-{i:02}.png',pnginfo=p)
    paths=sorted(p.resolve() for p in out.iterdir() if p.is_file())
    (out.parent/'fixtures.txt').write_text(''.join(str(p)+'\n' for p in paths))
    (out.parent/'fixture-manifest.json').write_text(json.dumps([{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths],indent=2)+'\n')
    return paths

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('upstream_generated',type=Path);a=p.parse_args();fixtures(a.output,a.upstream_generated)
