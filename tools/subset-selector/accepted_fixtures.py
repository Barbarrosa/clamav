#!/usr/bin/env python3
"""Deterministic valid PDF/JPEG/PNG throughput set, including incompressible images.
No omitted-type files or policy holds may be counted as throughput improvements.
GPL-2.0-only.
"""
import argparse,hashlib,json,random
from pathlib import Path
from PIL import Image,PngImagePlugin
from reportlab.pdfgen import canvas
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('base',type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
pixels=random.Random(42).randbytes(1600*1200*3);im=Image.frombytes('RGB',(1600,1200),pixels)
info=PngImagePlugin.PngInfo();info.add_text('Evidence','synthetic-incompressible-image')
im.save(a.output/'noisy.png',pnginfo=info);im.save(a.output/'noisy.jpg',quality=90)
c=canvas.Canvas(str(a.output/'image-document.pdf'),invariant=1);c.setAuthor('Synthetic metadata preserved');c.drawImage(str(a.output/'noisy.png'),0,0,width=600,height=450);c.save()
paths=[(a.base/n).resolve() for n in ['clean.png','clean.jpg','clean.pdf','long.pdf','misleading-mime.exe']]
paths+=sorted(p.resolve() for p in a.base.glob('photo-*.png'))+sorted(p.resolve() for p in a.output.iterdir())
(a.output.parent/'accepted.txt').write_text(''.join(str(p)+'\n' for p in paths))
(a.output.parent/'accepted-manifest.json').write_text(json.dumps([{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths],indent=2)+'\n')
