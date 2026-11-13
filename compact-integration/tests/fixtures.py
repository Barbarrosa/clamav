# SPDX-License-Identifier: GPL-2.0-only
# Harmless structural fixture generators retained from the compact-memory research.
# Generated PE data is never executed.
import io
import struct
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



import base64

def png():
    return base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAFElEQVR4nGOUiWhlwAaYsIoOWgkAxzUBCb8z1VwAAAAASUVORK5CYII=')

def jpeg():
    return base64.b64decode('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAAIAAgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDiqKKK908E/9k=')
