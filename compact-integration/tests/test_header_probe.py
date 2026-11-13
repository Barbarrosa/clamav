#!/usr/bin/env python3
"""Bounded FreshClam metadata callback and real loopback HTTP regressions."""
import ast
import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest


class HeaderProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('CI_SOURCE'):
            raise unittest.SkipTest('materialized patched source required (CI_SOURCE)')
        cls.source=Path(os.environ['CI_SOURCE'])
        cls.temporary=tempfile.TemporaryDirectory(prefix='compact-header-probe-')
        cls.root=Path(cls.temporary.name)
        source=(cls.source/'libfreshclam/libfreshclam_internal.c').read_text()
        start=source.index('struct MemoryStruct {');end=source.index('struct FileStruct {',start)
        callback=source[start:end]
        wrapper=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CVD_HEADER_SIZE 512
#define LOGG_ERROR 0
#define logg(...) ((void)0)
static int fail_allocation;
static size_t largest_allocation;
static void *checked_realloc(void *old,size_t size) {
 if(size>largest_allocation)largest_allocation=size;
 if(fail_allocation)return NULL;
 return realloc(old,size);
}
#define realloc checked_realloc
'''+callback+r'''
int main(void) {
 char body[16384];memset(body,'A',sizeof(body));
 struct MemoryStruct value={0};
 assert(WriteMemoryCallback(body,1,512,&value)==512);
 assert(value.size==512 && !value.prefix_complete && value.buffer[512]==0);
 assert(WriteMemoryCallback(body,1,1,&value)==0 && value.prefix_complete);free(value.buffer);
 value=(struct MemoryStruct){0};
 assert(WriteMemoryCallback(body,1,513,&value)==0 && value.prefix_complete && value.size==512);free(value.buffer);
 value=(struct MemoryStruct){0};
 assert(WriteMemoryCallback(body,1,sizeof(body),&value)==0 && value.prefix_complete && value.size==512);free(value.buffer);
 value=(struct MemoryStruct){0};
 assert(WriteMemoryCallback(body,1,300,&value)==300);
 assert(WriteMemoryCallback(body+300,1,213,&value)==0 && value.prefix_complete && value.size==512);free(value.buffer);
 value=(struct MemoryStruct){0};
 assert(WriteMemoryCallback(body,SIZE_MAX,2,&value)==0 && !value.prefix_complete && value.size==0);
 assert(WriteMemoryCallback(body,1,300,&value)==300);fail_allocation=1;
 assert(WriteMemoryCallback(body,1,213,&value)==0 && !value.prefix_complete && value.size==300);free(value.buffer);
 assert(largest_allocation<=513);
 puts("six callback boundary/overflow/allocation cases passed; allocation<=513");
 return 0;
}
'''
        (cls.root/'callback.c').write_text(wrapper)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(cls.root/'callback.c'),'-o',str(cls.root/'callback')],check=True)
        tree=ast.parse((cls.source/'unit_tests/freshclam_test.py').read_text())
        handler=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='WebServerHandler_02')
        cls.header=next(n.value for n in ast.walk(handler) if isinstance(n,ast.Constant)
                        and isinstance(n.value,bytes) and len(n.value)>=512)[:512]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_callback_keeps_only_prefix_for_513_large_and_fragmented_chunks(self):
        result=subprocess.run([str(self.root/'callback')],capture_output=True,text=True,check=True)
        self.assertIn('allocation<=513',result.stdout)

    def http_probe(self, *, body, metadata_status=206, fragmented=False, expected=17):
        build=os.environ.get('CI_BUILD')
        if not build:
            self.skipTest('real FreshClam build required (CI_BUILD)')
        binary=Path(build)/'freshclam/freshclam'
        if not binary.is_file():self.skipTest('FreshClam executable unavailable')
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                is_range='Range' in self.headers
                requests.append(is_range)
                self.send_response(metadata_status if is_range else 403)
                self.send_header('Content-Length',str(len(body) if is_range else 9))
                self.end_headers()
                try:
                    if not is_range:self.wfile.write(b'Forbidden');return
                    if fragmented:
                        self.wfile.write(body[:300]);self.wfile.flush();time.sleep(0.02)
                        self.wfile.write(body[300:]);self.wfile.flush()
                    else:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='http-',dir=self.root) as temporary:
                root=Path(temporary);db=root/'db';db.mkdir(mode=0o700)
                config=root/'freshclam.conf'
                config.write_text('DatabaseMirror http://127.0.0.1:'+str(server.server_port)+'\n'
                    'DNSDatabaseInfo no\nDatabaseOwner '+getpass.getuser()+'\nDatabaseDirectory '+str(db)+'\n'
                    'MaxAttempts 1\nConnectTimeout 2\nReceiveTimeout 2\nLogVerbose yes\n')
                result=subprocess.run([str(binary),'--no-dns','--config-file='+str(config),'--update-db=daily'],
                                      capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
                self.assertIn(True,requests)
                if expected==17:
                    self.assertIn('Forbidden',result.stderr+result.stdout)
                    self.assertTrue((db/'freshclam.dat').is_file())
                if metadata_status in (403,429):
                    self.assertNotIn(False,requests)
                    self.assertTrue((db/'freshclam.dat').is_file())
                    count=len(requests)
                    again=subprocess.run([str(binary),'--no-dns','--config-file='+str(config),'--update-db=daily'],
                                         capture_output=True,text=True,timeout=15)
                    self.assertEqual(again.returncode,0,again.stdout+again.stderr)
                    self.assertEqual(len(requests),count)
                    self.assertIn('cool-down',again.stdout+again.stderr)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_real_513_byte_range_retains_header_then_forbidden(self):
        self.http_probe(body=self.header+b' ')

    def test_real_large_range_body_is_bounded_then_forbidden(self):
        self.http_probe(body=self.header+b'x'*(512*1024))

    def test_real_fragmented_range_retains_header_then_forbidden(self):
        self.http_probe(body=self.header+b' ',fragmented=True)

    def test_real_malformed_header_remains_rejected(self):
        self.http_probe(body=b'\0'*513,expected=11)

    def test_real_403_cvd_looking_body_cannot_become_success(self):
        self.http_probe(body=self.header+b'x'*65536,metadata_status=403)

    def test_real_429_cvd_looking_body_preserves_cooldown(self):
        # Upstream version discovery maps this error to exit11; the persisted
        # upstream cooldown must still prevent the next request.
        self.http_probe(body=self.header+b'x'*65536,metadata_status=429,expected=11)


if __name__=='__main__':unittest.main()
