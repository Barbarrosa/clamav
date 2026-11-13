#!/usr/bin/env python3
"""Actual Ed25519 authentication plus isolated remote release/tuple fault tests.

GitHub/HTTP and native updater fixtures are explicit test doubles. Nothing is
published, no production key is used, and these are not live TLS/CDN tests.
"""
import asyncio
import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock

import test_gateway as gateway_tests
app = gateway_tests.app
release = app.release_client

UPDATER = r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=dict(zip(sys.argv[2::2],sys.argv[3::2]))
state=Path(args['--state'])
import hashlib
assert args['--expected-current-sha256']==hashlib.sha256((state/'current.json').read_bytes()).hexdigest()
with (state/'invocations.jsonl').open('a') as out:out.write(json.dumps(args)+'\n')
MODE=__MODE__
if MODE=='failed':sys.exit(1)
generation='gen-'+'2'*64
if MODE!='false-success':
 old=json.loads((state/'current.json').read_text())
 assert old.get('program')!=args['--program-id'] or old['generation']==generation
 value={'protocol':1,'generation':generation,'program':args['--program-id']}
 temporary=state/'test-next.json';temporary.write_text(json.dumps(value));os.replace(temporary,state/'current.json')
print(json.dumps({'protocol':1,'status':'updated','generation':generation,'next_attempt_after':None}))
'''


class ReleaseFixture(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='compact-release-test-')
        self.root=Path(self.temporary.name)
        self.programs=self.root/'programs'
        self.key=self.root/'test-private.pem'
        subprocess.run(['openssl','genpkey','-algorithm','Ed25519','-out',str(self.key)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        public=subprocess.check_output(['openssl','pkey','-in',str(self.key),'-pubout','-outform','DER'])
        self.public=base64.b64encode(public[-32:]).decode()
        self.mapping={}
        self.calls=[]
        self.client=self.new_client()

    def tearDown(self):
        # Installed bundles are deliberately read-only, including their directories.
        for directory,_,_ in __import__('os').walk(self.root):
            Path(directory).chmod(0o700)
        self.temporary.cleanup()

    def new_client(self, **kwargs):
        options=dict(programs=self.programs,public_key=self.public,channel='preview',staging_bytes=8*1024*1024,
                     metadata_bytes=1024*1024,wall_seconds=5,check_seconds=7200,disk_reserve_bytes=1,fetch=self.fetch)
        options.update(kwargs)
        return release.ReleaseClient(**options)

    async def fetch(self,url,limit,*,expected=None,sink=None):
        self.calls.append(url)
        status,headers,data=self.mapping[url]
        if isinstance(data,Exception):
            raise data
        if len(data)>limit:
            raise release.ReleaseError('test-transport-response-too-large')
        if sink is not None:
            sink.write(data)
            return status,headers,b''
        return status,headers,data

    def signed(self,manifest):
        raw=json.dumps(manifest,separators=(',',':')).encode()
        source=self.root/'signing-input';source.write_bytes(raw)
        signature=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(source)])
        self.assertEqual(len(signature),64)
        return raw,signature

    def fixture(self,sequence=1,mode='normal',marker='candidate'):
        scanner=gateway_tests.WORKER.replace('__MODE__',repr('normal')).replace(
            "print(json.dumps(result),flush=True)", "result['release_marker']="+repr(marker)+";print(json.dumps(result),flush=True)")
        payload={'bin/compact-scan':scanner.encode(),
                 'bin/compact-update':UPDATER.replace('__MODE__',repr(mode)).encode(),
                 'lib/compact-scan.real':b'explicit unused native fixture',
                 'lib/compact-update.real':b'explicit unused updater fixture',
                 'certs/clamav.crt':b'explicit release-file fixture, not a CVD trust test'}
        tag='compact-v0.1.'+str(sequence)
        files=[]
        for path,data in payload.items():
            digest=hashlib.sha256(data).hexdigest()
            url=release.DOWNLOAD+tag+'/'+digest[:16]+'--'+Path(path).name
            files.append({'path':path,'size':len(data),'sha256':digest,
                          'mode':'0400' if path.startswith('certs/') else '0500','url':url})
            self.mapping[url]=(200,{},data)
        manifest={'protocol':1,'sequence':sequence,'expires_at':int(time.time())+3600,'version':'0.1.'+str(sequence),
                  'channel':'preview','repository':release.REPOSITORY,'platform':release.PLATFORM,'tag':tag,'files':files,
                  'platform_requirements':{'architecture':'x86_64','libc':'glibc','minimum_glibc':'2.36','other_sonames':[]}}
        return manifest

    def discovery(self,manifest,raw,signature):
        tag=manifest['tag']
        assets=[{'name':name,'state':'uploaded','size':len(data),'browser_download_url':release.DOWNLOAD+tag+'/'+name}
                for name,data in [('manifest.json',raw),('manifest.sig',signature)]]
        value={'draft':False,'prerelease':True,'tag_name':tag,'assets':assets}
        self.mapping[release.API+'?per_page=3&page=1']=(200,{},json.dumps([value]).encode())
        self.mapping[release.DOWNLOAD+tag+'/manifest.json']=(200,{},raw)
        self.mapping[release.DOWNLOAD+tag+'/manifest.sig']=(200,{},signature)

class ReleaseTests(ReleaseFixture):
    async def test_missing_key_does_not_fetch_or_create_programs(self):
        client=self.new_client(public_key='')
        self.assertIsNone(await client.stage_next())
        self.assertEqual(client.health['status'],'disabled')
        self.assertEqual(self.calls,[])
        self.assertFalse(self.programs.exists())

    async def test_real_signature_stage_is_immutable_and_not_activation(self):
        manifest=self.fixture();raw,signature=self.signed(manifest)
        candidate=await self.client.stage(raw,signature)
        self.assertEqual(candidate.id,'pkg-'+hashlib.sha256(raw).hexdigest())
        self.assertEqual((candidate.path/'manifest.exact').read_bytes(),raw)
        self.assertEqual((candidate.path/'manifest.sig').read_bytes(),signature)
        scanner,updater,certs=release.resolve_program(self.programs,candidate.id)
        self.assertEqual(scanner.stat().st_mode&0o777,0o500)
        self.assertEqual((certs/'clamav.crt').stat().st_mode&0o777,0o400)
        self.assertEqual(candidate.path.stat().st_mode&0o777,0o500)
        self.assertFalse((self.programs/'current.json').exists())
        count=len(self.calls)
        self.assertEqual((await self.client.stage(raw,signature)).id,candidate.id)
        self.assertEqual(len(self.calls),count)

    async def test_tampered_or_foreign_signature_never_downloads_payload(self):
        manifest=self.fixture();raw,signature=self.signed(manifest)
        for wrong_raw,wrong_signature in [(raw+b' ',signature),(raw,signature[:-1]),(raw,b'x'*64)]:
            with self.subTest(case=len(wrong_signature)),self.assertRaises(release.ReleaseError):
                await self.client.stage(wrong_raw,wrong_signature)
        self.assertEqual(self.calls,[])
        self.assertEqual(list((self.programs/'releases').iterdir()),[])

    async def test_bad_paths_modes_and_external_urls_rejected_before_download(self):
        for path,mode,url in [('../escape','0500',None),('bin/../escape','0500',None),
                              ('bin//escape','0500',None),('bin/./escape','0500',None),
                              ('bin/compact-scan','0700',None),('bin/compact-scan','0500','https://evil.invalid/a')]:
            manifest=self.fixture();item=manifest['files'][0];item['path']=path;item['mode']=mode
            if url:item['url']=url
            raw,signature=self.signed(manifest)
            with self.subTest(path=path,mode=mode,url=url),self.assertRaises(release.ReleaseError):
                await self.client.stage(raw,signature)
        self.assertEqual(self.calls,[])

    async def test_expiry_channel_platform_and_integer_types_fail_closed(self):
        for field,value in [('expires_at',int(time.time())),('expires_at',True),('sequence',True),
                            ('protocol',True),('channel','stable'),('repository','other/clamav'),
                            ('platform','linux-aarch64'),('tag','compact-v9.9.9')]:
            manifest=self.fixture();manifest[field]=value;raw,signature=self.signed(manifest)
            with self.subTest(field=field,value=value),self.assertRaises(release.ReleaseError):
                await self.client.stage(raw,signature)
        self.assertEqual(self.calls,[])

    async def test_replay_floor_persists_even_after_interrupted_download(self):
        manifest=self.fixture(sequence=3);raw,signature=self.signed(manifest)
        item=manifest['files'][0];self.mapping[item['url']]=(200,{},b'wrong payload')
        with self.assertRaises(release.ReleaseError):
            await self.client.stage(raw,signature)
        self.assertEqual(list((self.programs/'staging').iterdir()),[])
        for sequence in (2,3):
            old=self.fixture(sequence=sequence,marker='replacement');old_raw,old_sig=self.signed(old)
            with self.subTest(sequence=sequence),self.assertRaisesRegex(release.ReleaseError,'replay'):
                await self.new_client().stage(old_raw,old_sig)

    async def test_discovery_signature_and_rate_limit_are_persisted(self):
        manifest=self.fixture();raw,signature=self.signed(manifest);self.discovery(manifest,raw,signature)
        candidate=await self.client.stage_next()
        self.assertEqual(self.client.health['status'],'staged')
        self.assertTrue(candidate.path.is_dir())
        self.assertIsNone(await self.new_client().stage_next())
        self.assertEqual(self.calls.count(release.API+'?per_page=3&page=1'),1)
        schedule=self.programs/'code-update-preview.json'
        release.atomic_json(schedule,{'next_at':0})
        retry=int(time.time())+10000
        self.mapping[release.API+'?per_page=3&page=1']=(429,{'retry-after':'10000','x-ratelimit-reset':str(retry)},b'')
        with self.assertRaises(release.ReleaseError):
            await self.new_client().stage_next()
        self.assertGreaterEqual(json.loads(schedule.read_text())['next_at'],retry)
        calls=len(self.calls)
        self.assertIsNone(await self.new_client().stage_next())
        self.assertEqual(len(self.calls),calls)

    async def test_preview_pagination_finds_candidate_with_one_shared_deadline(self):
        manifest=self.fixture();raw,signature=self.signed(manifest);self.discovery(manifest,raw,signature)
        first=release.API+'?per_page=3&page=1';second=release.API+'?per_page=3&page=2'
        self.mapping[second]=self.mapping[first]
        stable={'draft':False,'prerelease':False,'tag_name':'compact-v0.0.1','assets':[]}
        self.mapping[first]=(200,{},json.dumps([stable,stable,stable]).encode())
        candidate=await self.client.stage_next()
        self.assertTrue(candidate.path.is_dir())
        self.assertEqual(self.calls[:2],[first,second])
        # No candidate: stop at the protocol's bounded page count, not forever.
        client=self.new_client();client.deadline=time.monotonic()+5
        self.calls.clear()
        for page in range(1,21):
            self.mapping[release.API+'?per_page=3&page='+str(page)]=self.mapping[first]
        self.assertIsNone(await client.discover())
        self.assertEqual(len(self.calls),20)
        client.deadline=time.monotonic()-1
        with self.assertRaisesRegex(release.ReleaseError,'deadline'):
            await client.discover()
        self.assertEqual(len(self.calls),20)

    async def test_staging_allocation_and_disk_reserve_fail_without_payload(self):
        manifest=self.fixture();raw,signature=self.signed(manifest)
        for client in [self.new_client(staging_bytes=1),self.new_client()]:
            with mock.patch.object(release.shutil,'disk_usage',return_value=types.SimpleNamespace(free=0)):
                with self.assertRaises(release.ReleaseError):
                    await client.stage(raw,signature)
        self.assertEqual(self.calls,[])

    async def test_installed_content_and_symlink_rejected(self):
        manifest=self.fixture();raw,signature=self.signed(manifest)
        candidate=await self.client.stage(raw,signature)
        scanner=candidate.path/'bin/compact-scan';scanner.chmod(0o700);scanner.write_bytes(b'tampered');scanner.chmod(0o500)
        with self.assertRaisesRegex(release.ReleaseError,'content-changed'):
            release.resolve_program(self.programs,candidate.id)
        candidate.path.chmod(0o700)
        (candidate.path/'unexpected').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(release.ReleaseError):
            release.resolve_program(self.programs,candidate.id)

    async def test_http_parser_streams_chunks_and_rejects_redirect_or_oversize(self):
        client=self.new_client(fetch=None);client.prepare();client.deadline=time.monotonic()+5
        class Writer:
            def __init__(self):self.transport=self;self.closed=False
            def write(self,value):pass
            async def drain(self):pass
            def close(self):self.closed=True
            def abort(self):self.closed=True
        async def response(raw):
            reader=asyncio.StreamReader(limit=65536);reader.feed_data(raw);reader.feed_eof()
            writer=Writer()
            async def connect(*args,**kwargs):return reader,writer
            return connect,writer
        connect,writer=await response(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n')
        with mock.patch.object(release.asyncio,'open_connection',side_effect=connect):
            status,_,body=await client.fetch(release.API,3,expected=3)
        self.assertEqual((status,body),(200,b'abc'));self.assertTrue(writer.closed)
        for raw in [b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nxxxx',
                    b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n',
                    b'HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/a\r\n\r\n']:
            connect,writer=await response(raw)
            with mock.patch.object(release.asyncio,'open_connection',side_effect=connect):
                with self.assertRaises(release.ReleaseError):
                    await client.fetch(release.API,3)
            self.assertTrue(writer.closed)


class TupleTests(ReleaseFixture):
    async def gateway_fixture(self,mode='normal'):
        manifest=self.fixture(mode=mode);raw,signature=self.signed(manifest)
        candidate=await self.client.stage(raw,signature)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.scratch=self.root/'scratch';self.scratch.mkdir(mode=0o700)
        self.certs=self.root/'bootstrap-certs';self.certs.mkdir(mode=0o700)
        self.scanner=self.root/'bootstrap-scan';self.scanner.write_text(gateway_tests.WORKER.replace('__MODE__',repr('normal')));self.scanner.chmod(0o700)
        self.updater=self.root/'bootstrap-update';self.updater.write_text(gateway_tests.UPDATER.replace('__MODE__',repr('normal')));self.updater.chmod(0o700)
        (self.state/'current.json').write_text(json.dumps({'protocol':1,'generation':gateway_tests.GENERATION}))
        cfg=app.Config(scanner=self.scanner,updater=self.updater,state=self.state,scratch=self.scratch,certs=self.certs,
            token=gateway_tests.TOKEN,admin_token=gateway_tests.ADMIN,max_input_bytes=4096,disk_reserve_bytes=1,
            as_bytes=128*1024*1024,cpu_seconds=10,wall_seconds=3,file_bytes=1024*1024,output_bytes=8192,
            max_requests=5,max_age_seconds=86400,line_bytes=4096,connect_seconds=1,low_speed_seconds=1,max_attempts=1,
            programs=self.programs,release_public_key=self.public,release_channel='preview',code_staging_bytes=8*1024*1024,
            code_update_seconds=5,code_check_seconds=7200,max_state_bytes=16*1024*1024,max_state_inodes=1000)
        return cfg,candidate

    async def test_atomic_candidate_tuple_and_next_worker_use_new_program(self):
        cfg,candidate=await self.gateway_fixture()
        prior=json.loads((self.state/'current.json').read_text())
        self.assertNotIn('program',prior)  # staging alone never changes activation.
        async def stage_next():return candidate
        self.client.stage_next=stage_next
        self.client.health={'status':'staged','program':candidate.id}
        gateway=app.Gateway(cfg,releases=self.client)
        try:
            status,result=await gateway_tests.request(gateway,path='/v1/update',token=gateway_tests.ADMIN)
            self.assertEqual(status,200);self.assertEqual(result['code_update']['status'],'active')
            current=json.loads((self.state/'current.json').read_text())
            self.assertEqual(current['program'],candidate.id)
            self.assertEqual(current['generation'],result['generation'])
            invoked=json.loads((self.state/'invocations.jsonl').read_text().splitlines()[0])
            self.assertEqual(invoked['--scanner'],str(candidate.path/'bin/compact-scan'))
            self.assertEqual(invoked['--certs'],str(candidate.path/'certs'))
            self.assertEqual(invoked['--program-id'],candidate.id)
            self.assertEqual(invoked['--expected-current-sha256'],hashlib.sha256(json.dumps(prior).encode()).hexdigest())
            status,result=await gateway_tests.request(gateway,body=b'original')
            self.assertEqual(status,200);self.assertEqual(result['release_marker'],'candidate')
            gateway.releases=self.new_client(public_key='')
            status,result=await gateway_tests.request(gateway,path='/v1/update',token=gateway_tests.ADMIN)
            self.assertEqual(status,200);self.assertEqual(result['code_update']['status'],'disabled')
            invoked=json.loads((self.state/'invocations.jsonl').read_text().splitlines()[-1])
            self.assertEqual(invoked['--program-id'],candidate.id)
            self.assertEqual(invoked['--scanner'],str(candidate.path/'bin/compact-scan'))
        finally:
            await gateway.worker.stop()

    async def test_candidate_failure_or_false_success_updates_current_code_databases(self):
        for mode in ('failed','false-success'):
            with self.subTest(mode=mode):
                # Each case uses its own isolated programs/state directories.
                if hasattr(self,'state'):
                    shutil.rmtree(self.state);shutil.rmtree(self.scratch);shutil.rmtree(self.certs)
                    self.scanner.unlink();self.updater.unlink()
                    self.programs=self.root/('programs-'+mode);self.client=self.new_client()
                cfg,candidate=await self.gateway_fixture(mode)
                async def stage_next():return candidate
                self.client.stage_next=stage_next;self.client.health={'status':'staged'}
                gateway=app.Gateway(cfg,releases=self.client)
                status,result=await gateway_tests.request(gateway,path='/v1/update',token=gateway_tests.ADMIN)
                self.assertEqual(status,200);self.assertEqual(result['status'],'up_to_date')
                self.assertEqual(result['code_update']['status'],'failed')
                self.assertNotIn('program',json.loads((self.state/'current.json').read_text()))

    async def test_tampered_staged_candidate_falls_back_without_executing_it(self):
        cfg,candidate=await self.gateway_fixture()
        scanner=candidate.path/'bin/compact-scan'
        scanner.chmod(0o700);scanner.write_bytes(b'not trusted');scanner.chmod(0o500)
        async def stage_next():return candidate
        self.client.stage_next=stage_next;self.client.health={'status':'staged'}
        gateway=app.Gateway(cfg,releases=self.client)
        status,result=await gateway_tests.request(gateway,path='/v1/update',token=gateway_tests.ADMIN)
        self.assertEqual(status,200);self.assertEqual(result['status'],'up_to_date')
        self.assertEqual(result['code_update']['status'],'failed')
        self.assertFalse((self.state/'invocations.jsonl').exists())
        self.assertNotIn('program',json.loads((self.state/'current.json').read_text()))

    async def test_missing_key_and_network_failure_do_not_block_db_updates(self):
        cfg,_=await self.gateway_fixture()
        for key in ('',self.public):
            with self.subTest(key_configured=bool(key)):
                client=self.new_client(public_key=key)
                if key:self.mapping[release.API+'?per_page=3&page=1']=(503,{},release.ReleaseError('test-network-unavailable'))
                gateway=app.Gateway(cfg,releases=client)
                status,result=await gateway_tests.request(gateway,path='/v1/update',token=gateway_tests.ADMIN)
                self.assertEqual(status,200);self.assertEqual(result['status'],'up_to_date')
                self.assertEqual(result['code_update']['status'],'failed' if key else 'disabled')


if __name__=='__main__':
    unittest.main()
