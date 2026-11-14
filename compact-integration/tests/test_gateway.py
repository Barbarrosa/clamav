#!/usr/bin/env python3
"""ASGI and native-pipe lifecycle tests; no deployment or network access."""
import asyncio
import gc
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('compact_gateway',ROOT/'service/app.py')
app=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=app
spec.loader.exec_module(app)
TOKEN='s'*48
ADMIN='a'*48
GENERATION='gen-'+'1'*64


class FakeWorker:
    def __init__(self):
        self.calls=[]
        self.stops=0
        self.started=asyncio.Event()
        self.release=None

    async def scan(self,path,profile,sha,size):
        assert path.stat().st_mode & 0o777 == 0o400
        data=path.read_bytes()
        assert hashlib.sha256(data).hexdigest()==sha and len(data)==size
        self.calls.append((path,profile,sha,size))
        self.started.set()
        if self.release:
            await self.release.wait()
        return {'protocol':1,'status':'clean','sha256':sha,'size':size}

    async def stop(self):
        self.stops+=1


async def request(gateway, *, body=b'data', query=b'', headers=None, path='/v1/scan',
                  method='POST', token=TOKEN, events=None, receive_hook=None):
    raw=[(b'authorization',('Bearer '+token).encode()),
         (b'content-length',str(len(body)).encode()),
         (b'x-content-sha256',hashlib.sha256(body).hexdigest().encode())]
    if headers is not None:
        raw=headers
    scope={'type':'http','path':path,'method':method,'query_string':query,'headers':raw}
    queue=list(events if events is not None else [{'type':'http.request','body':body,'more_body':False}])
    sent=[]
    async def receive():
        if receive_hook:
            return await receive_hook()
        return queue.pop(0)
    async def send(message):
        sent.append(message)
    await gateway(scope,receive,send)
    return sent[0]['status'],json.loads(sent[-1]['body'])


WORKER=r'''#!/usr/bin/env python3
import hashlib,json,os,sys,time
from pathlib import Path
MODE=__MODE__
assert os.environ['COMPACT_PARENT_PID']==str(os.getppid())
if sys.argv[1]=='doctor':
 if MODE=='doctor-flood':
  print('x'*1000000);sys.exit(0)
 if MODE=='doctor-hang':
  time.sleep(30)
 print(json.dumps({'protocol':1,'status':'ready','engine_sha256':'2'*64,'scan_options_sha256':'3'*64}))
 sys.exit(0)
args=dict(zip(sys.argv[2::2],sys.argv[3::2]))
assert Path(args['--certs']).is_dir()
assert os.fstat(int(args['--lock-fd'])).st_size==0
for line in sys.stdin:
 job=json.loads(line)
 if MODE=='hang':time.sleep(30)
 if MODE=='stdout-flood':print('x'*1000000,flush=True);continue
 if MODE=='stderr-flood':
  sys.stderr.write('x'*1000000);sys.stderr.flush();time.sleep(30)
 data=Path(job['input']).read_bytes()
 profile=args['--profile']
 result={'protocol':1,'completed':True,'status':'clean','applicability_proven':True,'coverage_qualified':True,
 'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),
 'requested_profile':profile,'effective_profile':profile,'generation_id':Path(args['--generation']).name[4:],
 'request_id':job['request_id'],'findings':[],'reason_codes':[]}
 if MODE=='bad-echo':result['request_id']='foreign'
 if MODE=='bad-generation':result['generation_id']='4'*64
 if MODE=='unqualified':result['coverage_qualified']=False
 if MODE=='incomplete':result['completed']=False
 print(json.dumps(result),flush=True)
'''
UPDATER=r'''#!/usr/bin/env python3
import json,os,sys,time
assert os.environ['COMPACT_PARENT_PID']==str(os.getppid())
MODE=__MODE__
if MODE=='updater-flood':
 sys.stderr.write('x'*1000000);sys.stderr.flush();time.sleep(30)
if MODE=='updater-hang':time.sleep(30)
print(json.dumps({'protocol':1,'status':'up_to_date','generation':'gen-'+'1'*64,'next_attempt_after':None}))
'''


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='compact-gateway-test-')
        self.root=Path(self.tmp.name)
        self.scratch=self.root/'scratch';self.scratch.mkdir(mode=0o700)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.certs=self.root/'certs';self.certs.mkdir(mode=0o700)
        (self.state/'current.json').write_text(json.dumps({'protocol':1,'generation':GENERATION}))
        self.scanner=self.root/'scanner'
        self.updater=self.root/'updater'
        self.set_programs()
        self.config=app.Config(scanner=self.scanner,state=self.state,scratch=self.scratch,token=TOKEN,
            max_input_bytes=4096,disk_reserve_bytes=1,as_bytes=128*1024*1024,cpu_seconds=10,
            wall_seconds=2,file_bytes=1024*1024,output_bytes=8192,max_requests=2,max_age_seconds=86400,
            admin_token=ADMIN,updater=self.updater,certs=self.certs,line_bytes=4096,
            connect_seconds=1,low_speed_seconds=1,max_attempts=1,max_state_bytes=16*1024*1024,max_state_inodes=1000,
            # Explicit test-only allocations remove pacing between unrelated
            # fixture assertions; dedicated tests exercise the real low limits.
            cpu_hour_seconds=3600*1000000,cpu_day_seconds=86400*1000000,cpu_month_seconds=2678400*1000000)
        self.worker=FakeWorker()
        self.gateway=app.Gateway(self.config,self.worker)
        self.native=[]

    def set_programs(self,worker='normal',updater='normal'):
        self.scanner.write_text(WORKER.replace('__MODE__',repr(worker)));self.scanner.chmod(0o700)
        self.updater.write_text(UPDATER.replace('__MODE__',repr(updater)));self.updater.chmod(0o700)

    async def asyncTearDown(self):
        for worker in self.native:
            await worker.stop()
        for process in tuple(self.gateway.processes):
            await app.kill_process(process)
        self.tmp.cleanup()

    async def test_authentication_and_duplicate_headers(self):
        self.assertEqual((await request(self.gateway,token='bad'))[0],401)
        self.assertEqual((await request(self.gateway,headers=[(b'authorization',b'\xff')]))[0],401)
        self.assertEqual((await request(self.gateway,headers=[
            (b'authorization',b'Bearer '+TOKEN.encode()),(b'Authorization',b'Bearer '+TOKEN.encode())]))[0],400)
        self.assertEqual(self.worker.calls,[])

    async def test_stream_identity_and_cleanup_before_response(self):
        status,row=await request(self.gateway,body=b'abc',events=[
            {'type':'http.request','body':b'a','more_body':True},
            {'type':'http.request','body':b'bc','more_body':False}])
        self.assertEqual(status,200);self.assertEqual(row['sha256'],hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(len(self.worker.calls),1)
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_invalid_query_is_400(self):
        for query in (b'profile',b'profile=',b'profile=full&profile=full',b'\xff',b'x=full'):
            with self.subTest(query=query):
                self.assertEqual((await request(self.gateway,query=query))[0],400)
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_size_and_hash_failures_never_scan(self):
        self.assertEqual((await request(self.gateway,body=b'x'*4097))[0],413)
        headers=[(b'authorization',b'Bearer '+TOKEN.encode()),(b'content-length',b'2'),
                 (b'x-content-sha256',hashlib.sha256(b'ab').hexdigest().encode())]
        self.assertEqual((await request(self.gateway,body=b'abc',headers=headers))[0],400)
        self.assertEqual((await request(self.gateway,body=b'cd',headers=headers))[0],400)
        self.assertEqual(self.worker.calls,[])
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_disconnect_and_input_timeout_cleanup(self):
        self.assertEqual((await request(self.gateway,events=[{'type':'http.disconnect'}]))[0],400)
        gateway=app.Gateway(replace(self.config,wall_seconds=0.05),self.worker)
        async def stalled():
            await asyncio.sleep(30)
        self.assertEqual((await request(gateway,receive_hook=stalled))[0],503)
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_capacity_failure_does_not_create_input(self):
        with mock.patch.object(app.shutil,'disk_usage',return_value=types.SimpleNamespace(free=0)):
            self.assertEqual((await request(self.gateway))[0],503)
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_busy_scans_and_updates_serialize(self):
        self.worker.release=asyncio.Event()
        first=asyncio.create_task(request(self.gateway))
        await self.worker.started.wait()
        self.assertEqual((await request(self.gateway))[0],503)
        maintenance=asyncio.create_task(request(self.gateway,path='/v1/update',token=ADMIN))
        while not self.gateway.maintenance_waiting:
            await asyncio.sleep(0)
        self.assertEqual((await request(self.gateway))[0],503)
        self.worker.release.set()
        self.assertEqual((await first)[0],200)
        self.assertEqual((await maintenance)[0],200)
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_admin_token_is_separate_and_cannot_supply_commands(self):
        self.assertEqual((await request(self.gateway,path='/v1/update'))[0],404)
        self.assertEqual((await request(self.gateway,path='/v1/update',token=ADMIN,query=b'url=foreign'))[0],400)
        status,row=await request(self.gateway,path='/v1/update',token=ADMIN)
        self.assertEqual(status,200);self.assertEqual(row['status'],'up_to_date')
        self.assertGreater(self.worker.stops,0)
        self.assertEqual(self.gateway.processes,set())

    async def test_doctor_and_updater_outputs_and_deadlines_are_bounded(self):
        for mode,updater in [('doctor-flood','normal'),('doctor-hang','normal'),
                             ('normal','updater-flood'),('normal','updater-hang')]:
            with self.subTest(mode=mode,updater=updater):
                self.set_programs(mode,updater)
                gateway=app.Gateway(replace(self.config,wall_seconds=0.15),self.worker)
                result=await asyncio.wait_for(request(gateway,path='/v1/update',token=ADMIN),2)
                self.assertEqual(result[0],503)
                self.assertEqual(gateway.processes,set())

    async def test_native_worker_has_certs_echo_and_rotates_profiles(self):
        worker=app.NativeWorker(self.config);self.native.append(worker)
        path=self.root/'original';path.write_bytes(b'original')
        sha=hashlib.sha256(b'original').hexdigest()
        first=await worker.scan(path,'full',sha,8)
        old=worker.process
        second=await worker.scan(path,'pdf-jpeg-png-pe-exclusions',sha,8)
        self.assertNotEqual(first['request_id'],second['request_id'])
        self.assertIsNot(worker.process,old)
        self.assertIsNotNone(old.returncode)

    async def test_native_mismatched_or_unqualified_results_stop_process(self):
        for mode in ('bad-echo','bad-generation','unqualified','incomplete','stdout-flood','stderr-flood','hang'):
            with self.subTest(mode=mode):
                self.set_programs(mode)
                worker=app.NativeWorker(replace(self.config,wall_seconds=0.15));self.native.append(worker)
                path=self.root/'original';path.write_bytes(b'original')
                with self.assertRaises(Exception):
                    await asyncio.wait_for(worker.scan(path,'full',hashlib.sha256(b'original').hexdigest(),8),2)
                self.assertIsNone(worker.process)

    async def test_missing_state_policy_disables_updates_but_keeps_scanning(self):
        gateway=app.Gateway(replace(self.config,max_state_bytes=0,max_state_inodes=0),self.worker)
        status,row=await request(gateway,path='/v1/update',token=ADMIN)
        self.assertEqual((status,row['error']),(503,'update-state-policy-not-configured'))
        self.assertEqual((await request(gateway))[0],200)
        self.assertEqual(len(self.worker.calls),1)

    async def test_pid_fallback_kills_child_without_session(self):
        process=await asyncio.create_subprocess_exec(sys.executable,'-c','import time; time.sleep(30)')
        await asyncio.wait_for(app.kill_process(process),2)
        self.assertIsNotNone(process.returncode)

    async def test_cancelled_scan_removes_private_temp(self):
        self.worker.release=asyncio.Event()
        task=asyncio.create_task(request(self.gateway))
        await self.worker.started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(list(self.scratch.iterdir()),[])

    async def test_unknown_cpu_allocations_defer_both_routes_without_native_work(self):
        gateway=app.Gateway(replace(self.config,cpu_month_seconds=0),self.worker)
        for path,token,code in [('/v1/scan',TOKEN,'scan_budget_unknown'),
                                ('/v1/update',ADMIN,'maintenance_budget_unknown')]:
            status,row=await request(gateway,path=path,token=token)
            self.assertEqual((status,row['error']),(503,code))
        status,row=await request(gateway,path='/v1/status',method='GET')
        self.assertEqual(status,200);self.assertFalse(row['scan_budget']['configured'])
        self.assertEqual(self.worker.calls,[]);self.assertEqual(self.worker.stops,0)
        self.assertEqual(list(self.scratch.iterdir()),[])
        self.assertFalse((self.state/'service-work-budget.bin').exists())

    async def test_zero_input_never_consumes_budget_or_starts_native_work(self):
        status,row=await request(self.gateway,body=b'')
        self.assertEqual((status,row['error']),(400,'empty-input-not-accepted'))
        self.assertEqual(self.worker.calls,[])
        self.assertFalse((self.state/'service-work-budget.bin').exists())

    async def test_tiny_flood_is_paced_and_restart_does_not_reset_debt(self):
        config=replace(self.config,cpu_seconds=0.1,cpu_hour_seconds=3600,
                       cpu_day_seconds=86400,cpu_month_seconds=2678400)
        gateway=app.Gateway(config,self.worker)
        self.assertEqual((await request(gateway,body=b'x'))[0],200)
        ledger=self.state/'service-work-budget.bin';identity=ledger.stat()
        with mock.patch.object(gateway.budget,'reserve',wraps=gateway.budget.reserve) as reserve:
            for _ in range(20):
                self.assertEqual((await request(gateway,body=b'x'))[0],503)
            self.assertEqual(reserve.call_count,0)  # cached denials avoid ledger I/O.
        self.assertEqual((ledger.stat().st_ino,ledger.stat().st_mtime_ns),
                         (identity.st_ino,identity.st_mtime_ns))
        restarted=app.Gateway(config,self.worker)
        self.assertEqual((await request(restarted,body=b'x'))[0],503)
        self.assertEqual(len(self.worker.calls),1)
        snapshot=restarted.budget.snapshot()
        self.assertEqual(snapshot['windows']['hour']['scan_seconds'],1)

    async def test_pre_scan_ingress_failures_keep_a_healthy_worker(self):
        self.assertEqual((await request(self.gateway))[0],200)
        gateway=app.Gateway(replace(self.config,wall_seconds=0.1),self.worker)
        async def stalled():await asyncio.sleep(30)
        self.assertEqual((await request(gateway,receive_hook=stalled))[0],503)
        self.assertEqual(self.worker.stops,0);self.assertEqual(len(self.worker.calls),1)
        self.assertEqual(list(self.scratch.iterdir()),[])
        self.assertEqual((await request(gateway))[0],200)

    async def test_response_backpressure_releases_processing_slot_and_has_deadline(self):
        gateway=app.Gateway(replace(self.config,response_seconds=0.08),self.worker)
        ready=asyncio.Event();responses=[]
        async def receive():return {'type':'http.request','body':b'x','more_body':False}
        async def blocked_send(message):
            responses.append(message)
            if message['type']=='http.response.body':
                ready.set();await asyncio.Event().wait()
        scope={'type':'http','path':'/v1/scan','method':'POST','query_string':b'',
               'headers':[(b'authorization',b'Bearer '+TOKEN.encode()),(b'content-length',b'1'),
                          (b'x-content-sha256',hashlib.sha256(b'x').hexdigest().encode())]}
        first=asyncio.create_task(gateway(scope,receive,blocked_send))
        await ready.wait()
        self.assertFalse(gateway.lock.locked());self.assertEqual(list(self.scratch.iterdir()),[])
        self.assertEqual((await request(gateway,body=b'next'))[0],200)
        with self.assertRaises(TimeoutError):await first
        self.assertEqual(self.worker.stops,0)

    async def test_separate_gateway_cannot_duplicate_global_work(self):
        self.worker.release=asyncio.Event()
        first=asyncio.create_task(request(self.gateway))
        await self.worker.started.wait()
        second_worker=FakeWorker();second=app.Gateway(self.config,second_worker)
        self.assertEqual((await request(second))[0],503)
        self.assertEqual(second_worker.calls,[])
        self.worker.release.set();self.assertEqual((await first)[0],200)

    async def test_maintenance_intent_blocks_other_gateways_and_cancellation_releases_it(self):
        self.worker.release=asyncio.Event()
        first=asyncio.create_task(request(self.gateway))
        await self.worker.started.wait()
        pending=asyncio.create_task(request(self.gateway,path='/v1/update',token=ADMIN))
        while not self.gateway.maintenance_waiting:await asyncio.sleep(0)
        other=app.Gateway(self.config,FakeWorker())
        status,row=await request(other)
        self.assertEqual((status,row['error']),(503,'maintenance-pending'))
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):await pending
        self.assertFalse(self.gateway.maintenance_waiting)
        intent=app.work_budget.acquire_lease(self.state,'service-maintenance.lock')
        self.assertIsNotNone(intent);intent.close()
        self.worker.release.set();self.assertEqual((await first)[0],200)

    async def test_native_lease_precedes_runtime_verification_and_releases_on_stop(self):
        worker=app.NativeWorker(self.config);self.native.append(worker)
        original=app.Config.runtime;observed=[]
        def runtime(config,current):
            probe=app.work_budget.acquire_lease(config.state,'job.lock')
            observed.append(probe is None)
            if probe is not None:probe.close()
            return original(config,current)
        path=self.root/'original';path.write_bytes(b'original')
        with mock.patch.object(app.Config,'runtime',runtime):
            await worker.scan(path,'full',hashlib.sha256(b'original').hexdigest(),8)
        self.assertEqual(observed,[True])
        await worker.stop()
        released=app.work_budget.acquire_lease(self.state,'job.lock')
        self.assertIsNotNone(released);released.close()

    async def test_cancelled_admin_child_is_reaped_and_all_admission_leases_release(self):
        self.set_programs(updater='updater-hang')
        task=asyncio.create_task(request(self.gateway,path='/v1/update',token=ADMIN))
        while not self.gateway.processes:await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(self.gateway.processes,set());self.assertFalse(self.gateway.lock.locked())
        for name in ('service-maintenance.lock','service-admission.lock'):
            lease=app.work_budget.acquire_lease(self.state,name)
            self.assertIsNotNone(lease);lease.close()

    async def test_insufficient_code_cpu_reserve_still_runs_trusted_database_update(self):
        config=replace(self.config,release_public_key='configured-test-placeholder',code_update_seconds=1,
                       cpu_hour_seconds=20,cpu_day_seconds=20,cpu_month_seconds=20)
        releases=types.SimpleNamespace(health={'status':'configured'},stage_next=mock.AsyncMock())
        gateway=app.Gateway(config,self.worker,releases)
        status,row=await request(gateway,path='/v1/update',token=ADMIN)
        self.assertEqual((status,row['status']),(200,'up_to_date'))
        self.assertEqual(row['code_update']['reason'],'code-cpu-budget-unavailable')
        releases.stage_next.assert_not_awaited()

    async def test_cancelled_command_retrieves_original_gather_result(self):
        loop=asyncio.get_running_loop();previous=loop.get_exception_handler();unhandled=[]
        loop.set_exception_handler(lambda _loop,context:unhandled.append(context))
        processes=set()
        try:
            task=asyncio.create_task(app.bounded_command(
                [sys.executable,'-c','import time;time.sleep(30)'],
                output_bytes=8192,wall_seconds=2,processes=processes))
            while not processes:await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
            self.assertEqual(processes,set())
            del task
            gc.collect();await asyncio.sleep(0)
            self.assertEqual(unhandled,[])
        finally:
            for process in tuple(processes):await app.kill_process(process)
            loop.set_exception_handler(previous)


if __name__=='__main__':
    unittest.main()
