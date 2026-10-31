#!/usr/bin/env python3
"""Failure-injection and native process-lifecycle regression tests. GPL-2.0-only."""
import copy
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import intake
import runner
import select_db
from storage import write_json, exclusive_lock
import test_support


class IntakeHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.source=self.root/'evidence';self.source.write_bytes(b'original evidence')
        self.folder,self.record=intake.preserve(self.source,self.root/'quarantine')
        self.lib=self.root/'lib';self.lib.write_bytes(b'engine')
        self.gen=test_support.generation(self.root/'generation')
        self.row,self.stdout=test_support.result(self.folder,self.lib)
    def tearDown(self):self.tmp.cleanup()
    def validate(self, rows=None, profile='full'):
        text=self.stdout if rows is None else '\n'.join(map(json.dumps,rows))
        return intake.validate_result(text,self.folder/'original',self.record['sha256'],profile,self.lib)
    def assess(self, output=None, **kwargs):
        with patch.object(intake,'command',return_value=['/fake-probe']),patch.object(intake,'run_scanner',return_value=SimpleNamespace(returncode=0,stdout=output or self.stdout)):
            return intake.assess(self.folder,self.gen,'/probe',self.lib,'/certs',**kwargs)
    def test_private_durable_files(self):
        self.assertEqual(stat.S_IMODE((self.folder/'original').stat().st_mode),0o400)
        self.assertEqual(stat.S_IMODE((self.folder/'record.json').stat().st_mode),0o600)
        self.assertFalse(self.record['release_qualified'])
        self.assertEqual(self.record['bytes'],len(self.source.read_bytes()))
    def test_oversize_keeps_source(self):
        with self.assertRaisesRegex(ValueError,'size exceeds'):intake.preserve(self.source,self.root/'quarantine',1)
        self.assertEqual(self.source.read_bytes(),b'original evidence')
    def test_nonregular_source(self):
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError,'regular'):intake.preserve(fifo,self.root/'quarantine')
    def test_existing_temp_symlink_not_followed(self):
        target=self.root/'sentinel';target.write_text('unchanged')
        (self.folder/'record.next.json').symlink_to(target)
        self.assertEqual(self.assess()['outcome'],'clean')
        self.assertEqual(target.read_text(),'unchanged')
    def test_corrupt_outcomes_fail_closed(self):
        for values in [dict(candidate_outcome='unexpected'),dict(candidate_outcome='held'),
                dict(outcome='held'),dict(hold_bits=-1),dict(hold_bits='0'),dict(verdict=99),
                dict(return_code=2),dict(return_code=True),dict(allmatch=1),dict(round=1),
                dict(path='/different-original'),dict(sha256='mismatch'),dict(after_sha256='mismatch'),
                dict(events={}),dict(events=[None]),dict(final_name='Detection'),
                dict(events=[{'event':'legacy_virus','name':'Detection'}]),dict(scanned_bytes=-1)]:
            with self.subTest(values=values):
                rows=[json.loads(x) for x in self.stdout.splitlines()];rows[2].update(values)
                with self.assertRaises(ValueError):self.validate(rows)
    def test_unknown_candidate_never_clean_in_intake(self):
        rows=[json.loads(x) for x in self.stdout.splitlines()];rows[2]['candidate_outcome']='future-outcome'
        result=self.assess('\n'.join(map(json.dumps,rows)))
        self.assertEqual(result['outcome'],'failed');self.assertFalse(result['release_qualified'])
    def test_missing_duplicate_or_unknown_rows(self):
        rows=[json.loads(x) for x in self.stdout.splitlines()]
        for bad in [rows[:-1],rows+rows[2:3],rows+[{'kind':'future'}],rows+[[]]]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):self.validate(bad)
    def test_runtime_binding_and_modules(self):
        for update in [dict(engine_sha256='other'),dict(unrar_modules_verified=0)]:
            rows=[json.loads(x) for x in self.stdout.splitlines()];rows[0].update(update)
            with self.assertRaisesRegex(ValueError,'runtime'):self.validate(rows)
    def test_legacy_results_preserve_return_code_and_holds(self):
        for profile,candidate,holds in [('full','clean',0),('full','detected',0),
                ('legal-redress','clean',0),('legal-redress','detected',0),
                ('legal-redress','held',1),('full','failed',0)]:
            with self.subTest(profile=profile,candidate=candidate,holds=holds):
                _,output=test_support.result(self.folder,self.lib,profile,candidate,holds)
                rows=[json.loads(x) for x in output.splitlines()]
                rows[0]['scan_api']='legacy-1.4';rows[2]['verdict']=None
                row,_,_=self.validate(rows,profile)
                self.assertEqual(row['candidate_outcome'],candidate)
                if profile=='legal-redress':self.assertNotEqual(row['outcome'],'clean')
    def test_legacy_contradictory_results_rejected(self):
        for update in [dict(verdict=0),dict(verdict=2),dict(return_code=1),dict(return_code=2),
                dict(final_name='Detection'),dict(events=[{'event':'legacy_virus','name':'Detection'}])]:
            with self.subTest(update=update):
                rows=[json.loads(x) for x in self.stdout.splitlines()]
                rows[0]['scan_api']='legacy-1.4';rows[2]['verdict']=None;rows[2].update(update)
                with self.assertRaises(ValueError):self.validate(rows)
    def test_unknown_api_rejected(self):
        rows=[json.loads(x) for x in self.stdout.splitlines()];rows[0]['scan_api']='future-api'
        with self.assertRaisesRegex(ValueError,'unsupported scanner API'):self.validate(rows)
    def test_legal_never_releases(self):
        _,output=test_support.result(self.folder,self.lib,'legal-redress')
        result=self.assess(output,database_profile='legal-redress')
        self.assertEqual(result['outcome'],'held');self.assertFalse(result['release_qualified'])
    def test_stale_database_fails(self):
        (self.gen/'manifest.json').write_text(json.dumps({'signed_databases':[{'name':'daily.cvd','header':'x:1'}]}))
        with patch.object(intake,'run_scanner') as child:
            result=intake.assess(self.folder,self.gen,'/probe',self.lib,'/certs')
        child.assert_not_called();self.assertEqual(result['outcome'],'failed')
        self.assertIn('stale',result['reason'])
    def test_future_database_fails(self):
        (self.gen/'manifest.json').write_text(json.dumps({'signed_databases':[{'name':'daily.cvd','header':'x:'+str(int(time.time()+3600))}]}))
        self.assertIn('future',self.assess()['reason'])
    def test_source_change_fails(self):
        os.chmod(self.folder/'original',0o600);(self.folder/'original').write_bytes(b'tampered');os.chmod(self.folder/'original',0o400)
        self.assertEqual(self.assess()['outcome'],'failed')
    def test_hardlinked_original_fails(self):
        os.link(self.folder/'original',self.root/'link')
        self.assertEqual(self.assess()['outcome'],'failed')
    def test_symlink_original_fails(self):
        (self.folder/'original').unlink();(self.folder/'original').symlink_to(self.source)
        self.assertEqual(self.assess()['outcome'],'failed')
    def test_busy_scanner_holds(self):
        with exclusive_lock(self.folder.parent/'.scanner.lock'):
            result=self.assess()
        self.assertEqual(result['reason'],'scanner-busy-retry');self.assertFalse(result['release_qualified'])
    def test_parallel_same_attachment_cannot_overwrite(self):
        before=(self.folder/'record.json').read_bytes()
        with exclusive_lock(self.folder/'.assessment.lock'):
            with self.assertRaises(BlockingIOError):self.assess()
        self.assertEqual((self.folder/'record.json').read_bytes(),before)
    def test_symlink_lock_rejected(self):
        (self.folder/'.assessment.lock').symlink_to(self.source)
        with self.assertRaises(OSError):self.assess()
        self.assertEqual(self.source.read_bytes(),b'original evidence')
    def test_reassessment_crash_revokes_previous_release(self):
        self.assess()
        with patch.object(intake,'command',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):intake.assess(self.folder,self.gen,'/probe',self.lib,'/certs')
        saved=json.loads((self.folder/'record.json').read_text())
        self.assertFalse(saved['release_qualified']);self.assertEqual(saved['reason'],'scan-in-progress')
    def test_history_preserves_previous_detection(self):
        _,detected=test_support.result(self.folder,self.lib,candidate='detected')
        self.assess(detected);self.assess()
        old=[json.loads(p.read_text()) for p in self.folder.glob('attempt-*-before.json')]
        self.assertTrue(any(x.get('detection_result')=='detected' for x in old))
    def test_fsync_failure_never_reports_success(self):
        with patch('storage.os.fsync',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):write_json(self.folder/'other.json',{'release_qualified':True})
        self.assertFalse((self.folder/'other.json').exists())
    def test_scanner_timeout_preserves_original(self):
        with patch.object(intake,'command',return_value=['probe']),patch.object(intake,'run_scanner',side_effect=TimeoutError('time limit')):
            result=intake.assess(self.folder,self.gen,'/probe',self.lib,'/certs')
        self.assertEqual(result['outcome'],'failed');self.assertFalse(result['release_qualified'])
        self.assertEqual((self.folder/'original').read_bytes(),self.source.read_bytes())
    def test_scanner_crash_preserves_original(self):
        with patch.object(intake,'command',return_value=['probe']),patch.object(intake,'run_scanner',return_value=SimpleNamespace(returncode=-11,stdout='')):
            result=intake.assess(self.folder,self.gen,'/probe',self.lib,'/certs')
        self.assertEqual(result['outcome'],'failed');self.assertFalse(result['release_qualified'])
    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'):
            intake.validate_result('{"kind":"scan","kind":"engine"}',self.source,'x','full',self.lib)
    def test_nonfinite_output_rejected(self):
        with self.assertRaises(ValueError):intake.validate_result('{"kind":"scan","x":NaN}',self.source,'x','full',self.lib)


class RunnerTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def run_code(self,code,**kwargs):
        return runner.run([sys.executable,'-c',code],temp_directory=self.root,**kwargs)
    def test_success_and_exit_status(self):
        result=self.run_code('print("hello");raise SystemExit(7)')
        self.assertEqual(result.returncode,7);self.assertEqual(result.stdout,'hello\n')
    def test_timeout(self):
        start=time.monotonic()
        with self.assertRaises(TimeoutError):self.run_code('import time;time.sleep(10)',timeout=.2)
        self.assertLess(time.monotonic()-start,3)
    def test_output_bound(self):
        with self.assertRaisesRegex(ValueError,'output limit'):self.run_code('print("x"*20000)',output_bytes=1000)
    def test_cpu_bound(self):
        result=self.run_code('while True: pass',cpu_seconds=1,timeout=5)
        self.assertLess(result.returncode,0)
    def test_address_space_bound(self):
        result=self.run_code('x=bytearray(512*1024*1024)',address_space_mib=128)
        self.assertNotEqual(result.returncode,0);self.assertIn('MemoryError',result.stderr)
    def test_environment_and_no_new_privileges(self):
        with patch.dict(os.environ,SUBSET_FRESHCLAM_LIBRARY='/evil',SUBSET_TEST_MAX_FILESIZE='1',LD_PRELOAD='/evil'):
            result=self.run_code('import os;print(os.getenv("SUBSET_TEST_MAX_FILESIZE"),os.getenv("SUBSET_FRESHCLAM_LIBRARY"),os.getenv("LD_PRELOAD"));print(open("/proc/self/status").read())')
        self.assertTrue(result.stdout.startswith('None None None\n'));self.assertIn('NoNewPrivs:\t1',result.stdout)
    def test_descendants_killed(self):
        pidfile=self.root/'pid'
        code='import os,time;pid=os.fork();open('+repr(str(pidfile))+',"w").write(str(pid)) if pid else None;time.sleep(10)'
        with self.assertRaises(TimeoutError):self.run_code(code,timeout=.3)
        pid=int(pidfile.read_text());status=Path('/proc')/str(pid)/'status'
        self.assertTrue(not status.exists() or 'State:\tZ' in status.read_text())
    def test_invalid_limits(self):
        for limits in [dict(timeout=float('nan')),dict(timeout=0),dict(cpu_seconds=0),dict(address_space_mib=0)]:
            with self.assertRaises(ValueError):self.run_code('pass',**limits)

if __name__=='__main__':unittest.main(verbosity=2)
