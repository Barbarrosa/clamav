#!/usr/bin/env python3
"""Configuration and detection-contract rejection tests. GPL-2.0-only."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import equivalence
import intake
import scan
import test_support


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.kw=dict(probe=Path('/probe'),lib=Path('/lib'),certs=Path('/certs'),files=Path('/files'))
    def test_full_default_no_skips(self):
        cmd=scan.command(**self.kw,database=Path('/db'))
        self.assertEqual(cmd[3],'-');self.assertEqual(cmd[-1],'first')
    def test_explicit_full_identical(self):
        self.assertEqual(scan.command(**self.kw,database=Path('/db')),
                         scan.command(**self.kw,database=Path('/db'),database_profile='full'))
    def test_restricted_requires_generation(self):
        with self.assertRaisesRegex(ValueError,'verified'):scan.command(**self.kw,database='/db',database_profile='legal-redress')
    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):scan.command(**self.kw,database='/db',database_profile='legal-redres')
    def test_no_ambiguous_database_sources(self):
        with self.assertRaises(ValueError):scan.command(**self.kw,database='/db',generation='/gen')
    def test_restricted_rejects_broad_profile(self):
        with self.assertRaisesRegex(ValueError,'PDF/JPEG/PNG'):scan.command(**self.kw,generation='/gen',database_profile='legal-redress',broad=True)
    def test_restricted_forces_allmatch_and_accept_callbacks(self):
        with patch.object(scan,'validate_generation',return_value={'full_load_validation':{'probe_sha256':'ok'}}),patch.object(scan,'sha',return_value='ok'):
            cmd=scan.command(**self.kw,generation='/gen',database_profile='legal-redress')
        self.assertEqual(cmd[3],'/gen/skip.tsv');self.assertEqual(cmd[-1],'all');self.assertEqual(cmd[7],'0')
    def test_probe_change_rejected(self):
        with patch.object(scan,'validate_generation',return_value={'full_load_validation':{'probe_sha256':'old'}}),patch.object(scan,'sha',return_value='new'):
            with self.assertRaisesRegex(ValueError,'probe changed'):scan.command(**self.kw,generation='/gen',database_profile='legal-redress')
    def test_generation_failure_is_not_fallback_to_full(self):
        with patch.object(scan,'validate_generation',side_effect=ValueError('changed input')):
            with self.assertRaisesRegex(ValueError,'changed input'):scan.command(**self.kw,generation='/gen',database_profile='legal-redress')
    def test_intake_unknown_profile_fails_and_keeps_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'evidence.pdf';p.write_bytes(b'original evidence')
            folder,_=intake.preserve(p,Path(tmp)/'quarantine')
            r=intake.assess(folder,'/gen','/probe','/lib','/certs',database_profile='typo')
            self.assertEqual(r['outcome'],'failed');self.assertEqual((folder/'original').read_bytes(),p.read_bytes())
    def test_intake_outcomes_and_retained_evidence(self):
        for profile, candidate, holds, expected in [
            ('full','clean',0,'clean'), ('legal-redress','clean',0,'held'),
            ('legal-redress','detected',0,'detected'), ('legal-redress','held',1,'held'),
            ('legal-redress','failed',0,'failed')]:
            with self.subTest(profile=profile,candidate=candidate), tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'evidence.pdf';p.write_bytes(b'original evidence')
                folder,_=intake.preserve(p,Path(tmp)/'quarantine')
                gen=test_support.generation(Path(tmp)/'generation')
                lib=Path(tmp)/'lib';lib.write_bytes(b'library')
                row,stdout=test_support.result(folder,lib,profile,candidate,holds)
                with patch.object(intake,'command',return_value=['probe']),patch.object(intake,'run_scanner',return_value=SimpleNamespace(returncode=0,stdout=stdout)):
                    r=intake.assess(folder,gen,'/probe',lib,'/certs',database_profile=profile)
                self.assertEqual(r['outcome'],expected);self.assertEqual(r['scan_evidence'],[row])
                self.assertEqual(r['release_qualified'],expected=='clean')
                self.assertEqual((folder/'original').read_bytes(),p.read_bytes())
    def test_intake_rejects_wrong_mode_and_missing_scan(self):
        for rows in [[],[dict(kind='scan',allmatch=0,candidate_outcome='clean',hold_bits=0)]]:
            with self.subTest(rows=rows), tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'evidence.pdf';p.write_bytes(b'original')
                folder,_=intake.preserve(p,Path(tmp)/'quarantine')
                with patch.object(intake,'command',return_value=['probe']),patch.object(intake,'run_scanner',return_value=SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,rows)))):
                    r=intake.assess(folder,'/gen','/probe','/lib','/certs',database_profile='legal-redress')
                self.assertEqual(r['outcome'],'failed');self.assertFalse(r['release_qualified'])


class EquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.row=dict(allmatch=1,return_code=1,verdict=2,root_type='CL_TYPE_PDF',scanned_bytes=100,hold_bits=0,
                      sha256='abc',after_sha256='abc',candidate_outcome='detected',final_name='B',events=[
            dict(event='file_type',type='CL_TYPE_PDF',depth=0,object_id=0,attributes=0,name=None),
            dict(event='legacy_virus',name='A'),dict(event='legacy_virus',name='A'),dict(event='legacy_virus',name='B'),
            dict(event='alert',type='CL_TYPE_PDF',depth=0,object_id=0,attributes=0,name='B'),
            dict(event='post_scan',type='CL_TYPE_PDF',depth=0,object_id=0,attributes=0,name='B')])
        self.other=copy.deepcopy(self.row)
    def test_order_and_last_name_are_accepted(self):
        self.other['events'][1:4]=reversed(self.other['events'][1:4]);self.other['final_name']='A'
        self.other['events'][-1]['name']='A'
        self.assertTrue(equivalence.detection_equivalent(self.row,self.other))
    def test_removed_duplicate_rejected(self):
        del self.other['events'][1]
        self.assertFalse(equivalence.detection_equivalent(self.row,self.other))
    def test_changed_name_rejected(self):
        self.other['events'][1]['name']='Renamed'
        self.assertFalse(equivalence.detection_equivalent(self.row,self.other))
    def test_unrelated_final_name_rejected(self):
        self.other['final_name']='not-in-detection-evidence'
        self.assertFalse(equivalence.detection_equivalent(self.row,self.other))
    def test_layer_and_severity_changes_rejected(self):
        for key,value in [('hold_bits',1),('verdict',3),('scanned_bytes',99),('allmatch',0),('after_sha256','changed'),('return_code',0)]:
            with self.subTest(key=key):
                other=copy.deepcopy(self.row);other[key]=value
                self.assertFalse(equivalence.detection_equivalent(self.row,other))
        self.other['events'][0]['type']='CL_TYPE_MSEXE'
        self.assertFalse(equivalence.detection_equivalent(self.row,self.other))
    def test_alert_layer_change_rejected(self):
        self.other['events'][4]['depth']=1
        self.assertFalse(equivalence.detection_equivalent(self.row,self.other))


if __name__=='__main__':unittest.main(verbosity=2)
