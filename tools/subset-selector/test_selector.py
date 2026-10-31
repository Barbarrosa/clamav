#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import io,json,os,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import select_db as s
import intake
import generations


def cvd(path, files):
    with path.open('wb') as out:
        out.write(b'ClamAV-VDB:synthetic-test-only'.ljust(512,b' '))
        with tarfile.open(fileobj=out,mode='w:gz') as t:
            for name,data in files.items():
                data=data.encode();info=tarfile.TarInfo(name);info.size=len(data);t.addfile(info,io.BytesIO(data))

class SelectorTests(unittest.TestCase):
    def test_target0(self):self.assertFalse(s.classify('ndb',b'Win.Name:0:*:41424344')[3])
    def test_not_name_inference(self):self.assertTrue(s.classify('ndb',b'Unix.Name:1:*:41424344')[3])
    def test_no_hash_name_inference(self):self.assertFalse(s.classify('hdb',b'123:4:Win.Malware')[3])
    def test_wildcard_target(self):self.assertFalse(s.classify('ndb',b'Foo:*:*:41424344')[3])
    def test_ambiguous_numeric(self):self.assertFalse(s.classify('ndb',b'Foo:01:*:41424344')[3])
    def test_handler_retained(self):self.assertFalse(s.classify('ldb',b'Foo;Target:1,HandlerType:CL_TYPE_PDF;0;41424344')[3])
    def test_unknown_attribute_retained(self):self.assertFalse(s.classify('ldb',b'Foo;Target:1,Future:4;0;41424344')[3])
    def test_macro_retained(self):self.assertFalse(s.classify('ldb',b'Foo;Target:1;0;${1-2}3$')[3])
    def test_duplicate_target_retained(self):self.assertFalse(s.classify('ldb',b'Foo;Target:1,Target:1;0;41424344')[3])
    def test_target7_retained(self):self.assertFalse(s.classify('ldb',b'Win.Loader. Space;Target:7;0;41424344')[3])
    def test_missing_target_retained(self):self.assertFalse(s.classify('ldb',b'Foo;Engine:90-255;0;41424344')[3])
    def test_plain_pe_logical(self):self.assertTrue(s.classify('ldb',b'Foo;Engine:90-255,Target:1,Container:CL_TYPE_PDF;0;41424344')[3])
    def test_sdb_never_skipped(self):self.assertFalse(s.classify('sdb',b'Foo:1:*:41424344')[3])
    def test_cbc_never_skipped(self):self.assertFalse(s.classify('cbc',b'Foo;Target:1;0;41424344')[3])
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.lib=self.root/'lib';self.lib.write_bytes(b'test library');self.full_validation=patch.object(s,'full_load_validate',return_value={'status':'passed','runtime':{'engine_sha256':s.sha(self.lib),'unrar_modules_verified':1}});self.full_validation.start()
    def tearDown(self):self.full_validation.stop();self.tmp.cleanup()
    def plan(self,files):
        src=self.root/'test.cvd';cvd(src,files)
        with patch.object(s,'verify') as verify:
            r=s.make_plan([src],self.root/'generation',self.lib,self.root);self.assertEqual(verify.call_count,1)
        return r,(self.root/'generation'/'skip.tsv').read_text()
    def test_mixed_target_duplicates_retained(self):
        _,text=self.plan({'test.ndb':'Same:1:*:41424344\nSame:0:*:41424344\nOther:1:*:41424344\n'})
        self.assertEqual(text,'ndb\tOther\n')
    def test_ndu_namespace_protects_ndb(self):
        _,text=self.plan({'test.ndb':'Same:1:*:41424344\n','test.ndu':'Same:0:*:41424344\n'});self.assertEqual(text,'')
    def test_cbc_dependency_protection(self):
        _,text=self.plan({'test.ldb':'Same;Target:1;0;41424344\n','test.cbc':'ClamBCsynthetic\nSame;Target:1;0;41424344\n'});self.assertEqual(text,'')
    def test_skip_order_and_hashes(self):
        _,text=self.plan({'a.ndb':'Zed:1:*:41424344\n','a.ldb':'Abc;Target:1;0;41424344\n','a.mdb':'2:abcd:Foo\n','a.hdb':'abcd:2:Win.Foo\n'})
        self.assertEqual(text,'ldb\tAbc\nmdb\t*\nndb\tZed\n');self.assertNotIn('hdb',text)
    def test_unknown_format_blocks_activation(self):
        r,_=self.plan({'a.new':'unknown\n'});self.assertTrue(r['activation_blockers'])
        with self.assertRaisesRegex(ValueError,'unresolved'):s.validate_generation(self.root/'generation',self.lib)
    def test_full_load_failure_no_publication(self):
        src=self.root/'invalid-rule.cvd';cvd(src,{'a.ndb':'X:1:*:NOT_A_VALID_PATTERN\n'})
        with patch.object(s,'verify'),patch.object(s,'full_load_validate',side_effect=ValueError('full load failed')):
            with self.assertRaises(ValueError):s.make_plan([src],self.root/'g',self.lib,self.root)
        self.assertFalse((self.root/'g').exists())
    def test_verify_failure_no_publication(self):
        src=self.root/'bad.cvd';cvd(src,{'a.ndb':'X:1:*:41424344\n'})
        with patch.object(s,'verify',side_effect=ValueError('bad signature')):
            with self.assertRaises(ValueError):s.make_plan([src],self.root/'g',self.lib,self.root)
        self.assertFalse((self.root/'g').exists())
    def test_generation_detects_update(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});g=self.root/'generation';s.validate_generation(g,self.lib)
        p=g/'databases'/'test.cvd';os.chmod(p,0o600);p.write_bytes(b'update')
        with self.assertRaisesRegex(ValueError,'database changed'):s.validate_generation(g,self.lib)
    def test_generation_detects_extra_database(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});g=self.root/'generation';(g/'databases'/'evil.ndb').write_text('bad')
        with self.assertRaisesRegex(ValueError,'unexpected'):s.validate_generation(g,self.lib)
    def test_generation_detects_manifest_change(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});g=self.root/'generation';os.chmod(g/'skip.tsv',0o600);(g/'skip.tsv').write_text('ndb\tY\n')
        with self.assertRaisesRegex(ValueError,'exclusion'):s.validate_generation(g,self.lib)
    def test_generation_detects_decision_audit_change(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});g=self.root/'generation'
        os.chmod(g/'decisions.sqlite',0o600);(g/'decisions.sqlite').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'audit changed'):s.validate_generation(g,self.lib)
    def test_generation_rejects_symlink_manifest(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});g=self.root/'generation'
        (g/'manifest.json').rename(g/'saved.json');(g/'manifest.json').symlink_to(g/'saved.json')
        with self.assertRaisesRegex(ValueError,'symlink'):s.validate_generation(g,self.lib)
    def test_generation_rejects_unverified_runtime(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});g=self.root/'generation'
        p=g/'manifest.json';m=json.loads(p.read_text());m['full_load_validation']['runtime']['unrar_modules_verified']=0
        os.chmod(p,0o600);p.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,'unverified runtime'):s.validate_generation(g,self.lib)
    def test_generation_detects_engine_change(self):
        self.plan({'a.ndb':'X:1:*:41424344\n'});self.lib.write_bytes(b'new version')
        with self.assertRaisesRegex(ValueError,'engine changed'):s.validate_generation(self.root/'generation',self.lib)
    def test_rollback_original_unmodified(self):
        src=self.root/'input.cvd';cvd(src,{'a.ndb':'X:1:*:41424344\n'});before=src.read_bytes()
        with patch.object(s,'verify'):s.make_plan([src],self.root/'g',self.lib,self.root)
        self.assertEqual(src.read_bytes(),before)
    def test_archive_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsafe'):self.plan({'../evil.ndb':'X:1:*:41424344\n'})
    def test_new_database_recomputes_targets_and_rollback(self):
        src=self.root/'test.cvd';cvd(src,{'a.ndb':'Same:1:*:41424344\n'})
        with patch.object(s,'verify'):s.make_plan([src],self.root/'v1',self.lib,self.root)
        generations.switch_shadow(self.root/'state',self.root/'v1',self.lib)
        cvd(src,{'a.ndb':'Same:0:*:41424344\n'})
        with patch.object(s,'verify'):s.make_plan([src],self.root/'v2',self.lib,self.root)
        self.assertEqual((self.root/'v2'/'skip.tsv').read_text(),'')
        generations.switch_shadow(self.root/'state',self.root/'v2',self.lib)
        generations.rollback_shadow(self.root/'state',self.lib)
        self.assertEqual((self.root/'state'/'shadow-current').resolve(),self.root/'v1')
    def test_release_activation_always_blocked(self):
        with self.assertRaisesRegex(ValueError,'release activation disabled'):generations.activate_for_release()
    def test_metadata_and_bytes_preserved(self):
        p=self.root/'file.pdf';p.write_bytes(b'%PDF\x00 original metadata\r\n');before=p.stat();folder,rec=intake.preserve(p,self.root/'q')
        self.assertEqual((folder/'original').read_bytes(),p.read_bytes());self.assertEqual(rec['source_mtime_ns'],before.st_mtime_ns)
        self.assertEqual(rec['outcome'],'held');self.assertEqual(rec['original_filename'],'file.pdf')
    def test_symlink_rejected(self):
        p=self.root/'file';p.write_text('x');link=self.root/'link';link.symlink_to(p)
        with self.assertRaises(OSError):intake.preserve(link,self.root/'q')
    def test_world_readable_quarantine_rejected(self):
        p=self.root/'file';p.write_text('x');q=self.root/'q';q.mkdir(mode=0o755)
        with self.assertRaises(ValueError):intake.preserve(p,q)

if __name__=='__main__':unittest.main(verbosity=2)
