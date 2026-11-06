"""Protocol-only synthetic stubs; no linked counting method is executed.
SPDX-License-Identifier: GPL-2.0-only
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from run_counter import dimacs_info, run_counter


class CounterProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cnf = self.root / 'tiny.cnf'
        # x1 is true, x2 is unused: exactly two assignments, not one.
        self.cnf.write_text('p cnf 2 1\n1 0\n')
        self.stub = self.root / 'synthetic_protocol_stub.py'

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, body):
        self.stub.write_text('import hashlib,json,sys,time\nfrom pathlib import Path\n'
            'input_sha=hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()\n' + body + '\n')
        return {'argv': [sys.executable, str(self.stub), '{input}'],
                'label': 'synthetic protocol stub; not a counting algorithm',
                'identity_files': [str(self.stub)]}

    def response(self, count='2', status='exact', digest='input_sha'):
        value = 'json.loads(' + repr(json.dumps(count)) + ')'
        return self.command(f'print(json.dumps({{"status":{status!r},"count":{value},"input_sha256":{digest}}}))')

    def test_valid_fixture_protocol_keeps_unused_variables_and_does_not_claim_method_identity(self):
        result = run_counter(self.cnf, self.response(), expected_count=2)
        self.assertEqual(result['status'], 'fixture_count_matched')
        self.assertEqual(result['count'], '2')
        self.assertEqual(result['input']['declared_variables'], 2)
        self.assertTrue(result['verified_against_supplied_expected_count'])
        self.assertFalse(result['independent_proof_certificate_verified'])
        self.assertFalse(result['linked_counting_construction_execution_established'])
        self.assertNotIn('stdout', result)
        self.assertNotIn('stderr', result)
        self.assertEqual(result['input_sha256'], hashlib.sha256(self.cnf.read_bytes()).hexdigest())

    def test_no_expected_answer_is_reported_not_certified(self):
        result = run_counter(self.cnf, self.response())
        self.assertEqual(result['status'], 'reported_exact')
        self.assertFalse(result['verified_against_supplied_expected_count'])

    def test_wrong_hash_and_missing_hash_rejected(self):
        result = run_counter(self.cnf, self.response(digest="'wrong'"))
        self.assertEqual(result['status'], 'protocol_error')
        result = run_counter(self.cnf, self.command('print(json.dumps({"status":"exact","count":"2"}))'))
        self.assertEqual(result['status'], 'protocol_error')

    def test_count_mismatch_is_not_exact_success(self):
        result = run_counter(self.cnf, self.response(), expected_count='1')
        self.assertEqual(result['status'], 'count_mismatch')
        self.assertFalse(result['verified_against_supplied_expected_count'])

    def test_invalid_count_types_and_assignment_bound(self):
        for value in (True, 2, -1, float('nan'), float('inf'), '-1', '02', '5', '1.5', 'NaN'):
            with self.subTest(value=value):
                result = run_counter(self.cnf, self.response(count=value))
                self.assertEqual(result['status'], 'protocol_error')
        self.assertEqual(run_counter(self.cnf, self.response('4'))['status'], 'reported_exact')

    def test_zero_variables_allow_only_zero_or_one_assignment(self):
        self.cnf.write_text('p cnf 0 0\n')
        self.assertEqual(run_counter(self.cnf, self.response('1'))['status'], 'reported_exact')
        self.assertEqual(run_counter(self.cnf, self.response('0'))['status'], 'reported_exact')
        self.assertEqual(run_counter(self.cnf, self.response('2'))['status'], 'protocol_error')

    def test_unknown_is_not_an_exact_count(self):
        cmd = self.command('print(json.dumps({"status":"unknown","input_sha256":input_sha}))')
        result = run_counter(self.cnf, cmd)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['count'])

    def test_nonzero_exit_and_extra_output_cannot_qualify(self):
        command = self.response(); self.stub.write_text(self.stub.read_text() + '\nsys.exit(7)\n')
        self.assertEqual(run_counter(self.cnf, command)['status'], 'execution_error')
        command = self.response(); self.stub.write_text(self.stub.read_text() + '\nprint("extra")\n')
        self.assertEqual(run_counter(self.cnf, command)['status'], 'protocol_error')

    def test_timeout_and_output_bounds(self):
        result = run_counter(self.cnf, self.command('time.sleep(5)'), timeout=0.05)
        self.assertEqual(result['status'], 'timeout')
        self.assertIsNone(result['count'])
        result = run_counter(self.cnf, self.command('print("x"*8192)'), output_limit_bytes=256)
        self.assertEqual(result['status'], 'output_limit')
        self.assertNotIn('x' * 10, json.dumps(result))
        command = self.response(); self.stub.write_text(self.stub.read_text() + '\nsys.stderr.write("x"*8192)\n')
        self.assertEqual(run_counter(self.cnf, command, output_limit_bytes=256)['status'], 'output_limit')

    def test_timeout_kills_descendants_before_they_can_write(self):
        ready, marker = self.root / 'ready', self.root / 'late-marker'
        child = ('from pathlib import Path; import time; '
                 f'Path({str(ready)!r}).write_text("ready"); time.sleep(0.7); '
                 f'Path({str(marker)!r}).write_text("survived")')
        command = self.command('import subprocess\n'
            f'subprocess.Popen([sys.executable,"-c",{child!r}])\ntime.sleep(5)')
        result = run_counter(self.cnf, command, timeout=0.3)
        self.assertEqual(result['status'], 'timeout')
        self.assertTrue(ready.exists(), 'descendant must actually start for this control')
        time.sleep(0.6)
        self.assertFalse(marker.exists())

    def test_input_mutation_breaks_binding(self):
        result = run_counter(self.cnf, self.command('Path(sys.argv[1]).write_text("p cnf 1 0\\n")\n'
            'print(json.dumps({"status":"exact","count":"2","input_sha256":input_sha}))'))
        self.assertEqual(result['status'], 'protocol_error')
        self.assertFalse(result['input_and_declared_identities_unchanged'])

    def test_shell_text_and_undeclared_identity_are_not_substituted(self):
        command = self.response()
        command['argv'][-1] = '--file={input}'
        with self.assertRaises(ValueError):
            run_counter(self.cnf, command)
        command = self.response(); command['identity_files'] = []
        with self.assertRaises(ValueError):
            run_counter(self.cnf, command)

    def test_dimacs_validates_complete_body_and_preserves_empty_clauses(self):
        self.cnf.write_text('c comment\np cnf 4 2\n1\n-2 0 0\n')
        self.assertEqual(dimacs_info(self.cnf), {'declared_variables': 4, 'clauses': 2,
                                               'literal_occurrences': 2, 'maximum_clause_width': 2})
        for text in ('p cnf 2 1\n1\n', 'p cnf 1 1\n2 0\n', 'p cnf 1 2\n1 0\n'):
            self.cnf.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                dimacs_info(self.cnf)

    def test_cli_uses_relative_identity_paths_and_never_emits_raw_output(self):
        command = self.response(); command['identity_files'] = [self.stub.name]
        config = self.root / 'command.json'; config.write_text(json.dumps(command))
        report = self.root / 'report.json'
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('run_counter.py')),
            '--cnf', str(self.cnf), '--command-file', str(config), '--report', str(report),
            '--expected-count', '2'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(report.read_text())['status'], 'fixture_count_matched')
        self.assertNotIn('input_sha256', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
