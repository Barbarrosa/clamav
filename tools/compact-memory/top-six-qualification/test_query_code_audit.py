"""Adversarial checks of the machine-code comparison, not scanner tests.
SPDX-License-Identifier: GPL-2.0-only
"""
import unittest

from query_code_audit import function_body, parse_disassembly


def disassembly(entry, rows):
    return '\n'.join([f'{entry:x} <probe>:'] +
                     [f' {entry + offset:x}:\t{instruction}' for offset, instruction in rows])


class QueryCodeAuditTests(unittest.TestCase):
    def test_link_shifts_do_not_hide_literals_or_register_changes(self):
        a = parse_disassembly(disassembly(0x1000, [(0, 'mov $0x1234,%eax'), (5, 'call 3000 <other>'), (10, 'ret')]))
        b = parse_disassembly(disassembly(0x2000, [(0, 'mov $0x1234,%eax'), (5, 'call 4000 <other>'), (10, 'ret')]))
        self.assertEqual(a['strict'], b['strict'])
        changed = parse_disassembly(disassembly(0x2000, [(0, 'mov $0x1235,%eax'), (5, 'call 4000 <other>'), (10, 'ret')]))
        self.assertNotEqual(a['strict'], changed['strict'])
        self.assertNotEqual(a['nonpadding_cfg'], changed['nonpadding_cfg'])
        changed_register = parse_disassembly(disassembly(0x2000, [(0, 'mov $0x1234,%edx'), (5, 'call 4000 <other>'), (10, 'ret')]))
        self.assertNotEqual(a['nonpadding_cfg'], changed_register['nonpadding_cfg'])

    def test_rip_displacements_are_removed_but_symbol_offsets_are_retained(self):
        a = parse_disassembly(disassembly(0x1000, [(0, 'mov 0x20(%rip),%rax # 1027 <object+0x8>'), (7, 'ret')]))
        b = parse_disassembly(disassembly(0x2000, [(0, 'mov 0x30(%rip),%rax # 2037 <object+0x8>'), (7, 'ret')]))
        self.assertEqual(a['strict'], b['strict'])
        changed_target = parse_disassembly(disassembly(0x2000, [(0, 'mov 0x30(%rip),%rax # 2037 <object+0x9>'), (7, 'ret')]))
        self.assertNotEqual(a['strict'], changed_target['strict'])
        self.assertNotEqual(a['nonpadding_cfg'], changed_target['nonpadding_cfg'])

    def test_padding_changes_require_the_same_direct_branch_destination(self):
        a = parse_disassembly(disassembly(0x1000, [
            (0, 'mov $0x1,%eax'), (5, 'jne 1010 <probe+0x10>'),
            (7, 'nop'), (0x10, 'add $0x2,%eax'), (0x13, 'ret')]))
        b = parse_disassembly(disassembly(0x2000, [
            (0, 'mov $0x1,%eax'), (5, 'jne 2015 <probe+0x15>'),
            (7, 'data16 cs nopw 0x0(%rax,%rax,1)'), (0x10, 'nopl (%rax)'),
            (0x15, 'add $0x2,%eax'), (0x18, 'ret')]))
        self.assertNotEqual(a['strict'], b['strict'])
        self.assertEqual(a['nonpadding_cfg'], b['nonpadding_cfg'])
        wrong = parse_disassembly(disassembly(0x2000, [
            (0, 'mov $0x1,%eax'), (5, 'jne 2018 <probe+0x18>'),
            (7, 'data16 cs nopw 0x0(%rax,%rax,1)'), (0x10, 'nopl (%rax)'),
            (0x15, 'add $0x2,%eax'), (0x18, 'ret')]))
        self.assertNotEqual(a['nonpadding_cfg'], wrong['nonpadding_cfg'])

    def test_branch_into_padding_keeps_its_effective_destination(self):
        a = parse_disassembly(disassembly(0x1000, [
            (0, 'jmp 1007 <probe+0x7>'), (7, 'nop'), (8, 'ret')]))
        b = parse_disassembly(disassembly(0x2000, [
            (0, 'jmp 2010 <probe+0x10>'), (7, 'nop'), (0x10, 'xchg %ax,%ax'), (0x12, 'ret')]))
        self.assertEqual(a['nonpadding_cfg'], b['nonpadding_cfg'])

    def test_ambiguous_relocations_and_non_instruction_targets_are_unknown(self):
        ambiguous = parse_disassembly(disassembly(0x1000, [(0, 'mov 0x20(%rip),%rax # 1027'), (7, 'ret')]))
        self.assertTrue(ambiguous['normalization_unknowns'])
        malformed_target = parse_disassembly(disassembly(0x1000, [
            (0, 'jne 1001 <probe+0x1>'), (6, 'ret')]))
        self.assertTrue(malformed_target['normalization_unknowns'])

    def test_missing_or_empty_functions_are_not_equal_successes(self):
        for text in ('', 'Disassembly of section .text:', '1000 <probe>:', '1000 <probe>:\n1000: nop'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_disassembly(text)

    def test_source_body_parser_ignores_prototypes_comments_and_literal_braces(self):
        source = r'''int probe(int n);
/* probe(n) { wrong } */
int probe(int n) {
    const char *s = "}";
    if (n) { return n + 1; }
    return 0;
}
'''
        body = function_body(source, 'probe')
        self.assertIn('return n + 1;', body)
        self.assertTrue(body.endswith('}'))
        self.assertNotEqual(body, function_body(source.replace('n + 1', 'n + 2'), 'probe'))
        with self.assertRaises(ValueError):
            function_body('int probe(int n);', 'probe')


if __name__ == '__main__':
    unittest.main()
