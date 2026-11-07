#!/usr/bin/env python3
"""Compare selected query-source bodies and x86-64 GNU objdump instructions.

Strict comparison removes only link addresses and annotated RIP displacements;
it retains literal immediates, registers, memory operands, local instruction
offsets and symbol-relative target offsets. A second, explicitly weaker check
removes architectural NOPs and maps direct local branches to non-padding
instruction indexes. That check preserves branch destinations, not just their
mnemonics. Neither comparison proves hardware timing or dynamic step counts.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
from bisect import bisect_left
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


FUNCTIONS = {
    'libclamav/matcher-ac.c': (
        'cli_ac_scanbuff', 'ac_forward_match_branch', 'ac_backward_match_branch',
        'cli_ac_caloff', 'lsig_sub_matched', 'lsig_increment_subsig_match',
        'cli_ac_chkmacro', 'cli_ac_chklsig', 'cli_ac_initdata',
        'cli_ac_initdata_for_matcher', 'cli_ac_freedata'),
    'libclamav/matcher-bm.c': ('cli_bm_scanbuff',),
    'libclamav/matcher-hash.c': ('cli_hm_scan', 'cli_hm_scan_wild'),
    'libclamav/cache.c': ('clean_cache_check', 'clean_cache_add'),
}
HEADER_STRUCTS = {
    'libclamav/matcher-ac.h': ('cli_ac_patt', 'cli_ac_patt_ext', 'cli_ac_list', 'cli_ac_node', 'cli_ac_data'),
    'libclamav/matcher.h': ('cli_matcher', 'cli_ac_lsig', 'cli_lsig_tdb'),
}
HEADER_INLINE = ('cli_ac_lsig_row', 'cli_ac_lsig_counts', 'cli_ac_lsig_first', 'cli_ac_lsig_last')
LABEL = re.compile(r'^([0-9a-fA-F]+) <([^>]+)>:$')
INSTRUCTION = re.compile(r'^\s*([0-9a-fA-F]+):\s+(.+?)\s*$')
ANNOTATED_ADDRESS = re.compile(r'(?<![$\w])(?:0x)?[0-9a-fA-F]+\s+<([^>]+)>')
RIP_DISPLACEMENT = re.compile(r'(?<![\w$])[-+]?0x[0-9a-fA-F]+\(%rip\)')
DIRECT_BRANCH = re.compile(r'^(?:j[a-z]+|callq?|loop[a-z]*)\s+((?:0x)?[0-9a-fA-F]+)\s+<[^>]+>')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def text_digest(rows):
    return digest(('\n'.join(rows) + '\n').encode())


def is_padding(instruction):
    words = instruction.split()
    while words and words[0] in ('data16', 'cs'):
        words.pop(0)
    return bool(words and (words[0] in ('nop', 'nopl', 'nopw') or
                           ' '.join(words) == 'xchg %ax,%ax'))


def normalize_operands(instruction):
    """Retain unannotated addresses: guessing what they reference is unsafe."""
    unknown = []
    if '%rip' in instruction:
        if re.search(r'#\s+(?:0x)?[0-9a-fA-F]+\s+<[^>]+>', instruction):
            instruction = RIP_DISPLACEMENT.sub('<rip-displacement>(%rip)', instruction)
        else:
            unknown.append('RIP-relative operand without symbolic target annotation')
    instruction = ANNOTATED_ADDRESS.sub(lambda m: '<' + m.group(1) + '>', instruction)
    return re.sub(r'\s+', ' ', instruction).strip(), unknown


def parse_disassembly(text):
    labels, rows = [], []
    for line in text.splitlines():
        if match := LABEL.match(line):
            labels.append((int(match.group(1), 16), match.group(2)))
        elif match := INSTRUCTION.match(line):
            rows.append((int(match.group(1), 16), match.group(2)))
    if len(labels) != 1 or not rows:
        raise ValueError('expected one nonempty disassembled function')
    entry, label = labels[0]
    if any(address < entry for address, _ in rows):
        raise ValueError('instruction precedes selected function')
    addresses = [address for address, _ in rows]
    if addresses != sorted(set(addresses)):
        raise ValueError('instruction addresses must increase uniquely')
    live = [address for address, instruction in rows if not is_padding(instruction)]
    if not live:
        raise ValueError('function contains no non-padding instruction')
    strict, cfg, unknown = [], [], []
    address_set = set(addresses)
    direct_local = 0
    for address, instruction in rows:
        normalized, notes = normalize_operands(instruction)
        unknown.extend(notes)
        strict.append(f'{address - entry:x}: {normalized}')
        if is_padding(instruction):
            continue
        if match := DIRECT_BRANCH.match(instruction):
            target = int(match.group(1), 16)
            if entry <= target <= addresses[-1]:
                if target not in address_set:
                    unknown.append('local direct branch does not target a decoded instruction boundary')
                else:
                    index = bisect_left(live, target)
                    if index == len(live):
                        unknown.append('local direct branch targets trailing padding')
                    else:
                        # Match/rewrite the direct destination only. Immediates
                        # and unrelated symbolic/data operands remain intact.
                        normalized = re.sub(r'^(\S+\s+)<[^>]+>',
                                            lambda m: m.group(1) + f'<local-instruction:{index}>',
                                            normalized, count=1)
                        direct_local += 1
        cfg.append(normalized)
    return {'label': label, 'symbol_address': entry, 'instruction_count': len(rows),
            'padding_instructions': len(rows) - len(live),
            'nonpadding_instructions': len(live), 'local_direct_branches': direct_local,
            'strict': strict, 'nonpadding_cfg': cfg,
            'strict_sha256': text_digest(strict), 'nonpadding_cfg_sha256': text_digest(cfg),
            'normalization_unknowns': sorted(set(unknown)),
            'disassembled_instruction_sha256': text_digest([f'{a:x}: {i}' for a, i in rows])}


def mask_c(text):
    expression = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(expression, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), text)


def braced_body(text, masked, start):
    depth, cursor = 1, start + 1
    while depth and cursor < len(masked):
        depth += (masked[cursor] == '{') - (masked[cursor] == '}')
        cursor += 1
    if depth:
        raise ValueError('unbalanced C body')
    return text[start:cursor]


def function_body(text, name):
    masked = mask_c(text)
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', masked):
        cursor, depth = masked.find('(', match.start()) + 1, 1
        while depth and cursor < len(masked):
            depth += (masked[cursor] == '(') - (masked[cursor] == ')')
            cursor += 1
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        if cursor < len(masked) and masked[cursor] == '{':
            return braced_body(text, masked, cursor)
    raise ValueError('function definition not found: ' + name)


def struct_body(text, name):
    masked = mask_c(text)
    match = re.search(r'\bstruct\s+' + re.escape(name) + r'\s*\{', masked)
    if not match:
        raise ValueError('struct definition not found: ' + name)
    return braced_body(text, masked, masked.find('{', match.start()))


def run(command):
    return subprocess.check_output(command, text=True)


def source_audit(repo, baseline_ref, candidate_ref):
    refs = {name: run(['git', '-C', str(repo), 'rev-parse', ref]).strip()
            for name, ref in (('baseline', baseline_ref), ('candidate', candidate_ref))}
    rows, files = [], {}
    for path in sorted(set(FUNCTIONS) | set(HEADER_STRUCTS)):
        versions = {name: run(['git', '-C', str(repo), 'show', ref + ':' + path])
                    for name, ref in refs.items()}
        files[path] = {name: digest(text.encode()) for name, text in versions.items()}
        selections = [(name, function_body, 'query_function') for name in FUNCTIONS.get(path, ())]
        selections += [(name, struct_body, 'struct') for name in HEADER_STRUCTS.get(path, ())]
        if path == 'libclamav/matcher-ac.h':
            selections += [(name, function_body, 'inline_accessor') for name in HEADER_INLINE]
        for name, extractor, kind in selections:
            hashes = {key: digest(extractor(text, name).encode()) for key, text in versions.items()}
            rows.append({'path': path, 'name': name, 'kind': kind,
                         'body_sha256': hashes, 'body_bytes_unchanged': len(set(hashes.values())) == 1})
    return {'git_refs': refs, 'source_files': files, 'bodies': rows,
            'all_selected_bodies_unchanged': all(row['body_bytes_unchanged'] for row in rows),
            'scope': 'Exact source-body text and selected private structs/accessors; not binary build attestation or a whole-engine proof.'}


def audit(baseline, candidate, repo, baseline_ref, candidate_ref):
    inputs = {name: path.read_bytes() for name, path in (('baseline', baseline), ('candidate', candidate))}
    report = {'schema_version': 1, 'implementation_sha256': digest(Path(__file__).read_bytes()),
              'objdump_version': run(['objdump', '--version']).splitlines()[0],
              'binaries': {name: {'sha256': digest(raw), 'bytes': len(raw)} for name, raw in inputs.items()},
              'source': source_audit(repo, baseline_ref, candidate_ref), 'functions': []}
    # Snapshot complete input bytes so another build cannot replace the shared
    # library between identity recording and disassembly.
    with tempfile.TemporaryDirectory() as directory:
        snapshots = {}
        for name, raw in inputs.items():
            path = Path(directory) / (name + '.so')
            path.write_bytes(raw)
            if 'architecture: i386:x86-64' not in run(['objdump', '-f', str(path)]):
                raise ValueError('this normalizer is qualified only for GNU x86-64 disassembly')
            snapshots[name] = path
        for names in FUNCTIONS.values():
            for name in names:
                decoded = {key: parse_disassembly(run(['objdump', '-d', '--no-show-raw-insn',
                                                      '--disassemble=' + name, str(path)]))
                           for key, path in snapshots.items()}
                strict_equal = decoded['baseline']['strict'] == decoded['candidate']['strict']
                cfg_equal = decoded['baseline']['nonpadding_cfg'] == decoded['candidate']['nonpadding_cfg']
                unknown = any(value['normalization_unknowns'] for value in decoded.values())
                differences = list(difflib.unified_diff(decoded['baseline']['strict'],
                                                       decoded['candidate']['strict'], n=1))[:20]
                report['functions'].append({
                    'name': name, 'strict_normalized_equal': strict_equal,
                    'nonpadding_instruction_and_direct_target_equal': cfg_equal,
                    'normalization_complete_for_selected_operands': not unknown,
                    'versions': {key: {k: v for k, v in value.items() if k not in ('strict', 'nonpadding_cfg')}
                                 for key, value in decoded.items()},
                    'first_strict_differences': differences})
    report['summary'] = {
        'functions_checked': len(report['functions']),
        'strict_normalized_matches': sum(row['strict_normalized_equal'] for row in report['functions']),
        'nonpadding_instruction_and_direct_target_matches': sum(row['nonpadding_instruction_and_direct_target_equal']
                                                               for row in report['functions']),
        'all_selected_source_bodies_unchanged': report['source']['all_selected_bodies_unchanged'],
        'all_operand_normalizations_complete': all(row['normalization_complete_for_selected_operands'] for row in report['functions'])}
    report['limitations'] = [
        'Strict normalization retains immediate values, register choices, memory operands and symbol-relative offsets.',
        'The secondary equality check deliberately excludes architectural NOPs and encoding offsets; it is not machine-step equality.',
        'Local direct destinations are checked by decoded non-padding instruction index, preserving control-flow distinctions.',
        'Indirect branch data, all callees, Rust, parsers and unselected scanner functions are not independently audited.',
        'Identical code does not imply identical hardware time, instruction-cache alignment, page faults, residency or allocator/cache state.',
        'Provided Git source identities are compared separately; this tool does not attest that a binary was built from those identities.',
        'This does not replace paired performance, cold/warm, concurrency, update/reload or memory measurements.']
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--baseline-ref', required=True)
    parser.add_argument('--candidate-ref', default='HEAD')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.baseline, args.candidate, args.repo, args.baseline_ref, args.candidate_ref)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report['summary']))


if __name__ == '__main__':
    main()
