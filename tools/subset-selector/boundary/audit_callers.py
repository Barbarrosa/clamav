#!/usr/bin/env python3
"""Record the exact source reviewed for the PE exclusion boundary.

This is a review inventory, not a proof of parser completeness. GPL-2.0-only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

NAMES = ('cli_scan_buff', 'cli_scan_fmap', 'cli_scan_desc', 'cli_scanpe',
         'scan_pe_mdb', 'scan_pe_imp', 'cli_magic_scan',
         'dispatch_file_inspection_callback', 'dispatch_filetype_callback')

def inventory(source):
    pattern = re.compile(r'\b(' + '|'.join(NAMES) + r')\s*\(')
    files = {}
    for path in sorted((source / 'libclamav').rglob('*')):
        if path.suffix not in ('.c', '.h'):
            continue
        raw = path.read_bytes()
        matches = []
        for lineno, line in enumerate(raw.decode(errors='replace').splitlines(), 1):
            if pattern.search(line) or 'maxembeddedpe' in line.lower():
                matches.append({'line': lineno, 'text': line.strip()})
        if matches:
            files[str(path.relative_to(source))] = {
                'sha256': hashlib.sha256(raw).hexdigest(), 'matches': matches}
    return {'scope': 'source call-site inventory; includes declarations, comments and inactive branches',
            'automatic_proof': False, 'files': files}

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.write_text(json.dumps(inventory(args.source), indent=2) + '\n')
