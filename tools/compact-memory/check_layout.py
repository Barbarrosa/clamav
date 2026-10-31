#!/usr/bin/env python3
"""Compare the C/Rust record layouts affected by the compact matcher changes."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--include', type=Path, action='append', default=[])
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    fields = {
        'cli_hash_patt': ['sizehashes', 'compiled', 'buildpool'],
        'cli_hash_compiled': ['directory', 'starts', 'hashes', 'name_offsets', 'names',
                              'buckets', 'items', 'name_bytes', 'name_width'],
        'cli_matcher': ['ac_nodes', 'ac_lsigtable', 'ac_root', 'ac_nodetable',
                        'fuzzy_hashmap', 'ac_nodeidx', 'trans_array', 'ac_lsig_offsets', 'ac_lsig_slots',
                        'ac_flatnodes', 'ac_buildpool'],
        'cli_ac_lsig': ['id', 'bc_idx', 'type', 'flag', 'u', 'virname', 'tdb'],
        'cli_ac_data': ['lsigcnt', 'lsigsuboff_first', 'lsigsuboff_last', 'lsig_row_offsets'],
        'cli_ac_patt': ['pattern', 'ext', 'virname', 'lsigid', 'sigopts'],
        'cli_ac_patt_ext': ['customdata', 'special_table', 'mindist', 'ch'],
        'cli_ac_node': ['list', 'trans', 'fail'],
    }
    c = ['#include <stdio.h>', '#include <stddef.h>', '#include "matcher-ac.h"', 'int main(void) {']
    rust = [f'#[path = "{source / "libclamav_rust/src/sys.rs"}"] mod sys;',
            'fn main() {']
    for struct, members in fields.items():
        c.append(f'printf("{struct}.sizeof=%zu\\n", sizeof(struct {struct}));')
        rust.append(f'println!("{struct}.sizeof={{}}", std::mem::size_of::<sys::{struct}>());')
        for member in members:
            c.append(f'printf("{struct}.{member}=%zu\\n", offsetof(struct {struct}, {member}));')
            rust.append(f'println!("{struct}.{member}={{}}", std::mem::offset_of!(sys::{struct}, {member + '_' if member == 'type' else member}));')
    c.append('return 0; }')
    rust.append('}')
    with tempfile.TemporaryDirectory(prefix='clamav-layout-') as name:
        temp = Path(name)
        (temp / 'layout.c').write_text('\n'.join(c))
        (temp / 'layout.rs').write_text('\n'.join(rust))
        includes = [build, build / 'libclamav', source / 'libclamav',
                    source / 'libclamunrar_iface', source / 'libclammspack', *args.include]
        subprocess.run(['cc', '-DHAVE_CONFIG_H', *['-I' + str(p) for p in includes],
                        str(temp / 'layout.c'), '-o', str(temp / 'c')], check=True)
        subprocess.run(['rustc', '-A', 'warnings', str(temp / 'layout.rs'),
                        '-o', str(temp / 'rust')], check=True)
        expected = subprocess.check_output([str(temp / 'c')], text=True)
        actual = subprocess.check_output([str(temp / 'rust')], text=True)
        if actual != expected:
            raise SystemExit('C/Rust ABI mismatch\nC:\n' + expected + '\nRust:\n' + actual)
        print(expected, end='')
        print('All affected record sizes and field offsets agree.')


if __name__ == '__main__':
    main()
