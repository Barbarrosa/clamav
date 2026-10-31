#!/usr/bin/env python3
"""Build public-API probe against an already built retained engine. GPL-2.0-only."""
import argparse,os,shlex,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--build',type=Path,required=True);p.add_argument('--libdir',type=Path)
p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default=os.environ.get('CC','cc'))
p.add_argument('--include',action='append',type=Path,default=[]);p.add_argument('--library-path',action='append',type=Path,default=[])
p.add_argument('--boundary-test',action='store_true',help='test-only boundary witness and negative-control hooks')
a=p.parse_args();source=Path(__file__).resolve().parents[2];lib=(a.libdir or a.build/'libclamav').resolve()
probe_source=Path(__file__).parent/('scan_probe.c' if 'cl_scandesc_ex(' in (source/'libclamav/clamav.h').read_text() else 'scan_probe_legacy.c')
flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','json-c','openssl'],text=True))
a.output.parent.mkdir(parents=True,exist_ok=True)
cmd=[a.cc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(source/'libclamav'),'-I'+str(a.build.resolve())]
cmd+=['-I'+str(p.resolve()) for p in a.include]+[str(probe_source),'-L'+str(lib),'-Wl,--disable-new-dtags','-Wl,-rpath,'+':'.join(str(x.resolve()) for x in (lib, a.build/'libclamunrar_iface', a.build/'libclamunrar'))]
cmd+=['-L'+str(p.resolve()) for p in a.library_path]+['-lclamav','-ldl']+flags+['-o',str(a.output)]
if a.boundary_test:cmd+=['-DSUBSET_BOUNDARY_TEST','-Wl,--export-dynamic']
subprocess.run(cmd,check=True)
