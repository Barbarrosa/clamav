#!/usr/bin/env python3
"""Run one isolated native probe, recording process resource use and exit status."""
import argparse,json,os,resource,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--cpu',type=int);p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
if a.cpu is not None:os.sched_setaffinity(0,{a.cpu})
t=time.monotonic();r=subprocess.run(a.command);u=resource.getrusage(resource.RUSAGE_CHILDREN)
a.output.write_text(json.dumps({'command':a.command,'cpu':a.cpu,'exit':r.returncode,'wall_seconds':time.monotonic()-t,'user_seconds':u.ru_utime,'system_seconds':u.ru_stime,'peak_rss_kib':u.ru_maxrss},indent=2)+'\n')
raise SystemExit(r.returncode)
