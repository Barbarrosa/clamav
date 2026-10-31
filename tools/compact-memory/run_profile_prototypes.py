#!/usr/bin/env python3
"""Run the exact-layout prototype matrix sequentially on one selected CPU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--scalar', type=Path, required=True)
    p.add_argument('--blocks', type=Path, required=True)
    p.add_argument('--cpu', type=int, default=2)
    a = p.parse_args(); a.output.mkdir(parents=True,exist_ok=True)
    prefix = ['taskset','-c',str(a.cpu)]; completed=[]
    def run(name, command):
        with (a.output/(name+'.jsonl')).open('w') as out, (a.output/(name+'.stderr')).open('w') as err:
            subprocess.run(prefix+command,stdout=out,stderr=err,check=True)
        completed.append(name); print(name,flush=True)
    for kind, filename in [('patterns','patterns-interned.bin'),('links','links.bin'),('nodes','nodes.bin'),('logical','logical-interned.bin')]:
        for group in (64,256,1024):
            run(f'{kind}-{group}',[str(a.scalar.resolve()),str((a.data/filename).resolve()),kind,str(group)])
    for block in (4096,65536,262144):
        for cache in (1048576,8388608):
            run(f'tokens-{block}-{cache}',[str(a.blocks.resolve()),str((a.data/'token-data.bin').resolve()),
                 str((a.data/'token-index.bin').resolve()),str(block),str(cache),'3'])
    hashes={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(a.output.glob('*.jsonl'))}
    (a.output/'completed.json').write_text(json.dumps({'completed':completed,'cpu':a.cpu,'observations_sha256':hashes,
        'scope':'Sequential standalone component experiments; not end-to-end scanner timing or RSS.'},indent=2)+'\n')


if __name__ == '__main__': main()
