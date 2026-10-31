#!/usr/bin/env python3
"""Recompute aggregate comparison from retained JSONL experiment results."""
import argparse,json,statistics
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('results',type=Path);a=p.parse_args();d=a.results
read=lambda name:[json.loads(x) for x in (d/name).read_text().splitlines() if x.strip()]
out={}
for label in ('baseline','flat','indexed'):
 r=read('hash-'+label+'.jsonl');out[label]={'engine':r[0],'lookup_median_ns':{str(m):statistics.median(x['ns_per_query'] for x in r if x.get('kind')=='size_lookup' and x['mode']==m) for m in range(4)}}
for label in ('flat','indexed'):
 for k in ('records','queries','result_sha256','hits'):assert out[label]['engine'][k]==out['baseline']['engine'][k],(label,k)
b=out['baseline']['engine'];f=out['indexed']['engine']
out['indexed_vs_baseline']={'resident_saved_mib':(b['compiled_rss_kib']-f['compiled_rss_kib'])/1024,'resident_saved_percent':100*(1-f['compiled_rss_kib']/b['compiled_rss_kib']),'peak_change_mib':(f['compile_peak_rss_kib']-b['compile_peak_rss_kib'])/1024}
scans={}
for label in ('baseline','indexed'):
 scans[label]=read('scan-'+label+'-1.jsonl')
for i in (1,2):
 for k in ('files','virus_files','errors','callbacks','transcript_sha256'):assert scans['baseline'][i][k]==scans['indexed'][i][k],(i,k)
out['scan_corpus']=scans
out['onpair']={}
for bits in (12,14,16,'16-flagged'):
 path=d/f'onpair-{bits}.jsonl'
 if not path.exists():continue
 rows=read(path.name);first=rows[0]
 out['onpair'][str(bits)]={'layout':first,'median_access_ns':{str(m):{k:statistics.median(x[k+'_seconds']*1e9/x['queries'] for x in rows if x.get('kind')=='onpair_timing' and x['mode']==m) for k in ('raw','packed')} for m in range(5)}}
out['token_blocks']={}
for block in (4096,262144):
 rows=read(f'tokens-{block}.jsonl')
 out['token_blocks'][str(block)]={'layout':rows[0],'median_access_ns':{str(m):statistics.median(x['packed_seconds']*1e9/x['queries'] for x in rows if x.get('kind')=='token_timing' and x['input']==m) for m in range(4)}}
print(json.dumps(out,indent=2))
