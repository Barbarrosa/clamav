#!/usr/bin/env python3
"""Render identical numeric table data as Markdown, JSON and exact PNGs."""
import argparse
import json
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from profile_labels import VARIANTS, normalize_summary

HEADERS = ('Metric', 'Original ClamAV', 'New · full DB', 'PDF/JPEG/PNG')


def build_tables(summary):
    summary = normalize_summary(summary)
    variants = summary['variants']
    def values(fn): return [fn(variants[v]) for v in VARIANTS]
    def mean(d, key): return d[key]['mean']
    def fmt(n, places=2): return f'{n:,.{places}f}'
    def pair(v, section, key, scale=1, places=3,stat='mean'):
        names = ('empty', 'hydrated') if section == 'startup' else ('file_cache_empty', 'file_cache_hydrated')
        return ' → '.join(fmt(v[section][n][key][stat]/scale, places) for n in names)
    overview = [
        ['Engine-counted signatures loaded', *values(lambda v:f"{v['signatures_loaded']:,}")],
        ['Signatures loaded (% of full)', *values(lambda v:fmt(v['percent_full_signature_count'])+'%')],
        ['Signed database bytes retained', *values(lambda v:fmt(v['signed_source_bytes']/2**20,3)+' MiB · 100%')],
        ['Compiled engine RSS (MiB, mean)', *values(lambda v:fmt(v['compiled_rss_kib']['mean']/1024,1))],
        ['Construction peak RSS (MiB, max)', *values(lambda v:fmt(v['construction_hwm_kib']['max']/1024,1))],
        ['Peak through accepted scans (MiB, max)', *values(lambda v:fmt(v['scan_hwm_kib_max']/1024,1))],
        ['Two-engine reload peak RSS (MiB, max)', *values(lambda v:fmt(v['reload']['hwm_kib']['max']/1024,1))],
        ['Reload wall time (s, mean)', *values(lambda v:fmt(v['reload']['wall_seconds']['mean'],3))],
        ['Reload CPU time (s, mean)', *values(lambda v:fmt(v['reload']['cpu_seconds']['mean'],3))],
        ['Two engines + update test peak RSS (MiB)', *values(lambda v:fmt(v['update_overlap_peak_kib']/1024,1))],
    ]
    os_cache=[]
    for label,kind in [('DB page-cache RAM before load (MiB)','database'),('Input page-cache RAM before scan (MiB)','accepted_inputs')]:
        cache=summary['page_cache_working_sets'][kind]
        os_cache.append([label,*[f"0.00 → {cache['hydrated_resident_bytes']/2**20:.2f}"]*3])
    for label, section, key, scale, places in (
        ('Startup wall time (s, mean)', 'startup','wall_seconds',1,3),
        ('Startup CPU time (s, mean)', 'startup','cpu_seconds',1,3),
        ('Startup CPU utilization (%)', 'startup','cpu_percent_one_core',1,1),
        ('Post-startup RSS (MiB)', 'startup','rss_kib',1024,1),
        ('Post-startup PSS (MiB)', 'startup','pss_kib',1024,1),
        ('28-file scan wall time (s, mean)', 'scan','wall_seconds',1,3),
        ('28-file scan CPU time (s, mean)', 'scan','cpu_seconds',1,3),
        ('Scan CPU utilization (%)', 'scan','cpu_percent_one_core',1,1),
        ('Post-scan RSS (MiB)', 'scan','rss_kib',1024,1),
        ('Post-scan PSS (MiB)', 'scan','pss_kib',1024,1),
        ('Post-scan USS (MiB)', 'scan','uss_kib',1024,1),
        ('Input block reads (MiB per batch)', 'scan','block_read_bytes',2**20,2),
    ):
        os_cache.append([label,*values(lambda v,s=section,k=key,sc=scale,p=places:pair(v,s,k,sc,p))])
        if key in ('wall_seconds','cpu_seconds'):
            os_cache.append([label.replace('mean','median'),*values(lambda v,s=section,k=key,sc=scale,p=places:pair(v,s,k,sc,p,'median'))])
    for percentile in ('median','p95','p99'):
        os_cache.append([f'Per-file {percentile} latency (ms)',*values(lambda v,p=percentile:
            ' → '.join(fmt(v['scan_latency_ms'][n][p],2) for n in ('file_cache_empty','file_cache_hydrated')))])
    os_cache.append(['Hydrated scan throughput (MiB/s)',*values(lambda v:fmt(v['warm_throughput_mib_per_second'],2))])
    result_cache=[['Initial empty-cache engine RSS (MiB)',*values(lambda v:fmt(v['result_cache']['compiled_rss_kib']['mean']/1024,1))]]
    for label,key,scale,places in (
        ('28-file scan wall time (s)','wall_seconds',1,3),
        ('28-file scan CPU time (s)','cpu_seconds',1,3),
        ('Scan CPU utilization (%)','cpu_percent_one_core',1,1),
        ('Post-scan RSS (MiB)','rss_kib',1024,1),
        ('Post-scan PSS (MiB)','pss_kib',1024,1),
        ('Post-scan USS (MiB)','uss_kib',1024,1),
        ('Input block reads (MiB per batch)','block_read_bytes',2**20,2),
    ):
        result_cache.append([label,*values(lambda v,k=key,sc=scale,p=places:' → '.join(
            fmt(mean(v['result_cache'][n]['metrics'],k)/sc,p) for n in ('result_cache_empty','result_cache_hydrated')))])
    result_cache.extend([
        ['Verified root cache-hit rate',*values(lambda v:'0% → 100%')],
        ['Warmed-workload CPU reduction',*values(lambda v:fmt(v['result_cache']['cpu_reduction_percent'])+'%')],
        ['Configured cache entry capacity',*values(lambda v:f"{v['result_cache']['capacity']:,}")],
    ])
    return {'overview':overview,'os_cache':os_cache,'result_cache':result_cache}


def markdown(rows):
    return '\n'.join(['| '+' | '.join(HEADERS)+' |','|---|---:|---:|---:|']+
                     ['| '+' | '.join(row)+' |' for row in rows])


def render(path,title,subtitle,sections,notes):
    width=1920; margin=58; row_h=53; section_h=70; header_h=58
    height=190+sum(section_h+header_h+row_h*len(rows) for _,rows in sections)+45+len(notes)*34+32
    image=Image.new('RGB',(width,height),'#f5f7fa');draw=ImageDraw.Draw(image)
    fonts='/usr/share/fonts/truetype/dejavu/'
    regular=ImageFont.truetype(fonts+'DejaVuSans.ttf',25)
    small=ImageFont.truetype(fonts+'DejaVuSans.ttf',22)
    bold=ImageFont.truetype(fonts+'DejaVuSans-Bold.ttf',25)
    heading=ImageFont.truetype(fonts+'DejaVuSans-Bold.ttf',46)
    sectionfont=ImageFont.truetype(fonts+'DejaVuSans-Bold.ttf',29)
    draw.text((margin,38),title,font=heading,fill='#10283f')
    draw.text((margin,106),subtitle,font=regular,fill='#465769')
    cols=(margin,margin+735,margin+1090,margin+1445,width-margin)
    y=172
    for section,rows in sections:
        draw.text((margin,y+20),section,font=sectionfont,fill='#126a70');y+=section_h
        draw.rounded_rectangle((margin,y,width-margin,y+header_h),radius=8,fill='#17374e')
        for j,value in enumerate(HEADERS):
            box=draw.textbbox((0,0),value,font=bold)
            assert box[2]<=cols[j+1]-cols[j]-24,(value,box)
            draw.text((cols[j]+16,y+15),value,font=bold,fill='white')
        y+=header_h
        for i,row in enumerate(rows):
            draw.rectangle((margin,y,width-margin,y+row_h),fill='white' if i%2==0 else '#eaf0f5')
            draw.rectangle((cols[3],y,cols[4],y+row_h),fill='#e4f3ee' if i%2==0 else '#dcedE6')
            for j,value in enumerate(row):
                font=regular if j==0 else bold
                assert draw.textbbox((0,0),value,font=font)[2]<=cols[j+1]-cols[j]-24,value
                draw.text((cols[j]+16,y+13),value,font=font,fill='#172f43')
            y+=row_h
    y+=34
    for note in notes:
        assert draw.textbbox((0,0),note,font=small)[2]<width-2*margin,note
        draw.text((margin,y),note,font=small,fill='#465769');y+=34
    image.save(path,optimize=True)
    with path.open('rb') as f:os.fsync(f.fileno())


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--summary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=True);s=json.loads(a.summary.read_text());tables=build_tables(s)
    (a.output/'table-data.json').write_text(json.dumps({'headers':HEADERS,**tables},indent=2)+'\n')
    (a.output/'tables.md').write_text('\n\n'.join([
        '# Fresh three-way ClamAV measurements',
        'Same host, pinned source revisions, signed database snapshot and 28-file workload. Means except where labeled.',
        '## Database and lifecycle',markdown(tables['overview']),
        '## OS file-page cache: empty → hydrated',
        'Metadata enabled; ClamAV clean-result cache disabled. CPU utilization uses one core as 100%.',markdown(tables['os_cache']),
        '## ClamAV clean-result cache: empty → hydrated',
        'Diagnostic only: metadata disabled, OS input pages hydrated in both states. Not the evidence-preserving release configuration.',markdown(tables['result_cache'])])+'\n')
    render(a.output/'ClamAV-performance-comparison.png','ClamAV · fresh performance comparison',
        'Same host, build toolchain, database snapshot and scan options · 2026-10-29',
        [('Database and lifecycle',tables['overview'])],
        ['Means shown; peaks are observed maxima. RSS = resident process RAM. 1 MiB = 1,048,576 bytes.',
         'Reload retains old + replacement engines. Update peak adds one unreduced FreshClam DB-file validation.',
         'Update peak is the maximum across main, daily and bytecode validation (3 runs of each per variant).',
         'PDF/JPEG/PNG: eligible PE-specific rules excluded; 16.56% of engine-counted signatures loaded.',
         'All signed source database bytes are retained; signature count is not detection coverage.'])
    render(a.output/'ClamAV-OS-cache-comparison.png','OS file-page cache · empty → hydrated',
        'Evidence-preserving scans: metadata on, clean-result cache off · values are empty → hydrated',
        [('Database startup and 28-file scan workload',tables['os_cache'])],
        ['28 unique valid PDF/JPEG/PNG files · 14.158 MiB · one scanner · pinned CPU · 10 fresh engines per variant.',
         '5 startup runs per page-cache state; scans use 10 empty and 30 hydrated batches per variant.',
         'Tested-file residency verified at 0% / 100%. Cache setup is outside timed intervals; hashes are inside.',
         'Page-cache RAM covers the tested files only; report it separately from process RSS/PSS/USS.',
         'Means unless labeled median; pooled latency percentiles. CPU % = CPU seconds / wall seconds × 100.',
         'RSS: resident RAM. PSS: shared pages apportioned. USS: private pages. RAM sampled after each phase.'])
    render(a.output/'ClamAV-result-cache-comparison.png','ClamAV clean-result cache · empty → hydrated',
        'Separate diagnostic: metadata off; OS file pages hydrated in both states · empty → hydrated',
        [('28-file workload with verified cache hits',tables['result_cache'])],
        ['5 fresh engines per variant; 5 empty-cache and 15 hydrated-cache batches. All 28 root hits verified.',
         'Hydrated means this workload is cached; it does not mean all 65,536 configured entries are occupied.',
         'ClamAV bypasses clean-result caching when metadata collection is enabled. This is not a release policy.',
         'CPU can stay near 100% of one core while total CPU work drops sharply because each scan finishes sooner.',
         'RSS / PSS / USS and CPU values are means. Before/after file-integrity hashing remains in timed scans.'])
    print(json.dumps({'rendered':[str(p) for p in a.output.glob('*.png')]}))


if __name__=='__main__':main()
