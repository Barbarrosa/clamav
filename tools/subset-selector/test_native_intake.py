#!/usr/bin/env python3
"""Exercise the real supervised intake, preserving exact public/synthetic inputs.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import resource
import time
import intake
from select_db import sha


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('generation','probe','lib','certs','clean','positive','output'):
        p.add_argument('--'+arg,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    measurements=[]
    for profile in ('full','pdf-jpeg-png-pe-exclusions'):
        for kind,source in [('clean',a.clean),('positive',a.positive)]:
            for repetition in range(3):
                before=source.read_bytes();folder,_=intake.preserve(source,a.output/'quarantine')
                start=time.monotonic();cpu=resource.getrusage(resource.RUSAGE_CHILDREN)
                result=intake.assess(folder,a.generation,a.probe,a.lib,a.certs,
                                     database_profile=profile,max_database_age_hours=168)
                # The historic benchmark snapshot is deliberately allowed ONLY in this test.
                used=resource.getrusage(resource.RUSAGE_CHILDREN)
                assert (folder/'original').read_bytes()==before==source.read_bytes()
                assert result['outcome'] in (('clean',) if kind=='clean' and profile=='full'
                    else ('held',) if kind=='clean' else ('held','detected')),result
                if kind=='positive':
                    evidence=result['scan_evidence'][0]
                    assert (evidence['return_code']==1 if result['runtime'].get('scan_api')=='legacy-1.4'
                            else evidence['verdict'] in (2,3)),result
                if profile=='pdf-jpeg-png-pe-exclusions':assert not result['release_qualified']
                measurements.append(dict(profile=profile,kind=kind,repetition=repetition,
                    wall_seconds=time.monotonic()-start,
                    child_cpu_seconds=used.ru_utime+used.ru_stime-cpu.ru_utime-cpu.ru_stime,
                    compiled_rss_mib=result['engine']['compiled_rss_kib']/1024,
                    construction_hwm_mib=result['engine']['construction_hwm_kib']/1024,
                    source_sha256=sha(source),record=str(folder/'record.json'),outcome=result['outcome'],
                    release_qualified=result['release_qualified']))
    folder,_=intake.preserve(a.clean,a.output/'quarantine')
    stale=intake.assess(folder,a.generation,a.probe,a.lib,a.certs,database_profile='pdf-jpeg-png-pe-exclusions')
    assert stale['outcome']=='failed' and 'stale' in stale['reason'],stale
    report={'passed':True,'real_scans':len(measurements),'stale_default_rejected':True,
        'note':'Integration telemetry under concurrent regression-test load, not a controlled performance benchmark. Single-file intake includes verification, fresh engine startup and durable writes. These are NOT replacements for the prior controlled 78-process tables. Historical signed database allowed for tests with 168h limit; shipping default is 48h.',
        'measurements':measurements}
    (a.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
