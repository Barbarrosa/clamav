#!/usr/bin/env python3
"""Machine-readable release decision for this retained experimental build.
This is a checked-in decision, not a substitute for a deployment audit.
SPDX-License-Identifier: GPL-2.0-only
"""
import json

STATUS = {
    'production_ready': False,
    'restricted_automatic_release': False,
    'default_database_profile': 'full',
    'restricted_flag': '--database-profile=pdf-jpeg-png-pe-exclusions',
    'blockers': [
        {'id':'parser-completeness',
         'reason':'PE exclusion boundary tests pass; universal parsing completeness is not established. Reduced clean candidates remain held.'},
        {'id':'engine-release-qualification',
         'reason':'The retained engine is a custom 1.6 development build, not a supported stable/LTS release; security patch parity and the custom changes need release qualification.'},
        {'id':'deployment-isolation-and-recovery',
         'reason':'No target deployment supplied: read-only evidence isolation from the native scanner, queue recovery, storage quotas, access controls and service resource limits are unvalidated.'},
        {'id':'generation-update-operations',
         'reason':'Signed update preparation is validated locally; deployed freshness monitoring, promotion, rollback and recovery are unqualified.'},
    ],
    'report':'docs/production-readiness.md',
}

if __name__ == '__main__':
    print(json.dumps(STATUS, indent=2))
    raise SystemExit(3 if not STATUS['production_ready'] else 0)
