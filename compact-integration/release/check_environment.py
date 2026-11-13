#!/usr/bin/env python3
"""Require configured channel protection before a signing job may proceed.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository', required=True)
    p.add_argument('--channel', choices=('preview', 'stable'), required=True)
    a = p.parse_args()
    raw = subprocess.check_output(['gh', 'api', f'repos/{a.repository}/environments/compact-{a.channel}'], text=True)
    environment = json.loads(raw)
    policy = environment.get('deployment_branch_policy') or {}
    if policy.get('protected_branches') is not True:
        raise ValueError('Signing environment must restrict deployment to protected branches')
    if a.channel == 'stable' and not any(rule.get('type') == 'required_reviewers' and rule.get('reviewers')
                                        for rule in environment.get('protection_rules', [])):
        raise ValueError('Stable signing environment requires explicit reviewer protection')


if __name__ == '__main__':
    main()
