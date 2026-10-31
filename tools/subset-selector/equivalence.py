"""Detection equivalence for accepting all-match scans, never for callback stop/trust.
SPDX-License-Identifier: GPL-2.0-only
"""
from collections import Counter
import json


def detections(row):
    # Both APIs matter: weak/PUA names can occur only in legacy_virus callbacks
    # when a stronger alert supersedes them. Keep multiplicity and layer fields.
    return Counter(json.dumps(e, sort_keys=True) for e in row['events']
                   if e['event'] in ('alert', 'legacy_virus'))


def layers(row):
    # Non-alert callbacks expose the last selected name, which is order-dependent.
    # Retain their sequence and every other field, including object/depth/attributes.
    return [{k: v for k, v in e.items() if k != 'name'} for e in row['events']
            if e['event'] not in ('alert', 'legacy_virus')]


def detection_equivalent(full, reduced):
    keys = ('return_code', 'verdict', 'root_type', 'scanned_bytes', 'hold_bits',
            'sha256', 'after_sha256', 'candidate_outcome')
    names = {e['name'] for e in full['events'] if e['event'] in ('alert', 'legacy_virus')}
    selected_names_valid = (full['final_name'] == reduced['final_name'] or
                            (full['final_name'] in names and reduced['final_name'] in names))
    return (full['allmatch'] == reduced['allmatch'] == 1
            and selected_names_valid
            and all(full[k] == reduced[k] for k in keys)
            and detections(full) == detections(reduced)
            and layers(full) == layers(reduced))
