"""Current benchmark labels and read-only compatibility for archived results.

Only variant/comparison keys are normalized. File names, commands, hashes and
measurements remain the original evidence, including when a report reads an
older run. Ambiguous duplicate labels are rejected instead of mixing cohorts.
SPDX-License-Identifier: GPL-2.0-only
"""

RESTRICTED_VARIANT = 'pdf-jpeg-png-pe-exclusions'
LEGACY_RESTRICTED_VARIANT = 'legal-redress'
RESTRICTED_LABEL = 'PDF/JPEG/PNG with PE exclusions'
VARIANTS = ('upstream', 'full', RESTRICTED_VARIANT)


def normalize_variant(value):
    return RESTRICTED_VARIANT if value == LEGACY_RESTRICTED_VARIANT else value


def normalize_keys(mapping, key_function=normalize_variant):
    output = {}
    for key, value in mapping.items():
        canonical = key_function(key)
        if canonical in output:
            raise ValueError('duplicate historical/current benchmark variant: ' + canonical)
        output[canonical] = value
    return output


def normalize_comparison(value):
    left, separator, right = value.partition('-to-')
    if not separator:
        raise ValueError('invalid benchmark comparison label: ' + value)
    return normalize_variant(left) + separator + normalize_variant(right)


def normalize_summary(summary):
    """Return a current-label view; do not rewrite the archived summary."""
    result = dict(summary)
    result['variants'] = normalize_keys(summary['variants'])
    if 'comparisons' in summary:
        result['comparisons'] = normalize_keys(summary['comparisons'], normalize_comparison)
    if 'validation' in summary:
        result['validation'] = dict(summary['validation'])
        if 'primary_semantic_comparisons' in summary['validation']:
            result['validation']['primary_semantic_comparisons'] = normalize_keys(
                summary['validation']['primary_semantic_comparisons'])
        if 'extended_comparisons' in summary['validation']:
            result['validation']['extended_comparisons'] = {
                stage: normalize_keys(values)
                for stage, values in summary['validation']['extended_comparisons'].items()}
    return result
