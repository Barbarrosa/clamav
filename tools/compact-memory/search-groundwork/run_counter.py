#!/usr/bin/env python3
"""Run a caller-supplied counter with a bounded, hash-bound JSON protocol.

Command-file schema: {"argv":["executable","{input}"], "label":"caller label",
"identity_files":["engine-or-script"]}. Exactly one argv element must be the
literal {input}; no shell is used. Identity paths are relative to command-file
location. The child writes exactly one JSON object to stdout:
  {"status":"exact","count":"NONNEGATIVE_DECIMAL","input_sha256":"..."}
or {"status":"unknown","input_sha256":"..."}.

"exact" is a backend assertion, not a certificate. A declared engine label and
file hashes do not establish that any particular research algorithm ran. Reports
contain output hashes/sizes, never raw stdout or stderr. The optional expected
count checks a supplied fixture answer; it does not certify other instances.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


DECIMAL = re.compile(r'^(?:0|[1-9][0-9]*)$')
DEFAULT_OUTPUT_LIMIT = 1024 * 1024


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def dimacs_info(path):
    """Check the complete DIMACS body while preserving declared unused variables."""
    header, clauses, pending, literals, maximum_width = None, 0, 0, 0, 0
    with Path(path).open('r', encoding='ascii') as stream:
        for line in stream:
            parts = line.split()
            if not parts or parts[0] == 'c':
                continue
            if parts[0] == 'p':
                if header is not None or len(parts) != 4 or parts[1] != 'cnf':
                    raise ValueError('expected one DIMACS p cnf header')
                if not all(part.isdecimal() for part in parts[2:]):
                    raise ValueError('invalid DIMACS dimensions')
                header = tuple(int(part) for part in parts[2:])
                continue
            if header is None:
                raise ValueError('DIMACS clauses precede their header')
            for part in parts:
                if not re.fullmatch(r'-?[0-9]+', part):
                    raise ValueError('noninteger DIMACS literal')
                literal = int(part)
                if literal == 0:
                    clauses += 1
                    maximum_width = max(maximum_width, pending)
                    pending = 0
                else:
                    if abs(literal) > header[0]:
                        raise ValueError('DIMACS literal exceeds declared variable universe')
                    pending += 1
                    literals += 1
    if header is None or pending or clauses != header[1]:
        raise ValueError('incomplete DIMACS header or clause body')
    return {'declared_variables': header[0], 'clauses': clauses,
            'literal_occurrences': literals, 'maximum_clause_width': maximum_width}


def _strict_json(text):
    def pairs(items):
        output = {}
        for key, value in items:
            if key in output:
                raise ValueError('duplicate JSON key')
            output[key] = value
        return output

    def constant(value):
        raise ValueError('nonfinite JSON constant')

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _decimal_value(value):
    if not isinstance(value, str) or DECIMAL.fullmatch(value) is None:
        raise ValueError('count must be a canonical nonnegative decimal string')
    # Avoid changing Python's global decimal-to-integer safety setting. Small
    # chunks also support counters whose answers legitimately have >4300 digits.
    result = 0
    for start in range(0, len(value), 9):
        chunk = value[start:start + 9]
        result = result * (10 ** len(chunk)) + int(chunk)
    return result


def _within_assignment_universe(count, variables):
    bits = count.bit_length()
    return bits <= variables or (bits == variables + 1 and count & (count - 1) == 0)


def _kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_counter(cnf, command, timeout=30.0, expected_count=None,
                output_limit_bytes=DEFAULT_OUTPUT_LIMIT, identity_base=None):
    """Run the protocol and return provenance plus a non-certifying result.

    Valid statuses are reported_exact, fixture_count_matched, count_mismatch,
    unknown, timeout, output_limit, execution_error and protocol_error.
    Malformed caller configuration or DIMACS raises ValueError/OSError.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be positive and finite')
    if type(output_limit_bytes) is not int or not 256 <= output_limit_bytes <= 16 * 1024 * 1024:
        raise ValueError('output limit must be between 256 bytes and 16 MiB per stream')
    if not isinstance(command, dict) or set(command) != {'argv', 'label', 'identity_files'}:
        raise ValueError('command requires exactly argv, label and identity_files')
    argv, label, identities = command['argv'], command['label'], command['identity_files']
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(arg, str) or '\0' in arg for arg in argv) or
            not argv[0] or argv.count('{input}') != 1 or
            any('{input}' in arg and arg != '{input}' for arg in argv)):
        raise ValueError('argv must contain exactly one literal {input} element and no shell text substitution')
    if not isinstance(label, str) or not label or len(label) > 200:
        raise ValueError('label must be a nonempty caller-declared string of at most 200 characters')
    if (not isinstance(identities, list) or not identities or
            any(not isinstance(item, str) or not item for item in identities)):
        raise ValueError('identity_files must explicitly name at least one engine or script file')
    expected_text = None
    if expected_count is not None:
        if type(expected_count) is int:
            expected_count = str(expected_count)
        _decimal_value(expected_count)
        expected_text = expected_count
    cnf = Path(cnf).resolve()
    information = dimacs_info(cnf)
    input_hash = _sha(cnf)
    base = Path(identity_base).resolve() if identity_base is not None else Path.cwd()
    identity_paths = [((base / path).resolve() if not Path(path).is_absolute()
                       else Path(path).resolve()) for path in identities]
    if len(set(identity_paths)) != len(identity_paths) or any(not path.is_file() for path in identity_paths):
        raise ValueError('identity files must be distinct regular files')
    file_hashes = [{'path': str(path), 'sha256': _sha(path), 'bytes': path.stat().st_size}
                   for path in identity_paths]
    report = {
        'schema_version': 1, 'status': None, 'count': None,
        'input_sha256': input_hash, 'input': information,
        'backend_label': label, 'backend_label_source': 'caller declaration, not verified algorithm identity',
        'declared_identity_files': file_hashes,
        'argv_sha256': hashlib.sha256(json.dumps(argv, ensure_ascii=True,
                                     separators=(',', ':')).encode()).hexdigest(),
        'timeout_seconds': timeout, 'output_limit_bytes_per_stream': output_limit_bytes,
        'expected_count': expected_text, 'verified_against_supplied_expected_count': False,
        'independent_proof_certificate_verified': False,
        'linked_counting_construction_execution_established': False,
        'scope': 'external counter protocol and artifact binding; no independent count certification for general instances',
    }
    start = time.monotonic()
    actual_argv = [str(cnf) if arg == '{input}' else arg for arg in argv]
    with tempfile.TemporaryDirectory(prefix='clamav-counter-') as directory:
        stdout_path, stderr_path = Path(directory) / 'stdout', Path(directory) / 'stderr'
        process = None
        try:
            with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
                try:
                    process = subprocess.Popen(actual_argv, stdout=stdout, stderr=stderr,
                                               shell=False, start_new_session=True)
                except OSError:
                    report['status'] = 'execution_error'
                if process is not None:
                    deadline = start + timeout
                    while process.poll() is None:
                        if (stdout_path.stat().st_size > output_limit_bytes or
                                stderr_path.stat().st_size > output_limit_bytes):
                            report['status'] = 'output_limit'
                            _kill_group(process)
                            break
                        if time.monotonic() >= deadline:
                            report['status'] = 'timeout'
                            _kill_group(process)
                            break
                        time.sleep(min(0.01, max(0, deadline - time.monotonic())))
                    process.wait()
                    # No descendants may survive a completed or timed-out run.
                    _kill_group(process)
                    report['returncode'] = process.returncode
        finally:
            if process is not None:
                _kill_group(process)
                process.wait()
        report['elapsed_wall_seconds'] = time.monotonic() - start
        for name, path in [('stdout', stdout_path), ('stderr', stderr_path)]:
            report[name + '_bytes'] = path.stat().st_size
            report[name + '_sha256'] = _sha(path)
        if (report['stdout_bytes'] > output_limit_bytes or
                report['stderr_bytes'] > output_limit_bytes):
            report['status'] = report['status'] or 'output_limit'
        try:
            stable = (_sha(cnf) == input_hash and all(_sha(path) == item['sha256']
                      for path, item in zip(identity_paths, file_hashes)))
        except OSError:
            stable = False
        report['input_and_declared_identities_unchanged'] = stable
        if not stable:
            report['status'] = 'protocol_error'
            report['error'] = 'input or declared engine identity changed during execution'
        if report['status'] is not None:
            return report
        if report.get('returncode') != 0:
            report.update(status='execution_error', error='backend exited unsuccessfully')
            return report
        try:
            with stdout_path.open('rb') as output:
                raw = output.read(output_limit_bytes + 1)
            response = _strict_json(raw.decode('utf-8'))
            if not isinstance(response, dict) or response.get('input_sha256') != input_hash:
                raise ValueError('missing or mismatched input hash')
            if response.get('status') == 'unknown':
                if set(response) != {'status', 'input_sha256'}:
                    raise ValueError('unknown response must not include a count or extra fields')
                report['status'] = 'unknown'
                return report
            if set(response) != {'status', 'count', 'input_sha256'} or response['status'] != 'exact':
                raise ValueError('expected exact-count protocol response')
            text = response['count']
            # An upper bound on decimal digits of 2**n rejects grossly oversized
            # responses before constructing their integer representation.
            if isinstance(text, str) and len(text) > information['declared_variables'] * 30103 // 100000 + 1:
                raise ValueError('count exceeds declared assignment universe')
            count = _decimal_value(text)
            if not _within_assignment_universe(count, information['declared_variables']):
                raise ValueError('count exceeds declared assignment universe')
            report['count'] = text
            if expected_text is None:
                report['status'] = 'reported_exact'
            elif text != expected_text:
                report['status'] = 'count_mismatch'
            else:
                report['status'] = 'fixture_count_matched'
                report['verified_against_supplied_expected_count'] = True
        except (UnicodeError, json.JSONDecodeError):
            report.update(status='protocol_error', error='backend output is not one UTF-8 JSON protocol object')
        except ValueError as error:
            report.update(status='protocol_error', error=str(error))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cnf', type=Path, required=True)
    parser.add_argument('--command-file', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--expected-count')
    parser.add_argument('--output-limit-bytes', type=int, default=DEFAULT_OUTPUT_LIMIT)
    args = parser.parse_args()
    try:
        command = _strict_json(args.command_file.read_text())
        report = run_counter(args.cnf, command, args.timeout, args.expected_count,
                             args.output_limit_bytes, args.command_file.resolve().parent)
    except (OSError, ValueError, UnicodeError) as error:
        parser.error(str(error))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(args.report)}))
    return 0 if report['status'] in ('reported_exact', 'fixture_count_matched') else 2


if __name__ == '__main__':
    raise SystemExit(main())
