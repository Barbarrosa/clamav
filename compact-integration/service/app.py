"""Authenticated streaming ASGI gateway. Bind to loopback behind a TLS proxy.

Only service-created private input paths ever reach the native worker protocol.
Successful scan responses follow deletion of the temporary request copy.
WordPress owns and retains the original. Cleanup failure is an explicit error.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
from urllib.parse import parse_qs
import tempfile
import time

# Also support direct file loading by the standalone integration probes.
if __package__:
    from . import release_client, work_budget
else:
    import importlib.util
    import sys
    _release_spec = importlib.util.spec_from_file_location('compact_release_client', Path(__file__).with_name('release_client.py'))
    release_client = sys.modules.get(_release_spec.name)
    if release_client is None:
        release_client = importlib.util.module_from_spec(_release_spec)
        sys.modules[_release_spec.name] = release_client
        _release_spec.loader.exec_module(release_client)
    _budget_spec = importlib.util.spec_from_file_location('compact_work_budget', Path(__file__).with_name('work_budget.py'))
    work_budget = sys.modules.get(_budget_spec.name)
    if work_budget is None:
        work_budget = importlib.util.module_from_spec(_budget_spec)
        sys.modules[_budget_spec.name] = work_budget
        _budget_spec.loader.exec_module(work_budget)

PROFILES = {'full', 'pdf-jpeg-png-pe-exclusions'}


@dataclass(frozen=True)
class Config:
    scanner: Path
    state: Path
    scratch: Path
    token: str
    max_input_bytes: int
    disk_reserve_bytes: int
    as_bytes: int
    cpu_seconds: int
    wall_seconds: int
    file_bytes: int
    output_bytes: int
    max_requests: int
    max_age_seconds: int
    admin_token: str = ''
    updater: Path | None = None
    certs: Path | None = None
    line_bytes: int = 0
    connect_seconds: int = 0
    low_speed_seconds: int = 0
    max_attempts: int = 0
    programs: Path | None = None
    release_public_key: str = ''
    release_channel: str = 'stable'
    code_staging_bytes: int = 0
    code_update_seconds: int = 0
    code_check_seconds: int = 0
    max_state_bytes: int = 0
    max_state_inodes: int = 0
    cpu_hour_seconds: int = 0
    cpu_day_seconds: int = 0
    cpu_month_seconds: int = 0
    maintenance_wait_seconds: float = 0
    response_seconds: float = 0

    @classmethod
    def environment(cls):
        def positive(name):
            value = int(os.environ['COMPACT_' + name])
            if value <= 0:
                raise ValueError(name + ' must be positive')
            return value
        def allocation(name):
            # Unknown new allocations keep HTTP/status available but authorize
            # no native work. They are never replaced with provider guesses.
            try:
                value = int(os.environ.get('COMPACT_' + name, '0'))
                return value if value > 0 else 0
            except ValueError:
                return 0
        def tightening(name):
            try:
                value = float(os.environ.get('COMPACT_' + name, '0'))
                return value if math.isfinite(value) and value > 0 else 0
            except ValueError:
                return 0
        config = cls(Path(os.environ['COMPACT_SCANNER']), Path(os.environ['COMPACT_STATE']),
                     Path(os.environ['COMPACT_SCRATCH']), os.environ['COMPACT_TOKEN'],
                     *(positive(k) for k in ['MAX_INPUT_BYTES', 'DISK_RESERVE_BYTES', 'AS_BYTES', 'CPU_SECONDS',
                                            'WALL_SECONDS', 'FILE_BYTES', 'OUTPUT_BYTES', 'MAX_REQUESTS', 'MAX_AGE_SECONDS']),
                     admin_token=os.environ.get('COMPACT_ADMIN_TOKEN', ''),
                     updater=Path(os.environ['COMPACT_UPDATER']) if os.environ.get('COMPACT_UPDATER') else None,
                     certs=Path(os.environ['COMPACT_CERTS']),
                     line_bytes=int(os.environ.get('COMPACT_LINE_BYTES', '0')),
                     connect_seconds=int(os.environ.get('COMPACT_CONNECT_SECONDS', '0')),
                     low_speed_seconds=int(os.environ.get('COMPACT_LOW_SPEED_SECONDS', '0')),
                     max_attempts=int(os.environ.get('COMPACT_MAX_ATTEMPTS', '0')),
                     programs=Path(os.environ['COMPACT_PROGRAMS']) if os.environ.get('COMPACT_PROGRAMS') else None,
                     release_public_key=os.environ.get('COMPACT_RELEASE_PUBLIC_KEY', ''),
                     release_channel=os.environ.get('COMPACT_RELEASE_CHANNEL', 'stable'),
                     code_staging_bytes=int(os.environ.get('COMPACT_CODE_STAGING_BYTES', '0')),
                     code_update_seconds=int(os.environ.get('COMPACT_CODE_UPDATE_SECONDS', '0')),
                     code_check_seconds=int(os.environ.get('COMPACT_CODE_CHECK_SECONDS', '0')),
                     max_state_bytes=int(os.environ.get('COMPACT_MAX_STATE_BYTES', '0')),
                     max_state_inodes=int(os.environ.get('COMPACT_MAX_STATE_INODES', '0')),
                     cpu_hour_seconds=allocation('CPU_HOUR_SECONDS'),
                     cpu_day_seconds=allocation('CPU_DAY_SECONDS'),
                     cpu_month_seconds=allocation('CPU_MONTH_SECONDS'),
                     maintenance_wait_seconds=tightening('MAINTENANCE_WAIT_SECONDS'),
                     response_seconds=tightening('RESPONSE_SECONDS'))
        if len(config.token) < 32 or (config.admin_token and (len(config.admin_token) < 32 or config.admin_token == config.token)):
            raise ValueError('Use distinct random scan/admin credentials, at least 32 characters')
        if any(not path.is_absolute() for path in (config.scanner, config.state, config.scratch, config.certs)):
            raise ValueError('Native paths must be absolute')
        if config.programs is not None and not config.programs.is_absolute():
            raise ValueError('Program path must be absolute')
        if config.updater is not None and not config.updater.is_absolute():
            raise ValueError('Updater path must be absolute')
        for directory in (config.state, config.scratch):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if (directory.is_symlink() or directory.stat().st_mode & 0o077
                    or directory.stat().st_uid != os.geteuid()):
                raise ValueError('State and scratch directories must be private and non-symlinked')
        return config

    def runtime(self, current=None):
        program = current.get('program') if current else None
        if program is not None:
            if self.programs is None:
                raise RuntimeError('Active code package requires COMPACT_PROGRAMS')
            scanner, updater, certs = release_client.resolve_program(self.programs, program)
            return scanner, updater, certs, program
        return self.scanner, self.updater, self.certs, None

    def limits(self):
        return ['--as-bytes', str(self.as_bytes), '--cpu-seconds', str(self.cpu_seconds),
                '--wall-seconds', str(self.wall_seconds), '--file-bytes', str(self.file_bytes)]

    def timeout(self, tightening=0):
        # Optional values only tighten an already confirmed work deadline.
        return min(self.wall_seconds, tightening) if tightening > 0 else self.wall_seconds


def child_environment(environment=None):
    value = dict(os.environ if environment is None else environment)
    value['COMPACT_PARENT_PID'] = str(os.getpid())
    return value


def json_object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('nonfinite JSON value')
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError('JSON object required')
    return value


async def kill_process(process):
    """Kill the new-session process group, with a direct-PID fallback."""
    if process is None:
        return
    lock = getattr(process, '_compact_kill_lock', None)
    if lock is None:
        lock = asyncio.Lock()
        process._compact_kill_lock = lock
    async with lock:
        if process.returncode is None:
            group_killed = False
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_killed = True
            except (ProcessLookupError, PermissionError):
                pass
            # Do not send a redundant Popen signal after killing the group:
            # Popen.poll() could race asyncio's child watcher to reap it.
            if not group_killed:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        # Close paused pipe transports, but leave process reaping to its watcher.
        transport = getattr(process, '_transport', None)
        if transport is not None:
            for descriptor in (0, 1, 2):
                pipe = transport.get_pipe_transport(descriptor)
                if pipe is not None:
                    pipe.close()
        await process.wait()


async def bounded_command(command, *, output_bytes, wall_seconds, environment=None, processes=None):
    process = None
    tasks = []
    combined = None
    total = 0

    async def read(stream):
        nonlocal total
        chunks = bytearray()
        while chunk := await stream.read(min(65536, output_bytes + 1)):
            total += len(chunk)
            if total > output_bytes:
                raise RuntimeError('subprocess output exceeded its envelope')
            chunks.extend(chunk)
        return bytes(chunks)

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True, env=child_environment(environment), limit=min(65536, output_bytes + 1))
        if processes is not None:
            processes.add(process)
        tasks = [asyncio.create_task(read(process.stdout)),
                 asyncio.create_task(read(process.stderr)),
                 asyncio.create_task(process.wait())]
        combined = asyncio.gather(*tasks)
        stdout, stderr, code = await asyncio.wait_for(combined, wall_seconds)
        if code != 0:
            raise RuntimeError('subprocess did not complete')
        return stdout, stderr
    finally:
        if process is not None:
            await kill_process(process)
            if processes is not None:
                processes.discard(process)
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if combined is not None:
            # Retrieve the original gather's cancellation/error too; awaiting
            # its individual children does not consume this future's result.
            await asyncio.gather(combined, return_exceptions=True)


class NativeWorker:
    def __init__(self, config):
        self.config = config
        self.process = None
        self.identity = None
        self.requests = 0
        self.stderr_task = None
        self.native_lease = None

    def active_snapshot(self):
        pointer = self.config.state / 'current.json'
        fd = os.open(pointer, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_size > self.config.output_bytes):
                raise RuntimeError('Invalid generation pointer')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(self.config.output_bytes + 1)
                current = json_object(raw)
        finally:
            os.close(fd)
        if (type(current.get('protocol')) is not int or current['protocol'] != 1
                or not isinstance(current.get('generation'), str)
                or not re.fullmatch('gen-[0-9a-f]{64}', current['generation'])):
            raise RuntimeError('No compatible generation active')
        program = current.get('program')
        if program is not None and (not isinstance(program, str) or not re.fullmatch('pkg-[0-9a-f]{64}', program)):
            raise RuntimeError('Invalid program pointer')
        return current, self.config.state / 'generations' / current['generation'], hashlib.sha256(raw).hexdigest()

    def active(self):
        current, generation, _ = self.active_snapshot()
        return current, generation

    async def stop(self):
        process, self.process = self.process, None
        try:
            await kill_process(process)
        finally:
            if self.stderr_task:
                self.stderr_task.cancel()
                await asyncio.gather(self.stderr_task, return_exceptions=True)
                self.stderr_task = None
            self.identity = None
            self.requests = 0
            if self.native_lease is not None:
                self.native_lease.close()
                self.native_lease = None

    async def stderr(self, process):
        count = 0
        while data := await process.stderr.read(min(65536, self.config.output_bytes + 1)):
            count += len(data)
            if count > self.config.output_bytes:
                await kill_process(process)
                raise RuntimeError('Native diagnostic output exceeded its envelope')

    async def scan(self, path, profile, sha256, size):
        current, generation = self.active()
        identity = (current['generation'], current.get('program'), profile)
        if self.identity != identity or self.requests >= self.config.max_requests or (self.process and self.process.returncode is not None):
            await self.stop()
        if self.config.certs is None:
            raise RuntimeError('Native certificate directory is not configured')
        line_task = None
        try:
            if not self.process:
                # Take the native OFD lease before integrity hashing or process
                # startup. The child inherits exactly this already locked FD.
                self.native_lease = work_budget.acquire_lease(self.config.state, 'job.lock')
                if self.native_lease is None:
                    raise RuntimeError('native state is busy')
                scanner, _, certs, _ = self.config.runtime(current)
                environment = {k: os.environ[k] for k in ('PATH',) if k in os.environ}
                environment.update(LANG='C.UTF-8', TMPDIR=str(self.config.scratch))
                self.process = await asyncio.create_subprocess_exec(
                    str(scanner), 'worker', '--state', str(self.config.state),
                    '--lock-fd', str(self.native_lease.fd),
                    '--generation', str(generation), '--certs', str(certs),
                    '--profile', profile, '--worker-max-requests', str(self.config.max_requests),
                    '--max-age-seconds', str(self.config.max_age_seconds), *self.config.limits(),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    limit=self.config.output_bytes + 1, env=child_environment(environment),
                    start_new_session=True, pass_fds=(self.native_lease.fd,))
                self.identity = identity
                self.stderr_task = asyncio.create_task(self.stderr(self.process))
            job = {'input': str(path), 'request_id': os.urandom(16).hex()}
            self.process.stdin.write(json.dumps(job).encode() + b'\n')
            await self.process.stdin.drain()
            line_task = asyncio.create_task(self.process.stdout.readline())
            started = time.monotonic()
            done, _ = await asyncio.wait(
                (line_task, self.stderr_task), timeout=self.config.wall_seconds,
                return_when=asyncio.FIRST_COMPLETED)
            if not done:
                raise TimeoutError('Native worker deadline')
            if self.stderr_task.done() and not self.stderr_task.cancelled():
                diagnostic_error = self.stderr_task.exception()
                if diagnostic_error is not None:
                    raise diagnostic_error
            remaining = self.config.wall_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError('Native worker deadline')
            raw = await asyncio.wait_for(line_task, remaining)
            if not raw or len(raw) > self.config.output_bytes:
                raise RuntimeError('Native worker produced no bounded result')
            result = json_object(raw)
            if (result.get('request_id') != job['request_id']
                    or type(result.get('protocol')) is not int or result['protocol'] != 1
                    or result.get('sha256') != sha256 or type(result.get('size')) is not int
                    or result['size'] != size or result.get('completed') is not True
                    or result.get('status') not in ('clean', 'detected', 'held')):
                raise RuntimeError('Native result does not identify a completed original scan')
            if result.get('requested_profile') != profile or result.get('effective_profile') != profile:
                raise RuntimeError('Native worker changed profile')
            if result.get('generation_id') != current['generation'][4:]:
                raise RuntimeError('Native worker changed generation')
            if result['status'] == 'clean' and (
                    result.get('applicability_proven') is not True
                    or result.get('coverage_qualified') is not True
                    or result.get('findings') != [] or result.get('reason_codes') != []):
                raise RuntimeError('Native clean result lacks qualification')
            self.requests += 1
            return result
        except BaseException:
            await self.stop()
            raise
        finally:
            if line_task and not line_task.done():
                line_task.cancel()
                await asyncio.gather(line_task, return_exceptions=True)


class Gateway:
    def __init__(self, config, worker=None, releases=None, budget=None):
        self.config = config
        self.worker = worker or NativeWorker(config)
        self.lock = asyncio.Lock()
        self.processes = set()
        self.maintenance_waiting = False
        self.scan_retry_at = 0
        self.budget = budget or work_budget.BudgetLedger(config.state, config.cpu_hour_seconds,
                                                        config.cpu_day_seconds, config.cpu_month_seconds)
        allocations = (config.cpu_hour_seconds, config.cpu_day_seconds, config.cpu_month_seconds)
        self.budget_status = {
            'configured': all(type(value) is int and 0 < value <= ((1 << 64) - 1) // 1000
                              for value in allocations),
            'allocations_seconds': dict(zip(('hour', 'day', 'month'), allocations)),
            'scan_fraction_policy': 0.8, 'maintenance_reserve_policy': 0.2,
            'minimum_scan_charge_seconds_policy': 1, 'month_seconds_policy': 2678400,
            'charges_are_conservative': True,
        }
        self.releases = releases or release_client.ReleaseClient(
            programs=config.programs, public_key=config.release_public_key, channel=config.release_channel,
            staging_bytes=config.code_staging_bytes, metadata_bytes=config.output_bytes,
            wall_seconds=config.code_update_seconds, check_seconds=config.code_check_seconds,
            disk_reserve_bytes=config.disk_reserve_bytes)
        self.code_status = dict(self.releases.health)
        if config.programs is not None and config.release_public_key:
            try:
                status = release_client.json_value(release_client.read_private(
                    config.programs / 'code-update-status.json', config.output_bytes))
                if isinstance(status, dict):
                    self.code_status = status
            except (OSError, release_client.ReleaseError):
                self.code_status = {'status': 'configured', 'reason': 'release-check-not-yet-recorded'}

    def active_runtime(self):
        try:
            current, _, expected = NativeWorker(self.config).active_snapshot()
        except FileNotFoundError:
            current, expected = None, 'absent'
        return (*self.config.runtime(current), expected)

    def code_health(self, status):
        self.code_status = status
        if self.config.programs is not None and self.config.programs.exists():
            try:
                recorded = self.releases.record(status)
                if isinstance(recorded, dict):
                    self.code_status = recorded
            except (OSError, release_client.ReleaseError):
                self.code_status = dict(status, health_persistence_failed=True)

    async def respond(self, send, status, value):
        raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > self.config.output_bytes:
            status, raw = 503, b'{"error":"response-exceeds-envelope"}'
            if len(raw) > self.config.output_bytes:
                raw = b''
        async def transmit():
            await send({'type': 'http.response.start', 'status': status,
                        'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store'), (b'x-content-type-options', b'nosniff')]})
            await send({'type': 'http.response.body', 'body': raw})
        # A stalled reader cannot hold the processing slot or an unbounded task.
        await asyncio.wait_for(transmit(), self.config.timeout(self.config.response_seconds))

    def budget_denial(self, kind, error):
        reason = error.reason if isinstance(error, work_budget.BudgetDeferred) else 'budget_state_invalid'
        retry = error.retry_after if isinstance(error, work_budget.BudgetDeferred) else 1
        self.budget_status.update(last_denial=reason, retry_after=retry)
        if kind == 'scan':
            self.scan_retry_at = max(self.scan_retry_at, time.time() + retry)
        return 503, {'error': kind + '_budget_unknown' if reason == 'cpu_allocation_unknown'
                     else kind + '_budget_deferred', 'reason': reason, 'retry_after': retry}

    def settle_budget(self, token):
        if token is not None:
            self.budget.finish(token)
            try:
                snapshot = self.budget.snapshot()
                self.budget_status.update(snapshot)
                self.scan_retry_at = max(self.scan_retry_at, snapshot['scan_next_at'])
            except work_budget.BudgetDeferred as error:
                # Committed conservative debt is authoritative. Status refresh
                # cannot erase it or turn an incomplete scan into clean.
                self.budget_status.update(last_denial=error.reason)

    def reserve_budget(self, kind, charge, duration):
        try:
            # Fixed control-format workspace, not a guessed hosting quota.
            if shutil.disk_usage(self.config.state).free < self.config.disk_reserve_bytes + 2 * work_budget.METADATA_BYTES:
                raise work_budget.BudgetDeferred('budget_state_capacity')
        except OSError as error:
            raise work_budget.BudgetDeferred('budget_state_capacity') from error
        return self.budget.reserve(kind, charge, duration)

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            while True:
                event = await receive()
                if event['type'] == 'lifespan.startup':
                    await send({'type': 'lifespan.startup.complete'})
                elif event['type'] == 'lifespan.shutdown':
                    await self.worker.stop()
                    await asyncio.gather(*(kill_process(p) for p in tuple(self.processes)))
                    await send({'type': 'lifespan.shutdown.complete'})
                    return
        if scope['type'] != 'http':
            return
        headers = {}
        for key, value in scope.get('headers', []):
            if key.lower() in headers:
                return await self.respond(send, 400, {'error': 'duplicate-header'})
            headers[key.lower()] = value
        authorization = headers.get(b'authorization', b'')
        scan_token = b'Bearer ' + self.config.token.encode('utf-8')
        if not hmac.compare_digest(authorization, scan_token):
            if (scope['path'] == '/v1/update' and self.config.admin_token
                    and hmac.compare_digest(authorization, b'Bearer ' + self.config.admin_token.encode('utf-8'))):
                return await self.update(scope, send)
            return await self.respond(send, 401, {'error': 'authentication-required'})
        if scope['path'] == '/v1/status' and scope['method'] == 'GET':
            try:
                current, _ = NativeWorker(self.config).active()
                active = {'generation': current['generation'], 'program': current.get('program')}
            except Exception:
                active = {'status': 'unavailable'}
            return await self.respond(send, 200, {'protocol': 1, 'busy': self.lock.locked(),
                'maintenance_pending': self.maintenance_waiting, 'scan_budget': self.budget_status,
                'retains_uploads': False, 'active_pointer': active, 'code_update': self.code_status})
        if scope['path'] != '/v1/scan' or scope['method'] != 'POST':
            return await self.respond(send, 404, {'error': 'not-found'})
        status, response = await self.scan_request(scope, receive, headers)
        return await self.respond(send, status, response)

    async def scan_request(self, scope, receive, headers):
        try:
            query_bytes = scope.get('query_string', b'')
            if len(query_bytes) > 3 * (len('profile=') + max(map(len, PROFILES))):
                raise ValueError('query exceeds protocol envelope')
            query = parse_qs(query_bytes.decode('ascii'), strict_parsing=True,
                             keep_blank_values=True, max_num_fields=1, encoding='ascii', errors='strict')
            profile = query.get('profile', ['full'])
            if len(profile) != 1 or profile[0] not in PROFILES or set(query) - {'profile'}:
                raise ValueError('invalid profile')
            expected_hash = headers.get(b'x-content-sha256', b'').decode('ascii')
            length_text = headers.get(b'content-length', b'').decode('ascii')
            if not re.fullmatch('[0-9a-f]{64}', expected_hash) or not re.fullmatch('[0-9]{1,20}', length_text):
                raise ValueError('invalid identity')
            length = int(length_text)
            if b'transfer-encoding' in headers:
                raise ValueError('ambiguous request framing')
        except (ValueError, UnicodeError):
            return 400, {'error': 'invalid-profile-or-input-identity'}
        if length == 0:
            return 400, {'error': 'empty-input-not-accepted'}
        if length > self.config.max_input_bytes or length > self.config.file_bytes:
            return 413, {'error': 'input-exceeds-envelope'}
        if not self.budget_status['configured']:
            return self.budget_denial('scan', work_budget.BudgetDeferred('cpu_allocation_unknown'))
        if self.maintenance_waiting:
            return 503, {'error': 'maintenance-pending'}
        if time.time() < self.scan_retry_at:
            return 503, {'error': 'scan_budget_deferred', 'reason': 'scan_paced',
                         'retry_after': max(1, math.ceil(self.scan_retry_at - time.time()))}
        if self.lock.locked():
            return 503, {'error': 'scanner-busy'}
        lease = None
        try:
            intent = work_budget.acquire_lease(self.config.state, 'service-maintenance.lock')
            if intent is None:
                return 503, {'error': 'maintenance-pending'}
            intent.close()
            lease = work_budget.acquire_lease(self.config.state, 'service-admission.lock')
            if lease is None:
                return 503, {'error': 'scanner-busy'}
            async with self.lock:
                return await self.scan_admitted(receive, profile[0], expected_hash, length)
        except work_budget.BudgetDeferred as error:
            return self.budget_denial('scan', error)
        finally:
            if lease is not None:
                lease.close()

    async def scan_admitted(self, receive, profile, expected_hash, length):
        path = None
        token = None
        native_started = False
        status, response = 503, {'error': 'scan-did-not-complete'}
        deadline = time.monotonic() + self.config.wall_seconds
        try:
            # POLICY: every admitted request reserves at least one CPU
            # second, and the full native lifetime allowance when actual
            # per-request CPU is unavailable. Recycling cannot reset debt.
            token = self.reserve_budget('scan', max(1, self.config.cpu_seconds), self.config.wall_seconds)
            if shutil.disk_usage(self.config.scratch).free < self.config.disk_reserve_bytes + length:
                status, response = 503, {'error': 'scratch-capacity-unavailable'}
                return status, response
            fd, name = tempfile.mkstemp(prefix='scan-', dir=self.config.scratch)
            path = Path(name)
            size, digest = 0, hashlib.sha256()
            with os.fdopen(fd, 'wb') as output:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('input deadline')
                    message = await asyncio.wait_for(receive(), remaining)
                    if message['type'] == 'http.disconnect':
                        raise ConnectionError('client disconnected')
                    if message['type'] != 'http.request':
                        raise ValueError('invalid request event')
                    chunk = message.get('body', b'')
                    size += len(chunk)
                    if size > length:
                        raise ValueError('input size changed')
                    if shutil.disk_usage(self.config.scratch).free < self.config.disk_reserve_bytes + len(chunk):
                        raise OSError('scratch reserve exhausted')
                    output.write(chunk)
                    digest.update(chunk)
                    if not message.get('more_body', False):
                        break
                output.flush()
                os.fsync(output.fileno())
            if size != length or not hmac.compare_digest(digest.hexdigest(), expected_hash):
                raise ValueError('input identity changed')
            path.chmod(0o400)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('scan deadline')
            native_started = True
            response = await asyncio.wait_for(
                self.worker.scan(path, profile, digest.hexdigest(), size), remaining)
            status = 200
        except work_budget.BudgetDeferred as error:
            status, response = self.budget_denial('scan', error)
        except (ValueError, ConnectionError):
            if native_started:
                await self.worker.stop()
                status, response = 503, {'error': 'scan-did-not-complete'}
            else:
                status, response = 400, {'error': 'input-incomplete-or-changed'}
        except asyncio.CancelledError:
            if native_started:
                await self.worker.stop()
            raise
        except Exception:
            if native_started:
                await self.worker.stop()
        finally:
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    status, response = 503, {'error': 'scratch-cleanup-failed'}
                    await self.worker.stop()
            if token is not None:
                try:
                    self.settle_budget(token)
                except Exception:
                    status, response = 503, {'error': 'scan-budget-settlement-failed'}
        return status, response

    async def command(self, arguments, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('administrative deadline')
        return await bounded_command(arguments, output_bytes=self.config.output_bytes,
                                     wall_seconds=remaining, processes=self.processes)

    async def update_runtime(self, runtime, deadline):
        scanner, updater, certs, program, expected = runtime
        if updater is None or certs is None:
            raise ValueError('runtime updater is not configured')
        raw, _ = await self.command([str(scanner), 'doctor', '--state', str(self.config.state),
                                    *self.config.limits()], deadline)
        info = json_object(raw)
        if type(info.get('protocol')) is not int or info['protocol'] != 1 or info.get('status') != 'ready':
            raise ValueError('runtime protocol')
        for key in ('engine_sha256', 'scan_options_sha256'):
            if not isinstance(info.get(key), str) or not re.fullmatch('[0-9a-f]{64}', info[key]):
                raise ValueError('runtime identity')
        if min(self.config.line_bytes, self.config.connect_seconds, self.config.low_speed_seconds, self.config.max_attempts,
               self.config.max_state_bytes, self.config.max_state_inodes) <= 0:
            raise ValueError('update budgets not configured')
        command = [str(updater), 'update', '--state', str(self.config.state),
                   '--scanner', str(scanner), '--certs', str(certs),
                   '--engine-sha256', info['engine_sha256'], '--options-sha256', info['scan_options_sha256'],
                   '--expected-current-sha256', expected,
                   '--max-line-bytes', str(self.config.line_bytes), '--connect-seconds', str(self.config.connect_seconds),
                   '--low-speed-seconds', str(self.config.low_speed_seconds), '--max-attempts', str(self.config.max_attempts),
                   '--max-age-seconds', str(self.config.max_age_seconds),
                   '--disk-reserve-bytes', str(self.config.disk_reserve_bytes),
                   '--max-state-bytes', str(self.config.max_state_bytes),
                   '--max-state-inodes', str(self.config.max_state_inodes), *self.config.limits()]
        if program is not None:
            command += ['--program-id', program]
        stdout, _ = await self.command(command, deadline)
        values = [json_object(line) for line in stdout.splitlines() if line.startswith(b'{')]
        if not values:
            raise ValueError('missing update result')
        result = values[-1]
        if (type(result.get('protocol')) is not int or result['protocol'] != 1
                or result.get('status') not in ('updated', 'up_to_date', 'deferred', 'failed')):
            raise ValueError('update protocol')
        if result['status'] in ('updated', 'up_to_date'):
            if not re.fullmatch('gen-[0-9a-f]{64}', result.get('generation', '')):
                raise ValueError('update generation')
            current, _ = NativeWorker(self.config).active()
            if current.get('program') != program or current['generation'] != result['generation']:
                raise RuntimeError('requested code/database tuple was not activated')
        return result

    async def update(self, scope, send):
        status, response = await self.maintenance_request(scope)
        return await self.respond(send, status, response)

    async def maintenance_request(self, scope):
        if scope['method'] != 'POST' or self.config.updater is None or self.config.certs is None:
            return 404, {'error': 'not-found'}
        if scope.get('query_string'):
            return 400, {'error': 'update-arguments-not-accepted'}
        if not self.budget_status['configured']:
            return self.budget_denial('maintenance', work_budget.BudgetDeferred('cpu_allocation_unknown'))
        if min(self.config.max_state_bytes, self.config.max_state_inodes) <= 0:
            return 503, {'error': 'update-state-policy-not-configured'}
        if self.config.file_bytes > self.config.max_state_bytes // 5:
            return 503, {'error': 'update-file-cap-exceeds-state-headroom'}
        if self.maintenance_waiting:
            return 503, {'error': 'maintenance-already-pending'}
        intent = lease = None
        acquired = False
        tokens = []
        status, response = 503, {'error': 'update-status-unconfirmed-check-active-generation',
                                 'code_update': self.code_status}
        try:
            intent = work_budget.acquire_lease(self.config.state, 'service-maintenance.lock')
            if intent is None:
                return 503, {'error': 'maintenance-already-pending'}
            self.maintenance_waiting = True
            deadline = time.monotonic() + self.config.timeout(self.config.maintenance_wait_seconds)
            # Do not acquire in a separate wait_for task: cancellation after
            # that task takes the lock could otherwise lose its ownership.
            while self.lock.locked():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('maintenance admission deadline')
                await asyncio.sleep(min(0.025, remaining))
            if time.monotonic() >= deadline:
                raise TimeoutError('maintenance admission deadline')
            await self.lock.acquire()  # Uncontended; no suspension before ownership is recorded.
            acquired = True
            while lease is None:
                lease = work_budget.acquire_lease(self.config.state, 'service-admission.lock')
                if lease is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('maintenance admission deadline')
                    # Scheduler granularity only; not a provider resource allowance.
                    await asyncio.sleep(min(0.025, remaining))
            duration = self.config.wall_seconds + max(0, self.config.code_update_seconds)
            charge = 2 * max(1, self.config.cpu_seconds)  # doctor plus updater.
            tokens.append(self.reserve_budget('maintenance', charge, duration))
            code_allowed = True
            if self.config.release_public_key and self.config.code_update_seconds > 0:
                try:
                    tokens.append(self.reserve_budget('maintenance', charge, duration))
                except work_budget.BudgetDeferred as error:
                    if error.reason not in ('cpu_budget_exhausted', 'budget_busy'):
                        raise
                    # Preserve the already reserved trusted DB update even
                    # when a second code-candidate allowance is unavailable.
                    code_allowed = False
            status, response = await self.update_admitted(code_allowed)
        except work_budget.BudgetDeferred as error:
            status, response = self.budget_denial('maintenance', error)
        except TimeoutError:
            status, response = 503, {'error': 'maintenance-wait-deadline'}
        finally:
            for token in tokens:
                try:
                    self.settle_budget(token)
                except Exception:
                    status, response = 503, {'error': 'maintenance-budget-settlement-failed'}
            if lease is not None:
                lease.close()
            if acquired:
                self.lock.release()
            self.maintenance_waiting = False
            if intent is not None:
                intent.close()
        return status, response

    async def update_admitted(self, code_allowed=True):
        await self.worker.stop()
        try:
            baseline = self.active_runtime()
        except Exception:
            return 503, {'error': 'active-runtime-unavailable'}
        candidate = None
        if code_allowed:
            try:
                if self.config.release_public_key and self.config.code_update_seconds > 0:
                    candidate = await asyncio.wait_for(self.releases.stage_next(), self.config.code_update_seconds)
                else:
                    candidate = await self.releases.stage_next()
            except TimeoutError:
                self.releases.health = {'status': 'failed', 'reason': 'code-update-deadline'}
            except Exception:
                # Code failures never disable independently trusted DB updates.
                pass
            self.code_health(dict(self.releases.health))
        else:
            self.code_health({'status': 'deferred', 'reason': 'code-cpu-budget-unavailable'})
        deadline = time.monotonic() + self.config.wall_seconds
        try:
            if candidate is not None:
                try:
                    runtime = (*release_client.resolve_program(self.config.programs, candidate.id), candidate.id, baseline[4])
                    result = await self.update_runtime(runtime, deadline)
                    if result['status'] in ('updated', 'up_to_date'):
                        self.code_health({'status': 'active', 'program': candidate.id,
                                          'generation': result['generation'], 'sequence': candidate.manifest['sequence']})
                        return 200, dict(result, code_update=self.code_status)
                except Exception:
                    pass
                self.code_health({'status': 'failed', 'reason': 'candidate-qualification-or-activation-unconfirmed',
                                  'candidate_program': candidate.id})
            # Re-read the atomic tuple after a lost acknowledgement; do not assume
            # candidate failure means activation could not already have happened.
            result = await self.update_runtime(self.active_runtime(), deadline)
            return 200, dict(result, code_update=self.code_status)
        except Exception:
            return 503, {'error': 'update-status-unconfirmed-check-active-generation',
                         'code_update': self.code_status}


def create_app():
    return Gateway(Config.environment())
