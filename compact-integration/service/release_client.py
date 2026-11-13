"""Signed, bounded per-file native releases from one fixed GitHub repository.

A release is staged here; only compact-update may activate its code/database tuple.
No archives, downloaded keys or user-selected URLs are accepted.
"""
from __future__ import annotations
import asyncio
import base64
from dataclasses import dataclass
import email.utils
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import ssl
import stat
import tempfile
import time
from urllib.parse import urlsplit

REPOSITORY = 'Barbarrosa/clamav'
API = 'https://api.github.com/repos/' + REPOSITORY + '/releases'
DOWNLOAD = 'https://github.com/' + REPOSITORY + '/releases/download/'
PLATFORM = 'linux-x86_64-glibc2.36'
HOSTS = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
SEMVER = r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?'
REQUIRED = {'bin/compact-scan', 'bin/compact-update', 'lib/compact-scan.real',
            'lib/compact-update.real', 'certs/clamav.crt'}


class ReleaseError(RuntimeError):
    pass


def json_value(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ReleaseError('duplicate-release-json-key')
            value[key] = item
        return value
    def invalid(value):
        raise ReleaseError('nonfinite-release-json-value')
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, UnicodeError) as error:
        raise ReleaseError('invalid-release-json') from error


def private_directory(path, create=False, mode=None):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ReleaseError('unsafe-program-directory')
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise ReleaseError('unsafe-program-directory')
    return path


def regular(path, mode=None):
    info = Path(path).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o077
            or mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise ReleaseError('unsafe-program-file')
    return info


def read_private(path, limit):
    regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ReleaseError('oversized-program-state')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ReleaseError('oversized-program-state')
        return raw
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.state-', dir=Path(path).parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, separators=(',', ':'), allow_nan=False).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(Path(path).parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def inventory(manifest):
    if not isinstance(manifest.get('tag'), str) or not re.fullmatch('compact-v' + SEMVER, manifest['tag']):
        raise ReleaseError('invalid-release-tag')
    files = manifest.get('files')
    if not isinstance(files, list) or not 5 <= len(files) <= 512:
        raise ReleaseError('invalid-release-inventory')
    paths = set()
    total = 0
    for item in files:
        if not isinstance(item, dict):
            raise ReleaseError('invalid-release-file')
        path = item.get('path')
        if (not isinstance(path, str) or not re.fullmatch(r'(?:bin|lib|certs|notices)/[A-Za-z0-9_./+\-]+', path)
                or '..' in path or '//' in path or any(p in ('.', '') for p in path.split('/'))
                or path in paths or path.endswith('/')):
            raise ReleaseError('unsafe-release-path')
        if (type(item.get('size')) is not int or item['size'] < 1 or item['size'] > 2**63 - 1
                or not isinstance(item.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise ReleaseError('invalid-release-file-identity')
        executable = path.startswith('bin/') or path in ('lib/compact-scan.real', 'lib/compact-update.real')
        if item.get('mode') != ('0500' if executable else '0400'):
            raise ReleaseError('unsafe-release-mode')
        expected_url = DOWNLOAD + manifest['tag'] + '/' + item['sha256'][:16] + '--' + PurePosixPath(path).name
        if item.get('url') != expected_url:
            raise ReleaseError('release-asset-outside-fixed-repository')
        if any(path.startswith(old + '/') or old.startswith(path + '/') for old in paths):
            raise ReleaseError('conflicting-release-paths')
        paths.add(path)
        total += item['size']
        if total > 2**63 - 1:
            raise ReleaseError('release-size-overflow')
    if not REQUIRED <= paths:
        raise ReleaseError('missing-native-release-component')
    return files, total


def resolve_program(programs, program_id):
    """Verify an immutable, previously authenticated bundle before executing it."""
    if not isinstance(program_id, str) or not re.fullmatch('pkg-[0-9a-f]{64}', program_id):
        raise ReleaseError('invalid-program-id')
    root = private_directory(programs)
    private_directory(root / 'releases')
    bundle = private_directory(root / 'releases' / program_id, mode=0o500)
    raw = read_private(bundle / 'manifest.exact', 1048576)
    if hashlib.sha256(raw).hexdigest() != program_id[4:]:
        raise ReleaseError('installed-program-manifest-changed')
    manifest = json_value(raw)
    if not isinstance(manifest, dict) or manifest.get('repository') != REPOSITORY or manifest.get('platform') != PLATFORM:
        raise ReleaseError('invalid-installed-program-manifest')
    files, _ = inventory(manifest)
    expected = {'manifest.exact', 'manifest.sig'}
    for item in files:
        path = bundle / item['path']
        if path.resolve() != path:
            raise ReleaseError('installed-program-path-changed')
        for parent in path.parents:
            if parent == bundle:
                break
            private_directory(parent, mode=0o500)
        info = regular(path, int(item['mode'], 8))
        digest = hashlib.sha256()
        with path.open('rb') as source:
            while chunk := source.read(65536):
                digest.update(chunk)
        if info.st_size != item['size'] or digest.hexdigest() != item['sha256']:
            raise ReleaseError('installed-program-content-changed')
        expected.add(item['path'])
    if regular(bundle / 'manifest.sig', 0o400).st_size != 64:
        raise ReleaseError('invalid-installed-program-signature')
    actual = set()
    for path in bundle.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            private_directory(path, mode=0o500)
        elif stat.S_ISREG(info.st_mode):
            actual.add(path.relative_to(bundle).as_posix())
        else:
            raise ReleaseError('unlisted-installed-program-content')
    if actual != expected:
        raise ReleaseError('unlisted-installed-program-content')
    return bundle / 'bin/compact-scan', bundle / 'bin/compact-update', bundle / 'certs'


@dataclass(frozen=True)
class Candidate:
    id: str
    path: Path
    manifest: dict


class ReleaseClient:
    def __init__(self, *, programs, public_key, channel, staging_bytes, metadata_bytes,
                 wall_seconds, check_seconds, disk_reserve_bytes, fetch=None):
        self.programs = Path(programs) if programs is not None else None
        self.public_key = public_key
        self.channel = channel
        self.staging_bytes = staging_bytes
        self.metadata_bytes = min(metadata_bytes, 1048576)
        self.wall_seconds = wall_seconds
        self.check_seconds = check_seconds
        self.disk_reserve_bytes = disk_reserve_bytes
        self.fetch_override = fetch
        self.deadline = 0
        self.schedule = None
        self.ssl_context = None
        self.health = {'status': 'disabled', 'reason': 'release-public-key-not-configured'}

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise ReleaseError('code-update-deadline')
        return value

    def prepare(self):
        budgets = (self.staging_bytes, self.metadata_bytes, self.wall_seconds,
                   self.check_seconds, self.disk_reserve_bytes)
        if (self.programs is None or self.channel not in ('stable', 'preview')
                or any(type(value) is not int or not 0 < value <= 2**63 - 1 for value in budgets)
                or self.check_seconds > 2**63 - 1 - int(time.time())):
            raise ReleaseError('code-update-policy-not-configured')
        private_directory(self.programs, create=True)
        for name in ('releases', 'staging'):
            private_directory(self.programs / name, create=True)
        try:
            key = base64.b64decode(self.public_key, validate=True)
        except (ValueError, TypeError) as error:
            raise ReleaseError('invalid-release-public-key') from error
        if len(key) != 32 or base64.b64encode(key).decode() != self.public_key:
            raise ReleaseError('invalid-release-public-key')
        return key

    def lock(self):
        fd = os.open(self.programs / 'code-update.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise ReleaseError('unsafe-code-update-lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                return None
            return fd
        except BaseException:
            os.close(fd)
            raise

    def record(self, value):
        self.health = dict(value, checked_at=int(time.time()))
        if self.programs is not None:
            private_directory(self.programs)
            atomic_json(self.programs / 'code-update-status.json', self.health)
        return self.health

    async def stage_next(self):
        if not self.public_key:
            return None
        fd = None
        try:
            key = self.prepare()
            fd = self.lock()
            if fd is None:
                self.record({'status': 'deferred', 'reason': 'code-update-busy'})
                return None
            self.deadline = time.monotonic() + self.wall_seconds
            self.schedule = self.programs / ('code-update-' + self.channel + '.json')
            now = int(time.time())
            previous = json_value(read_private(self.schedule, self.metadata_bytes)) if self.schedule.exists() else {}
            if (not isinstance(previous, dict) or type(previous.get('next_at', 0)) is not int
                    or not 0 <= previous.get('next_at', 0) <= 2**63 - 1):
                raise ReleaseError('invalid-code-update-schedule')
            if now < previous.get('next_at', 0):
                self.record({'status': 'deferred', 'reason': 'code-check-not-due', 'next_attempt_after': previous['next_at']})
                return None
            atomic_json(self.schedule, {'attempted_at': now, 'next_at': now + self.check_seconds})
            release = await self.discover()
            if release is None:
                self.record({'status': 'up_to_date', 'reason': 'no-published-channel-release'})
                return None
            tag = release['tag_name']
            assets = {}
            for asset in release['assets']:
                if not isinstance(asset, dict) or asset.get('name') not in ('manifest.json', 'manifest.sig'):
                    continue
                name = asset['name']
                if (name in assets or asset.get('state') != 'uploaded' or type(asset.get('size')) is not int
                        or asset['size'] <= 0 or asset.get('browser_download_url') != DOWNLOAD + tag + '/' + name):
                    raise ReleaseError('invalid-release-manifest-assets')
                assets[name] = asset
            if (set(assets) != {'manifest.json', 'manifest.sig'} or assets['manifest.sig']['size'] != 64
                    or assets['manifest.json']['size'] > self.metadata_bytes):
                raise ReleaseError('invalid-release-manifest-assets')
            raw = await self.body(assets['manifest.json']['browser_download_url'], self.metadata_bytes, assets['manifest.json']['size'])
            signature = await self.body(assets['manifest.sig']['browser_download_url'], 64, 64)
            result = await self.stage(raw, signature, key=key, tag=tag)
            self.record({'status': 'staged', 'program': result.id, 'sequence': result.manifest['sequence']})
            return result
        except Exception as error:
            reason = str(error) if isinstance(error, ReleaseError) else 'code-release-fetch-or-install-failed'
            self.health = {'status': 'failed', 'reason': reason, 'checked_at': int(time.time())}
            if self.programs is not None:
                try:
                    self.record(self.health)
                except (OSError, ReleaseError):
                    pass
            raise ReleaseError(reason) from error
        finally:
            if fd is not None:
                os.close(fd)

    async def discover(self):
        # GitHub embeds every asset in each entry; three releases fit the same
        # metadata envelope without fetching an asset-heavy hundred-entry page.
        urls = ([API + '/latest'] if self.channel == 'stable'
                else (API + '?per_page=3&page=' + str(page) for page in range(1, 21)))
        value = None
        for url in urls:
            self.remaining()
            status, _, raw = await self.fetch(url, self.metadata_bytes)
            if status == 404:
                return None
            if status != 200:
                raise ReleaseError('release-discovery-http-' + str(status))
            entries = json_value(raw)
            if self.channel == 'stable':
                value = entries
                break
            if not isinstance(entries, list) or len(entries) > 3:
                raise ReleaseError('invalid-preview-release-inventory')
            value = next((v for v in entries if isinstance(v, dict)
                          and v.get('draft') is False and v.get('prerelease') is True), None)
            if value is not None:
                break
            if len(entries) < 3:
                return None
        if value is None:
            return None
        if (not isinstance(value, dict) or value.get('draft') is not False
                or value.get('prerelease') is not (self.channel == 'preview')
                or not isinstance(value.get('tag_name'), str) or not re.fullmatch('compact-v' + SEMVER, value['tag_name'])
                or not isinstance(value.get('assets'), list) or len(value['assets']) > 1024):
            raise ReleaseError('release-channel-or-tag-mismatch')
        return value

    async def body(self, url, limit, expected):
        status, _, raw = await self.fetch(url, limit, expected=expected)
        if status != 200 or len(raw) != expected:
            raise ReleaseError('release-metadata-incomplete')
        return raw

    async def verify(self, raw, signature, key):
        if len(raw) > self.metadata_bytes or len(signature) != 64:
            raise ReleaseError('invalid-release-signature-envelope')
        with tempfile.TemporaryDirectory(prefix='verify-', dir=self.programs / 'staging') as temporary:
            root = Path(temporary)
            for name, data in [('public.der', bytes.fromhex('302a300506032b6570032100') + key),
                               ('manifest', raw), ('signature', signature)]:
                fd = os.open(root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(data)
            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    'openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER',
                    '-inkey', str(root / 'public.der'), '-sigfile', str(root / 'signature'), '-in', str(root / 'manifest'),
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
                if await asyncio.wait_for(process.wait(), self.remaining()) != 0:
                    raise ReleaseError('invalid-release-signature')
            finally:
                if process is not None:
                    if process.returncode is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    await process.wait()

    @staticmethod
    def check_platform(manifest):
        try:
            libc = os.confstr('CS_GNU_LIBC_VERSION').split()
            version = tuple(map(int, libc[1].split('.')))
        except (ValueError, AttributeError, IndexError):
            raise ReleaseError('unsupported-native-host-libc')
        requirements = manifest.get('platform_requirements')
        if (platform.system() != 'Linux' or platform.machine() != 'x86_64' or libc[0] != 'glibc' or version < (2, 36)
                or requirements is not None and (not isinstance(requirements, dict)
                    or requirements.get('architecture') != 'x86_64' or requirements.get('libc') != 'glibc'
                    or requirements.get('minimum_glibc') != '2.36')):
            raise ReleaseError('unsupported-native-host-platform')

    async def stage(self, raw, signature, *, key=None, tag=None, now=None):
        key = self.prepare() if key is None else key
        if not self.deadline:
            self.deadline = time.monotonic() + self.wall_seconds
        await self.verify(raw, signature, key)
        manifest = json_value(raw)
        now = int(time.time()) if now is None else now
        if (not isinstance(manifest, dict) or type(manifest.get('protocol')) is not int or manifest['protocol'] != 1
                or manifest.get('repository') != REPOSITORY or manifest.get('channel') != self.channel
                or manifest.get('platform') != PLATFORM or type(manifest.get('sequence')) is not int
                or not 1 <= manifest['sequence'] <= 2**63 - 1 or type(manifest.get('expires_at')) is not int
                or not now < manifest['expires_at'] <= 2**63 - 1
                or not isinstance(manifest.get('version'), str) or not re.fullmatch(SEMVER, manifest['version'])
                or manifest.get('tag') != 'compact-v' + manifest['version']
                or tag is not None and manifest['tag'] != tag):
            raise ReleaseError('expired-or-incompatible-release-manifest')
        self.check_platform(manifest)
        files, total = inventory(manifest)
        required = total + len(raw) + len(signature)
        if required > self.staging_bytes:
            raise ReleaseError('release-exceeds-code-staging-allocation')
        digest = hashlib.sha256(raw).hexdigest()
        program_id = 'pkg-' + digest
        floor_path = self.programs / ('highest-' + self.channel + '.json')
        floor = json_value(read_private(floor_path, self.metadata_bytes)) if floor_path.exists() else {'sequence': 0, 'manifest_sha256': None}
        if (not isinstance(floor, dict) or type(floor.get('sequence')) is not int or floor['sequence'] < 0
                or not 0 <= floor['sequence'] <= 2**63 - 1
                or floor['sequence'] > 0 and (not isinstance(floor.get('manifest_sha256'), str)
                    or not re.fullmatch('[0-9a-f]{64}', floor['manifest_sha256']))
                or floor['sequence'] > manifest['sequence']
                or floor['sequence'] == manifest['sequence'] and floor.get('manifest_sha256') != digest):
            raise ReleaseError('release-replay-or-sequence-replacement')
        # Accepted signed identities advance the replay floor even if download is interrupted.
        atomic_json(floor_path, {'sequence': manifest['sequence'], 'manifest_sha256': digest, 'accepted_at': now})
        destination = self.programs / 'releases' / program_id
        if destination.exists() or destination.is_symlink():
            resolve_program(self.programs, program_id)
            if (read_private(destination / 'manifest.exact', self.metadata_bytes) != raw
                    or read_private(destination / 'manifest.sig', 64) != signature):
                raise ReleaseError('installed-release-identity-changed')
            return Candidate(program_id, destination, manifest)
        if shutil.disk_usage(self.programs).free < self.disk_reserve_bytes + required:
            raise ReleaseError('insufficient-code-staging-disk')
        stage = Path(tempfile.mkdtemp(prefix='release-', dir=self.programs / 'staging'))
        try:
            for item in files:
                self.remaining()
                path = stage / item['path']
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    status, _, _ = await self.fetch(item['url'], item['size'], expected=item['size'], sink=output)
                    if status != 200:
                        raise ReleaseError('native-file-download-failed')
                    output.flush()
                    os.fsync(output.fileno())
                digest_file = hashlib.sha256()
                with path.open('rb') as source:
                    while chunk := source.read(65536):
                        digest_file.update(chunk)
                if path.stat().st_size != item['size'] or digest_file.hexdigest() != item['sha256']:
                    raise ReleaseError('native-file-content-mismatch')
                path.chmod(int(item['mode'], 8))
            for name, value in [('manifest.exact', raw), ('manifest.sig', signature)]:
                fd = os.open(stage / name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o400)
                with os.fdopen(fd, 'wb') as output:
                    output.write(value)
                    output.flush()
                    os.fsync(output.fileno())
            directories = [p for p in stage.rglob('*') if p.is_dir()] + [stage]
            for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
                sync_directory(directory)
                if directory != stage:
                    directory.chmod(0o500)
            # Moving across parents updates '..', which requires write permission
            # on the moved directory for an unprivileged account. Freeze its root
            # immediately after rename, before any tuple can activate it.
            os.rename(stage, destination)
            destination.chmod(0o500)
            sync_directory(destination)
            sync_directory(destination.parent)
            resolve_program(self.programs, program_id)
            return Candidate(program_id, destination, manifest)
        finally:
            if stage.exists():
                for directory, _, _ in os.walk(stage):
                    Path(directory).chmod(0o700)
                shutil.rmtree(stage)

    def retry_after(self, status, headers):
        if self.schedule is None or status not in (403, 429, 503):
            return
        now = int(time.time())
        until = now
        retry = headers.get('retry-after', '')
        if retry.isdecimal():
            until = max(until, now + min(int(retry), 2**63 - 1 - now))
        elif retry:
            try:
                until = max(until, int(email.utils.parsedate_to_datetime(retry).timestamp()))
            except (ValueError, TypeError, OverflowError):
                pass
        reset = headers.get('x-ratelimit-reset', '')
        if reset.isdecimal():
            until = max(until, min(int(reset), 2**63 - 1))
        schedule = json_value(read_private(self.schedule, self.metadata_bytes))
        schedule['next_at'] = max(schedule['next_at'], until)
        atomic_json(self.schedule, schedule)

    async def fetch(self, url, limit, *, expected=None, sink=None):
        if self.fetch_override is not None:
            status, headers, raw = await self.fetch_override(url, limit, expected=expected, sink=sink)
            if len(raw) > limit:
                raise ReleaseError('release-response-exceeds-envelope')
            self.retry_after(status, headers)
            return status, headers, raw
        for redirect in range(4):
            parts = urlsplit(url)
            if (parts.scheme != 'https' or parts.hostname not in HOSTS or parts.port not in (None, 443)
                    or parts.username is not None or parts.password is not None or parts.fragment
                    or re.search(r'[\x00-\x20\x7f]', url)):
                raise ReleaseError('release-url-outside-approved-https-origins')
            writer = None
            try:
                if self.ssl_context is None:
                    self.ssl_context = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(asyncio.open_connection(
                    parts.hostname, 443, ssl=self.ssl_context, server_hostname=parts.hostname,
                    ssl_handshake_timeout=self.remaining(), limit=65536), self.remaining())
                target = (parts.path or '/') + ('?' + parts.query if parts.query else '')
                writer.write(('GET ' + target + ' HTTP/1.1\r\nHost: ' + parts.hostname
                              + '\r\nUser-Agent: Compact-ClamAV/0.1\r\nAccept: application/vnd.github+json\r\n'
                                'Accept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii'))
                await asyncio.wait_for(writer.drain(), self.remaining())
                header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), self.remaining())
                if len(header) > 65536:
                    raise ReleaseError('oversized-release-http-header')
                lines = header[:-4].split(b'\r\n')
                match = re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?', lines[0])
                if match is None:
                    raise ReleaseError('invalid-release-http-status')
                status = int(match[1])
                headers = {}
                for line in lines[1:]:
                    key, separator, value = line.partition(b':')
                    if not separator or not re.fullmatch(rb'[!#$%&\'*+.^_`|~0-9A-Za-z-]+', key):
                        raise ReleaseError('invalid-release-http-header')
                    key = key.decode('ascii').lower()
                    value = value.strip().decode('latin1')
                    if key in headers and key not in ('set-cookie',):
                        raise ReleaseError('ambiguous-release-http-header')
                    headers[key] = value
                self.retry_after(status, headers)
                if status in (301, 302, 303, 307, 308):
                    if redirect == 3 or not headers.get('location'):
                        raise ReleaseError('release-http-redirect-limit')
                    url = headers['location']
                    continue
                if status != 200:
                    return status, headers, b''
                if headers.get('content-encoding', 'identity') != 'identity':
                    raise ReleaseError('encoded-release-response-rejected')
                length = headers.get('content-length')
                transfer = headers.get('transfer-encoding')
                if length is not None and (not length.isdecimal() or int(length) > limit
                        or transfer is not None or expected is not None and int(length) != expected):
                    raise ReleaseError('invalid-release-http-length')
                if transfer not in (None, 'chunked'):
                    raise ReleaseError('invalid-release-http-transfer-encoding')
                count = 0
                body = bytearray()
                async def consume(count_bytes, exact):
                    nonlocal count
                    while count_bytes:
                        size = min(count_bytes, 65536)
                        chunk = await asyncio.wait_for(reader.readexactly(size) if exact else reader.read(size), self.remaining())
                        if not chunk:
                            break
                        count_bytes -= len(chunk)
                        count += len(chunk)
                        if count > limit:
                            raise ReleaseError('release-response-exceeds-envelope')
                        if sink is not None:
                            if shutil.disk_usage(self.programs).free < self.disk_reserve_bytes + len(chunk):
                                raise ReleaseError('code-staging-disk-reserve-exhausted')
                            sink.write(chunk)
                        else:
                            body.extend(chunk)
                if transfer == 'chunked':
                    while True:
                        line = await asyncio.wait_for(reader.readuntil(b'\r\n'), self.remaining())
                        if len(line) > 4096 or not re.fullmatch(rb'[0-9a-fA-F]+(?:;[^\r\n]*)?\r\n', line):
                            raise ReleaseError('invalid-release-http-chunk')
                        size = int(line[:-2].split(b';', 1)[0], 16)
                        if size > limit - count:
                            raise ReleaseError('release-response-exceeds-envelope')
                        if size == 0:
                            trailers = 0
                            while True:
                                line = await asyncio.wait_for(reader.readuntil(b'\r\n'), self.remaining())
                                trailers += len(line)
                                if trailers > 65536:
                                    raise ReleaseError('oversized-release-http-trailer')
                                if line == b'\r\n':
                                    break
                            break
                        await consume(size, True)
                        if await asyncio.wait_for(reader.readexactly(2), self.remaining()) != b'\r\n':
                            raise ReleaseError('invalid-release-http-chunk')
                elif length is not None:
                    await consume(int(length), True)
                else:
                    await consume(limit + 1, False)
                if expected is not None and count != expected:
                    raise ReleaseError('release-response-size-changed')
                return status, headers, bytes(body)
            finally:
                if writer is not None:
                    writer.close()
                    # Closing SSL must not extend the request's monotonic lease.
                    writer.transport.abort()
        raise ReleaseError('release-http-redirect-limit')
