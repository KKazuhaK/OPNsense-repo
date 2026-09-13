#!/usr/local/bin/python3
"""Bounded file snapshots carried by the native OPNsense configuration XML.

Each package installs its own copy; there is no shared package dependency.
Credentials travel on stdin and failures never expose configuration contents.
"""
import base64
from contextlib import contextmanager
import fcntl
import fnmatch
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import stat
import subprocess
import sys
import syslog
import tempfile
import time

MAX_FILE = 16 * 1024 * 1024
MAX_DOCUMENT = 32 * 1024 * 1024
# Keep old snapshots readable while limiting the cost of newly-created native
# configuration histories to 1 MiB compressed per plugin.
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_NEW_ARCHIVE = 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 64
MAX_PATH = 1023
WATCH_POLL = 1
WATCH_SETTLE = 2
WATCH_INTERVAL = 30


class BackupError(Exception):
    """A failure whose message is safe to show without revealing saved data."""


def revision_token(fields):
    """Match the PHP transport's canonical hash of the actual imported fields."""
    return hashlib.sha256(json.dumps(fields, ensure_ascii=True, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def rc_value(content, variable, default):
    """Read literal shell assignments, preserving escaped dollar signs.

    Shell expansion cannot be evaluated safely by a backup process. Quoted or
    escaped literal characters remain valid filesystem names.
    """
    value = default
    try:
        lines = content.decode('utf-8').splitlines()
        for line in lines:
            match = re.match(r'^\s*(?:export\s+)?' + re.escape(variable) + '=', line)
            if not match:
                continue
            text, result, quote, index = line[match.end():], [], '', 0
            while index < len(text):
                char = text[index]
                if quote == "'":
                    if char == "'":
                        quote = ''
                    else:
                        result.append(char)
                elif char == '\\':
                    index += 1
                    if index == len(text):
                        raise ValueError()
                    following = text[index]
                    if quote == '"' and following not in '$`"\\':
                        result.append('\\')
                    result.append(following)
                elif char == quote and quote:
                    quote = ''
                elif not quote and char in "'\"":
                    quote = char
                elif char in '$`' or (not quote and char in ';|&<>()'):
                    raise ValueError()
                elif not quote and char.isspace():
                    trailing = text[index:].strip()
                    if trailing and not trailing.startswith('#'):
                        raise ValueError()
                    break
                else:
                    result.append(char)
                index += 1
            if quote:
                raise ValueError()
            value = ''.join(result)
        return value
    except (ValueError, UnicodeError):
        raise BackupError('The service configuration has an unsupported path assignment.') from None


class ConfigBackup:
    def __init__(self, profile, script_dir=None, transport=None):
        self.profile = profile
        self.module = profile['module']
        if not re.fullmatch(r'[A-Z][A-Za-z0-9]{0,63}', self.module):
            raise ValueError('Invalid module name.')
        self.root = Path(os.environ.get(profile.get('root_env', ''), '/')).absolute()
        self.script_dir = Path(script_dir or profile.get('script_dir') or Path(sys.argv[0]).parent)
        self.transport = transport or self._transport
        self.state = self.path(profile.get('state_dir', '/var/db/os-' + self.module.lower() + '-backup'))
        persistent = self.path(profile.get('marker_dir', '/conf/os-config-backup/' + self.module))
        self.marker = persistent / 'applied.sha256'
        self.watch_saved = persistent / 'last-mirror-at'
        self.excludes = profile.get('excludes', []) + ['.config-backup-*']

    def path(self, value):
        return self.root / str(value).lstrip('/')

    def _transport(self, action, payload=None):
        result = subprocess.run(
            ['/usr/local/bin/php', str(self.script_dir / 'config_backup.php'), self.module, action],
            input=json.dumps(payload).encode() if payload is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
        if result.returncode or len(result.stdout) > MAX_ARCHIVE * 2:
            raise BackupError('The native configuration backup operation failed.')
        try:
            answer = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise BackupError('The native configuration backup response is invalid.') from None
        if not isinstance(answer, dict):
            raise BackupError('The native configuration backup response is invalid.')
        return answer

    @contextmanager
    def _lock(self):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        locks = [self.state / 'operation.lock']
        if self.profile.get('data_lock'):
            locks.append(self.path(self.profile['data_lock']))
        handles = []
        try:
            for path in locks:
                path.parent.mkdir(parents=True, exist_ok=True)
                handle = open(path, 'a+b')
                handles.append(handle)
                deadline = time.monotonic() + 10
                while True:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise BackupError('The configuration is busy; its backup could not be updated.')
                        time.sleep(0.05)
            yield
        finally:
            for handle in reversed(handles):
                handle.close()

    def _excluded(self, path):
        return any(fnmatch.fnmatch(part, pattern) for part in PurePosixPath(path).parts
                   for pattern in self.excludes)

    @staticmethod
    def _safe_path(path, kind, dynamic=False):
        if (not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or path == '/' or
                str(PurePosixPath(path)) != path or '..' in path.split('/') or
                any(ord(char) < 32 for char in path)):
            raise BackupError('The backup contains an unsupported configuration path.')
        if len(PurePosixPath(path).parts) > MAX_DEPTH:
            raise BackupError('A configuration path exceeds the backup depth limit.')
        if len(path.encode('utf-8')) > MAX_PATH:
            raise BackupError('A configuration path exceeds the backup length limit.')
        if dynamic:
            broad = {'/etc', '/usr', '/usr/local', '/usr/local/etc', '/var', '/var/db',
                     '/var/run', '/var/log', '/root', '/home', '/tmp'}
            forbidden = ['/conf', '/dev', '/proc', '/boot', '/bin', '/sbin', '/usr/bin',
                         '/usr/sbin', '/usr/lib', '/usr/local/bin', '/usr/local/sbin',
                         '/usr/local/lib', '/usr/local/opnsense', '/etc/ssh',
                         '/usr/local/etc/pkg', '/root/.ssh', '/etc/rc.conf.d',
                         '/etc/rc.d', '/etc/cron.d', '/usr/local/etc/rc.d',
                         '/usr/local/etc/cron.d', '/var/cron', '/var/etc',
                         '/usr/local/www', '/usr/local/etc/inc', '/usr/local/etc/rc.syshook.d']
            critical = {'/etc/passwd', '/etc/master.passwd', '/etc/group', '/etc/rc',
                        '/etc/rc.conf', '/etc/rc.conf.local', '/etc/fstab', '/etc/crontab'}
            if path in broad or path in critical or any(path == p or path.startswith(p + '/') for p in forbidden):
                raise BackupError('The backup references a protected system path.')
        if kind not in ('file', 'tree'):
            raise BackupError('The backup contains an unsupported configuration path.')

    def _roots(self, files):
        roots = {(path, 'tree') for path in self.profile.get('trees', [])}
        roots.update((path, 'file') for path in self.profile.get('files', []))
        for path, kind in roots:
            self._safe_path(path, kind)
        for spec in self.profile.get('rc_paths', []):
            value = rc_value(files.get(spec['file'], b''), spec['variable'], spec['default'])
            self._safe_path(value, spec['kind'], True)
            roots.add((value, spec['kind']))
        if self.profile.get('references'):
            try:
                for spec in self.profile['references'](files):
                    self._safe_path(spec['path'], spec['kind'], True)
                    roots.add((spec['path'], spec['kind']))
            except BackupError:
                raise
            except Exception:
                raise BackupError('A referenced configuration file could not be backed up.') from None
        # Owned trees already include their children; avoid duplicate roots.
        if len(roots) > MAX_ENTRIES:
            raise BackupError('The configuration has too many paths to back up.')
        return sorted((path, kind) for path, kind in roots if not any(
            other_kind == 'tree' and path.startswith(other + '/')
            for other, other_kind in roots if other != path))

    @staticmethod
    def _allowed(path, roots):
        return any(path == root or (kind == 'tree' and path.startswith(root + '/'))
                   for root, kind in roots)

    def _parents_safe(self, path):
        local = self.path(path)
        for parent in [local.parent, *local.parent.parents]:
            if parent == self.root.parent:
                break
            if parent.is_symlink():
                raise BackupError('A configuration path traverses a symbolic link.')

    def _validate_links(self, entries, roots):
        """Resolve archived links before applying subsequent dot components.

        Normalising a target first is unsafe: b -> '.' turns b/../secret into
        a path outside the directory even though its lexical path stays inside.
        Resolution uses only archived entries, never the destination filesystem.
        """
        for path, item in entries.items():
            if item['kind'] != 'link':
                continue
            target = item['target']
            if (not target or target.startswith('/') or '\x00' in target or
                    len(target.encode('utf-8')) > MAX_PATH):
                raise BackupError('A configuration symbolic link leaves its owned directory.')
            resolved = list(PurePosixPath(path).parent.parts[1:])
            pending, hops = target.split('/'), 0
            while pending:
                component = pending.pop(0)
                if component in ('', '.'):
                    continue
                if component == '..':
                    if resolved:
                        resolved.pop()
                    continue
                candidate = '/' + '/'.join(resolved + [component])
                # Unknown external components could themselves be live links.
                if not self._allowed(candidate, roots) and not any(
                        root.startswith(candidate + '/') for root, kind in roots):
                    raise BackupError('A configuration symbolic link leaves its owned directory.')
                referenced = entries.get(candidate)
                if referenced and referenced['kind'] == 'link':
                    hops += 1
                    if hops > 64:
                        raise BackupError('A configuration symbolic link cannot be resolved safely.')
                    pending = referenced['target'].split('/') + pending
                else:
                    if referenced and referenced['kind'] == 'file' and any(
                            part not in ('', '.') for part in pending):
                        raise BackupError('A configuration symbolic link cannot be resolved safely.')
                    resolved.append(component)
            if not self._allowed('/' + '/'.join(resolved), roots):
                raise BackupError('A configuration symbolic link leaves its owned directory.')

    def _collect(self, roots, validate_roots=True, validate_links=True):
        entries = {}
        total = 0
        visited = 0
        def collect(path):
            nonlocal total, visited
            visited += 1
            if visited > MAX_ENTRIES:
                raise BackupError('The configuration has too many files to back up.')
            self._safe_path(path, 'file')
            if self._excluded(path):
                return
            self._parents_safe(path)
            local = self.path(path)
            try:
                info = local.lstat()
            except FileNotFoundError:
                return
            item = {'path': path, 'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISDIR(info.st_mode):
                item['kind'] = 'dir'
                entries[path] = item
                for child in self._children(local, visited):
                    collect(path + '/' + child.name)
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_FILE:
                    raise BackupError('A configuration file exceeds the backup size limit.')
                fd = os.open(local, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as handle:
                    opened = os.fstat(handle.fileno())
                    if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino:
                        raise BackupError('The configuration changed while its backup was being read.')
                    data = handle.read(MAX_FILE + 1)
                    after = os.fstat(handle.fileno())
                if (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise BackupError('The configuration changed while its backup was being read.')
                total += len(data)
                if len(data) > MAX_FILE or total > MAX_DOCUMENT:
                    raise BackupError('The configuration exceeds the backup size limit.')
                item.update(kind='file', data=base64.b64encode(data).decode('ascii'))
                entries[path] = item
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(local)
                item.update(kind='link', target=target)
                entries[path] = item
            else:
                raise BackupError('The configuration contains an unsupported file type.')
            if len(entries) > MAX_ENTRIES:
                raise BackupError('The configuration has too many files to back up.')
        for path, kind in roots:
            collect(path)
            if validate_roots and path in entries and kind == 'file' and entries[path]['kind'] != 'file':
                raise BackupError('A configured file is not a regular file.')
            if validate_roots and path in entries and kind == 'tree' and entries[path]['kind'] != 'dir':
                raise BackupError('A configured directory is not a directory.')
        if validate_links:
            self._validate_links(entries, roots)
        return entries

    def _snapshot(self):
        fixed = self._roots({}) if not self.profile.get('references') else sorted(
            [(p, 'tree') for p in self.profile.get('trees', [])] +
            [(p, 'file') for p in self.profile.get('files', [])])
        entries = self._collect(fixed)
        for _ in range(4):
            files = {p: base64.b64decode(e['data']) for p, e in entries.items() if e['kind'] == 'file'}
            roots = self._roots(files)
            collected = self._collect(roots)
            if collected == entries:
                break
            entries = collected
        else:
            raise BackupError('The configuration changed while its backup was being read.')
        document = {'version': 1, 'roots': [{'path': p, 'kind': k, 'present': p in entries}
                    for p, k in roots], 'entries': [entries[p] for p in sorted(entries)]}
        raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
        if len(raw) > MAX_DOCUMENT:
            raise BackupError('The configuration exceeds the backup size limit.')
        archive = gzip.compress(raw, mtime=0)
        if len(archive) > MAX_NEW_ARCHIVE:
            raise BackupError('The configuration exceeds the backup size limit.')
        return {'schema': '1', 'archive': base64.b64encode(archive).decode(),
                'checksum': hashlib.sha256(archive).hexdigest()}

    def _decode(self, stored):
        try:
            if stored.get('schema') != '1' or not re.fullmatch(r'[a-f0-9]{64}', stored.get('checksum', '')):
                raise ValueError()
            encoded = stored['archive']
            if not isinstance(encoded, str) or len(encoded) > (MAX_ARCHIVE * 4 // 3 + 4):
                raise ValueError()
            archive = base64.b64decode(encoded, validate=True)
            if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != stored['checksum']:
                raise ValueError()
            with gzip.GzipFile(fileobj=io.BytesIO(archive)) as handle:
                raw = handle.read(MAX_DOCUMENT + 1)
            if len(raw) > MAX_DOCUMENT:
                raise ValueError()
            doc = json.loads(raw)
            if (doc['version'] != 1 or not isinstance(doc['entries'], list) or len(doc['entries']) > MAX_ENTRIES or
                    not isinstance(doc['roots'], list) or len(doc['roots']) > MAX_ENTRIES):
                raise ValueError()
            entries = {}
            files = {}
            for item in doc['entries']:
                path = item['path']
                self._safe_path(path, 'file')
                if path in entries or type(item['mode']) is not int or not 0 <= item['mode'] <= 0o777:
                    raise ValueError()
                if item['kind'] == 'file':
                    data = base64.b64decode(item['data'], validate=True)
                    if len(data) > MAX_FILE:
                        raise ValueError()
                    files[path] = data
                elif item['kind'] == 'link':
                    if not isinstance(item['target'], str) or item['target'].startswith('/') or '\x00' in item['target']:
                        raise ValueError()
                elif item['kind'] != 'dir':
                    raise ValueError()
                entries[path] = item
            permitted_roots = self._roots(files)
            roots = [(r['path'], r['kind']) for r in doc['roots']]
            # New package versions can add fixed roots. An older snapshot owns
            # only the roots it actually saved; absent new roots are preserved.
            if roots != sorted(set(roots)) or any(root not in permitted_roots for root in roots):
                raise ValueError()
            for root in doc['roots']:
                if type(root['present']) is not bool or root['present'] != (root['path'] in entries):
                    raise ValueError()
                if root['present'] and entries[root['path']]['kind'] != ('dir' if root['kind'] == 'tree' else 'file'):
                    raise ValueError()
            for path, item in entries.items():
                if not self._allowed(path, roots):
                    raise ValueError()
                for parent in PurePosixPath(path).parents:
                    if self._allowed(str(parent), roots) and (
                            str(parent) not in entries or entries[str(parent)]['kind'] != 'dir'):
                        raise ValueError()
            self._validate_links(entries, roots)
            # New exclusions leave software/cache names from an old archive
            # alone. Validate the entire old snapshot first so this filtering
            # cannot hide malformed hierarchy or malicious reference roots.
            entries = {p: e for p, e in entries.items() if not self._excluded(p)}
            files = {p: data for p, data in files.items() if p in entries}
            roots = [(p, kind) for p, kind in roots if not self._excluded(p)]
            return roots, entries, files
        except BackupError:
            raise
        except Exception:
            raise BackupError('The stored configuration backup is invalid or incomplete.') from None

    def _set_marker(self, checksum):
        self.marker.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.config-backup-', dir=self.marker.parent)
        try:
            with os.fdopen(fd, 'w') as handle:
                handle.write(checksum + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.marker)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _marker(self):
        try:
            return self.marker.read_text().strip()
        except FileNotFoundError:
            # Migrate an already-applied old installation without restoring stale
            # files. Future /var resets must not forget the applied XML revision.
            try:
                legacy = (self.state / 'applied.sha256').read_text().strip()
            except FileNotFoundError:
                return ''
            self._set_marker(legacy)
            return legacy

    @staticmethod
    def _children(local, visited):
        """Bound enumeration before sorting, including excluded runtime names."""
        children = []
        for child in local.iterdir():
            if len(children) + visited >= MAX_ENTRIES:
                raise BackupError('The configuration has too many files to back up.')
            children.append(child)
        return sorted(children)

    def _watch_saved_at(self):
        try:
            saved = float(self.watch_saved.read_text().strip())
            now = time.time()
            # A clock adjustment must not prevent automatic saves indefinitely.
            if not 0 <= saved <= now + WATCH_INTERVAL:
                return 0
            return min(max(saved, 0), now)
        except (FileNotFoundError, ValueError):
            return 0

    def _set_watch_saved_at(self):
        self.watch_saved.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.config-backup-', dir=self.watch_saved.parent)
        try:
            with os.fdopen(fd, 'w') as handle:
                handle.write(str(time.time()) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.watch_saved)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _check_restore_current(self, stored):
        if revision_token(self.transport('import')) != revision_token(stored):
            raise BackupError('The system configuration changed during restore; retry this plugin restore.')

    @staticmethod
    def _has_snapshot(stored):
        # Native model migration can materialize optional fields as empty XML
        # elements before a legacy installation has ever saved a snapshot.
        return any(stored.get(field, '') != '' for field in ('schema', 'archive', 'checksum'))

    def _watch_warning(self, message):
        syslog.syslog(syslog.LOG_WARNING, self.module + ' configuration backup: ' + message)

    def _apply(self, stored):
        roots, entries, files = self._decode(stored)
        return self._apply_entries(stored, roots, entries, files)

    def _restore_missing(self, stored):
        roots, entries, files = self._decode(stored)
        missing = [(p, kind) for p, kind in roots if p in entries and
                   not self.path(p).exists() and not self.path(p).is_symlink()]
        if not missing:
            return False
        entries = {p: item for p, item in entries.items() if self._allowed(p, missing)}
        files = {p: data for p, data in files.items() if p in entries}
        # Restoring a missing root must not revive a link that relies on a live
        # path outside this subset; an explicit full restore remains available.
        self._validate_links(entries, missing)
        return self._apply_entries(stored, missing, entries, files)

    def _apply_entries(self, stored, roots, entries, files):
        # Existing types and links may differ from the snapshot; collect them
        # without following links so a restore can safely replace those names.
        current = self._collect(roots, validate_roots=False, validate_links=False)
        if current == entries:
            self._check_restore_current(stored)
            self._set_marker(stored['checksum'])
            return False
        # Validate every destination before staging any changes.
        for path in set(entries) | set(current):
            self._parents_safe(path)
        created_dirs, staged, backups, modes, installed = [], {}, {}, {}, []
        committed = False
        def remove_private(local):
            if not local.name.startswith('.config-backup-'):
                raise BackupError('A configuration recovery path is invalid.')
            try:
                info = local.lstat()
            except FileNotFoundError:
                return
            if stat.S_ISDIR(info.st_mode):
                # shutil's descriptor-based implementation never follows links.
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise BackupError('A configuration recovery directory cannot be removed safely.')
                shutil.rmtree(local)
            else:
                local.unlink()
        try:
            directories = {p for p, e in entries.items() if e['kind'] == 'dir'}
            for path in entries:
                directories.update(str(p) for p in PurePosixPath(path).parents if str(p) != '/')
            # Stage every byte before moving an original. A nearest existing
            # directory also works when a desired parent is currently a file,
            # and keeps atomic renames on the destination filesystem.
            for path, item in entries.items():
                if item['kind'] == 'dir':
                    continue
                parent = self.path(path).parent
                while not parent.is_dir() or parent.is_symlink():
                    if parent == self.root:
                        raise BackupError('A configuration staging directory is unavailable.')
                    parent = parent.parent
                self._parents_safe('/' + str(parent.relative_to(self.root)) + '/.config-backup-stage')
                fd, temporary = tempfile.mkstemp(prefix='.config-backup-', dir=parent)
                staged[path] = Path(temporary)
                if item['kind'] == 'file':
                    with os.fdopen(fd, 'wb') as handle:
                        handle.write(files[path])
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(temporary, item['mode'])
                else:
                    os.close(fd)
                    os.unlink(temporary)
                    os.symlink(item['target'], temporary)
            conflicts = {p for p, e in current.items() if e['kind'] == 'dir' and
                         p in entries and entries[p]['kind'] != 'dir'}
            conflicts = {p for p in conflicts if not any(
                p.startswith(other + '/') for other in conflicts if p != other)}
            affected = {p for p, e in current.items() if e['kind'] != 'dir'} | set(staged) | conflicts
            affected = {p for p in affected if not any(p.startswith(other + '/') for other in conflicts)}
            for path in sorted(affected, key=lambda p: (p.count('/'), p)):
                local = self.path(path)
                if local.exists() or local.is_symlink():
                    self._parents_safe(path)
                    fd, temporary = tempfile.mkstemp(prefix='.config-backup-', dir=local.parent)
                    os.close(fd)
                    os.unlink(temporary)
                    os.replace(local, temporary)
                    backups[path] = Path(temporary)
                else:
                    backups[path] = None
            for path in sorted(directories, key=lambda p: (p.count('/'), p)):
                local = self.path(path)
                self._parents_safe(path)
                if local.is_symlink() or (local.exists() and not local.is_dir()):
                    raise BackupError('A restored directory conflicts with an existing file.')
                if not local.exists():
                    local.mkdir(mode=0o700)
                    created_dirs.append(local)
            for path, temporary in staged.items():
                self._parents_safe(path)
                os.replace(temporary, self.path(path))
                installed.append(path)
            for path, item in entries.items():
                if item['kind'] == 'dir':
                    local = self.path(path)
                    modes[local] = stat.S_IMODE(local.stat().st_mode)
                    os.chmod(local, item['mode'])
            # A second system restore during staging/application must leave its
            # XML pending and recover every original rather than commit stale
            # files and discard the rollback journal.
            self._check_restore_current(stored)
            self._set_marker(stored['checksum'])
            committed = True
        except Exception:
            # Continue recovering other originals when one rollback operation
            # fails. Its private sibling backup remains available for recovery.
            for path in reversed(installed):
                local = self.path(path)
                try:
                    self._parents_safe(path)
                    local.unlink()
                except (OSError, BackupError):
                    pass
            for local, mode in modes.items():
                try:
                    os.chmod(local, mode)
                except OSError:
                    pass
            for local in reversed(created_dirs):
                try:
                    local.rmdir()
                except OSError:
                    pass
            for path, original in reversed(list(backups.items())):
                if original is not None and (original.exists() or original.is_symlink()):
                    try:
                        self._parents_safe(path)
                        os.replace(original, self.path(path))
                    except (OSError, BackupError):
                        pass
            raise
        finally:
            # Failed rollback backups remain on disk for recovery, never discarded.
            cleanup = list(staged.values()) + ([p for p in backups.values() if p is not None] if committed else [])
            for local in cleanup:
                remove_private(local)
        # Remove obsolete empty directories without touching excluded runtime files.
        for path, item in sorted(current.items(), key=lambda pair: pair[0].count('/'), reverse=True):
            if item['kind'] == 'dir' and path not in entries:
                try:
                    self.path(path).rmdir()
                except OSError:
                    pass
        return True

    def _operate(self, action):
        snapshot = False
        try:
            with self._lock():
                stored = self.transport('import')
                snapshot = self._has_snapshot(stored)
                if action == 'mirror':
                    if snapshot and stored.get('checksum') != self._marker():
                        raise BackupError('A restored system configuration is pending; restart or restore this plugin before saving.')
                    payload = self._snapshot()
                    payload['_expected'] = revision_token(stored)
                    changed = bool(self.transport('export', payload).get('changed'))
                    confirmed = self.transport('import')
                    if confirmed != {k: v for k, v in payload.items() if k != '_expected'}:
                        raise BackupError('The system configuration changed before its backup update could be confirmed.')
                    self._set_marker(payload['checksum'])
                    self._set_watch_saved_at()
                    return {'ok': True, 'changed': changed, 'snapshot': True}
                if not snapshot:
                    return {'ok': True, 'changed': False, 'snapshot': False}
                if action == 'reconcile' and stored.get('checksum') == self._marker():
                    return {'ok': True, 'changed': self._restore_missing(stored), 'snapshot': True}
                return {'ok': True, 'changed': self._apply(stored), 'snapshot': True}
        except BackupError as error:
            return {'ok': False, 'changed': False, 'snapshot': snapshot, 'error': str(error)}
        except Exception:
            return {'ok': False, 'changed': False, 'snapshot': snapshot,
                    'error': 'The configuration backup operation failed; the saved backup was retained.'}

    def mirror(self):
        return self._operate('mirror')

    def restore(self):
        return self._operate('restore')

    def reconcile(self):
        return self._operate('reconcile')

    def _fingerprint(self):
        # No PHP bootstrap or full gzip read while an external application is idle.
        roots = sorted([(p, 'tree') for p in self.profile.get('trees', [])] +
                       [(p, 'file') for p in self.profile.get('files', [])])
        files = {}
        for spec in self.profile.get('rc_paths', []):
            try:
                with self.path(spec['file']).open('rb') as handle:
                    files[spec['file']] = handle.read(MAX_FILE + 1)
                if len(files[spec['file']]) > MAX_FILE:
                    raise BackupError('A configuration file exceeds the backup size limit.')
            except FileNotFoundError:
                pass
        try:
            roots = self._roots(files) if not self.profile.get('references') else roots
        except Exception:
            pass
        # Last mirror's paths also cover external certificate and rule files.
        roots += getattr(self, '_watch_roots', [])
        found = []
        visited = 0
        def visit(path):
            nonlocal visited
            visited += 1
            if visited > MAX_ENTRIES:
                raise BackupError('The configuration has too many files to back up.')
            self._safe_path(path, 'file')
            if self._excluded(path):
                return
            self._parents_safe(path)
            local = self.path(path)
            try:
                info = local.lstat()
            except FileNotFoundError:
                found.append((path, None))
                return
            found.append((path, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            if stat.S_ISDIR(info.st_mode):
                for child in self._children(local, visited):
                    visit(path + '/' + child.name)
        for path, kind in sorted(set(roots)):
            visit(path)
        return found

    def watch(self):
        stopping = False
        def stop(signum, frame):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        initial = self.reconcile()
        if not initial['ok']:
            return initial
        previous = None
        candidate = None
        dirty_since = settled_since = None
        last_attempt = -WATCH_INTERVAL
        last_warning = -WATCH_INTERVAL
        stored = self.transport('import')
        if self._has_snapshot(stored):
            self._watch_roots = self._decode(stored)[0]
        while not stopping:
            try:
                current = self._fingerprint()
                now = time.monotonic()
                if current != candidate:
                    candidate = current
                    settled_since = now
                    if dirty_since is None:
                        dirty_since = now
                if current == previous:
                    dirty_since = None
                due = time.time() - self._watch_saved_at() >= WATCH_INTERVAL
                settled = settled_since is not None and now - settled_since >= WATCH_SETTLE
                overdue = dirty_since is not None and now - dirty_since >= WATCH_INTERVAL
                if (dirty_since is not None and (settled or overdue) and due and
                        now - last_attempt >= WATCH_INTERVAL):
                    last_attempt = now
                    answer = self.mirror()
                    if answer['ok']:
                        self._watch_roots = self._decode(self.transport('import'))[0]
                        # Edits during the export remain visible on the next pass.
                        previous = current
                        dirty_since = None
                    else:
                        if now - last_warning >= WATCH_INTERVAL:
                            self._watch_warning(answer.get('error', 'The configuration backup operation failed.'))
                            last_warning = now
                time.sleep(WATCH_POLL)
            except Exception as error:
                now = time.monotonic()
                if now - last_warning >= WATCH_INTERVAL:
                    message = str(error) if isinstance(error, BackupError) else 'The configuration files could not be checked.'
                    self._watch_warning(message)
                    last_warning = now
                time.sleep(WATCH_POLL)
        return {'ok': True, 'changed': False, 'snapshot': True}

    def main(self, argv=None):
        argv = list(sys.argv[1:] if argv is None else argv)
        actions = {'mirror': self.mirror, 'import-config': self.restore,
                   'reconcile': self.reconcile, 'watch': self.watch}
        if len(argv) != 1 or argv[0] not in actions:
            result = {'ok': False, 'error': 'Usage: config_mirror.py mirror|import-config|reconcile|watch'}
        else:
            result = actions[argv[0]]()
        print(json.dumps(result))
        return 0 if result['ok'] else 1


def run(profile, argv=None):
    return ConfigBackup(profile).main(argv)
