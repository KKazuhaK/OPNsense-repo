#!/usr/local/bin/python3
"""Own one Mihomo daemon parent and child by exact kernel identities."""
import json
import os
from pathlib import Path
import re
import signal
import stat
import tempfile
import time

from process_identity import process as read_process


LIMIT = 64 * 1024
IDENTITY_FIELDS = ('pid', 'ppid', 'uid', 'birth', 'executable', 'argv')
CONTINUITY_FIELDS = ('pid', 'uid', 'birth', 'executable', 'argv')
DAEMON = '/usr/sbin/daemon'
CORE = '/usr/local/bin/mihomo'
PYTHON = '/usr/local/bin/python3'
STATE = '/var/db/os-mihomo'
HOME = STATE + '/home'
CONFIG = STATE + '/config.yaml'
SCRIPT = '/usr/local/opnsense/scripts/mihomo/mihomo.py'
CORE_PARENT_PID = '/var/run/mihomo.pid'
CORE_CHILD_PID = '/var/run/mihomo-child.pid'
CORE_JOURNAL = STATE + '/process-identity.json'
WATCH_PARENT_PID = '/var/run/mihomo-watch.pid'
WATCH_CHILD_PID = '/var/run/mihomo-watch-child.pid'
WATCH_JOURNAL = STATE + '/watch-process-identity.json'


class OwnershipError(RuntimeError):
    pass


def rooted(root, path):
    return Path(root) / str(path).lstrip('/')


def stable(identity):
    if not isinstance(identity, dict):
        return None
    try:
        return {field: identity[field] for field in IDENTITY_FIELDS}
    except KeyError:
        return None


def valid_identity(identity):
    return bool(
        isinstance(identity, dict) and set(identity) == set(IDENTITY_FIELDS)
        and type(identity.get('pid')) is int and 1 < identity['pid'] < 2147483648
        and type(identity.get('ppid')) is int and 0 <= identity['ppid'] < 2147483648
        and type(identity.get('uid')) is int and 0 <= identity['uid'] <= 4294967295
        and isinstance(identity.get('birth'), str)
        and re.fullmatch(r'[1-9][0-9]*:[0-9]{1,6}', identity['birth'])
        and isinstance(identity.get('executable'), str) and identity['executable'].startswith('/')
        and isinstance(identity.get('argv'), list) and identity['argv']
        and len(json.dumps(identity['argv'])) <= LIMIT
        and all(isinstance(value, str) and '\0' not in value for value in identity['argv']))


def secure_read(path, limit=LIMIT, private=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        unsafe_mode = before.st_mode & (0o077 if private else 0o022)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or unsafe_mode or before.st_size > limit):
            raise OwnershipError('The Mihomo process ownership file is not private.')
        content = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(content) > limit or any(getattr(before, field) != getattr(after, field) for field in fields):
        raise OwnershipError('The Mihomo process ownership file changed while it was read.')
    return content, tuple(getattr(before, field) for field in fields)


def atomic(path, content):
    path = Path(path)
    parent = path.parent
    if parent.is_symlink():
        raise OwnershipError('The Mihomo process ownership directory is unsafe.')
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OwnershipError('The Mihomo process ownership directory is not private.')
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def pid_snapshot(path):
    try:
        content, snapshot = secure_read(path, 64, private=False)
    except FileNotFoundError:
        return None, None
    try:
        text = content.decode('ascii').strip()
    except UnicodeError as error:
        raise OwnershipError('A Mihomo PID file is malformed.') from error
    if not re.fullmatch(r'[1-9][0-9]{0,9}', text) or int(text) >= 2147483648:
        raise OwnershipError('A Mihomo PID file is malformed.')
    return int(text), (snapshot, content)


def unlink_snapshot(path, captured):
    if captured is None:
        return
    try:
        current, snapshot = secure_read(path, max(LIMIT, len(captured[1])),
                                        private=Path(path).name.endswith('.json'))
    except FileNotFoundError:
        return
    if snapshot == captured[0] and current == captured[1]:
        Path(path).unlink()


class ProcessGroup:
    def __init__(self, tag, parent_pid, child_pid, journal, child_executable,
                 child_argv, process_reader=None, signaler=None, sleeper=None):
        self.tag = tag
        self.parent_pid = Path(parent_pid)
        self.child_pid = Path(child_pid)
        self.journal = Path(journal)
        self.child_executable = child_executable
        self.child_argv = list(child_argv)
        self.process_reader = process_reader or read_process
        self.signaler = signaler or os.kill
        self.sleeper = sleeper or time.sleep

    def identity(self, pid):
        try:
            return stable(self.process_reader(pid))
        except (OSError, RuntimeError, ValueError, TypeError) as error:
            raise OwnershipError('Mihomo process identity could not be established.') from error

    def parent_matches(self, identity):
        title = r'daemon: ' + re.escape(self.tag) + r'\[[1-9][0-9]*\](?: \(daemon\))?'
        return bool(valid_identity(identity) and identity['uid'] == os.geteuid()
                    and identity['executable'] == DAEMON and len(identity['argv']) == 1
                    and re.fullmatch(title, identity['argv'][0]))

    def child_matches(self, identity):
        return bool(valid_identity(identity) and identity['uid'] == os.geteuid()
                    and identity['executable'] == self.child_executable
                    and identity['argv'] == self.child_argv)

    def same(self, identity):
        current = self.identity(identity['pid']) if valid_identity(identity) else None
        # The daemon is launched without respawn. Its child remains ours if the
        # supervisor exits first and init reparents that same birth/executable/
        # NUL-argv identity; ppid proves adoption, not continuing ownership.
        return bool(current and all(current[field] == identity[field]
                                    for field in CONTINUITY_FIELDS))

    def load(self):
        try:
            content, snapshot = secure_read(self.journal)
        except FileNotFoundError:
            return None, None
        try:
            record = json.loads(content)
        except (UnicodeError, ValueError, TypeError) as error:
            raise OwnershipError('The Mihomo process ownership journal is invalid.') from error
        if (not isinstance(record, dict) or set(record) != {'version', 'tag', 'parent', 'child'}
                or record.get('version') != 1 or record.get('tag') != self.tag
                or not self.parent_matches(record.get('parent'))
                or not self.child_matches(record.get('child'))
                or record['child']['ppid'] != record['parent']['pid']):
            raise OwnershipError('The Mihomo process ownership journal is invalid.')
        return record, (snapshot, content)

    def persist(self, parent, child):
        parent, child = stable(parent), stable(child)
        if (not self.parent_matches(parent) or not self.child_matches(child)
                or child['ppid'] != parent['pid']):
            raise OwnershipError('The Mihomo daemon did not establish an exact parent and child identity.')
        record = {'version': 1, 'tag': self.tag, 'parent': parent, 'child': child}
        atomic(self.journal, (json.dumps(record, sort_keys=True) + '\n').encode())
        if not self.same(parent) or not self.same(child):
            raise OwnershipError('The Mihomo process identity changed while it was recorded.')
        return record

    def adopt(self):
        parent_pid, parent_snapshot = pid_snapshot(self.parent_pid)
        child_pid, child_snapshot = pid_snapshot(self.child_pid)
        if parent_pid is None and child_pid is None:
            return None
        parent = self.identity(parent_pid) if parent_pid is not None else None
        child = self.identity(child_pid) if child_pid is not None else None
        if parent is None and child is None:
            unlink_snapshot(self.parent_pid, parent_snapshot)
            unlink_snapshot(self.child_pid, child_snapshot)
            return None
        if (parent is None or child is None or not self.parent_matches(parent)
                or not self.child_matches(child) or child['ppid'] != parent['pid']):
            raise OwnershipError('Existing Mihomo PID files do not prove exact process ownership.')
        # Re-read both files and processes across journal publication.
        if pid_snapshot(self.parent_pid) != (parent_pid, parent_snapshot) or pid_snapshot(self.child_pid) != (child_pid, child_snapshot):
            raise OwnershipError('A Mihomo PID file changed during ownership adoption.')
        return self.persist(parent, child)

    def record_started(self, timeout=5):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                record = self.adopt()
                if record is not None:
                    return record
            except OwnershipError as error:
                last = error
            self.sleeper(0.05)
        raise OwnershipError('The new Mihomo daemon did not establish exact ownership.') from last

    def discover(self, adopt=True):
        record, journal_snapshot = self.load()
        if record is None:
            return self.adopt() if adopt else None
        if self.same(record['parent']) or self.same(record['child']):
            return record
        # Both recorded processes ended. Retire only unchanged plugin records;
        # a PID reused by another process never receives a signal.
        retired = []
        for label, path, expected in (('parent', self.parent_pid, record['parent']),
                                      ('child', self.child_pid, record['child'])):
            pid, snapshot = pid_snapshot(path)
            if pid is None:
                continue
            if pid != expected['pid']:
                raise OwnershipError('The Mihomo %s PID file was replaced and was preserved.' % label)
            # Equal digits are not proof that this is still our process. A live
            # reused PID makes the stale file foreign and therefore untouchable.
            if self.identity(pid) is not None:
                raise OwnershipError('The Mihomo %s PID was reused and its PID file was preserved.' % label)
            retired.append((path, snapshot))
        for path, snapshot in retired:
            unlink_snapshot(path, snapshot)
        unlink_snapshot(self.journal, journal_snapshot)
        return None

    def running(self, adopt=True):
        record = self.discover(adopt=adopt)
        return bool(record and self.same(record['child']))

    def send(self, identity, number):
        if not self.same(identity):
            return False
        try:
            self.signaler(identity['pid'], number)
        except ProcessLookupError:
            return False
        return True

    def stop(self):
        record = self.discover(adopt=True)
        if record is None:
            return
        for identity in (record['parent'], record['child']):
            self.send(identity, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while any(self.same(identity) for identity in (record['parent'], record['child'])) and time.monotonic() < deadline:
            self.sleeper(0.05)
        for identity in (record['parent'], record['child']):
            if self.same(identity):
                self.send(identity, signal.SIGKILL)
        deadline = time.monotonic() + 2
        while any(self.same(identity) for identity in (record['parent'], record['child'])) and time.monotonic() < deadline:
            self.sleeper(0.05)
        if any(self.same(identity) for identity in (record['parent'], record['child'])):
            raise OwnershipError('An exactly owned Mihomo process did not stop.')
        # discover() performs snapshot-checked journal and PID cleanup.
        self.discover(adopt=False)


def core_group(root='/', process_reader=None, signaler=None, sleeper=None, config=CONFIG):
    return ProcessGroup(
        'mihomo', rooted(root, CORE_PARENT_PID), rooted(root, CORE_CHILD_PID),
        rooted(root, CORE_JOURNAL), CORE,
        [CORE, '-d', str(rooted(root, HOME)), '-f', str(rooted(root, config))],
        process_reader=process_reader, signaler=signaler, sleeper=sleeper)


def watch_group(root='/', process_reader=None, signaler=None, sleeper=None):
    return ProcessGroup(
        'mihomo-watch', rooted(root, WATCH_PARENT_PID), rooted(root, WATCH_CHILD_PID),
        rooted(root, WATCH_JOURNAL), PYTHON,
        [PYTHON, str(rooted(root, SCRIPT)), 'watch'], process_reader=process_reader,
        signaler=signaler, sleeper=sleeper)
