#!/usr/local/bin/python3
"""Control one FreeBSD daemon without signaling foreign or reused processes."""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

from process_identity import process

LIMIT = 1024 * 1024


def children(pid):
    if type(pid) is not int or not 0 < pid < 2147483648:
        raise RuntimeError('Refusing an invalid supervisor PID.')
    try:
        result = subprocess.run(['/bin/ps', '-axo', 'pid=', '-o', 'ppid='], capture_output=True, timeout=3)
        if result.returncode or len(result.stdout) > LIMIT:
            raise RuntimeError('Cannot enumerate bounded supervisor children.')
        values = []
        for row in result.stdout.decode().splitlines():
            columns = row.split()
            if len(columns) != 2:
                raise ValueError
            child, parent = map(int, columns)
            if child == 0 and parent == 0:
                continue
            if not 0 < child < 2147483648 or not 0 <= parent < 2147483648:
                raise ValueError
            if parent == pid:
                values.append(child)
        return values
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('Cannot enumerate supervisor children.') from error


def boot():
    result = subprocess.run(['/sbin/sysctl', '-n', 'kern.boottime'], capture_output=True, timeout=3)
    if result.returncode or not result.stdout or len(result.stdout) > 4096:
        raise RuntimeError('Cannot read kernel boot identity.')
    return result.stdout.decode().strip()


def secure_read(path, limit=LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RuntimeError('The process record must be an owned regular file without foreign writers.')
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError('The process record is too large.')
        return data


def persist(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix='.%s.' % path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def positive_pid(text):
    if not isinstance(text, str) or not re.fullmatch(r'[1-9][0-9]{0,9}', text) or int(text) >= 2147483648:
        raise RuntimeError('Refusing an invalid service PID.')
    return int(text)


def acquire_lock(descriptor):
    deadline = time.monotonic() + 5
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Another scoped service operation did not release its lock.') from None
            time.sleep(0.05)


class Control:
    def __init__(self, pidfile, tag, binary, arguments):
        self.pidfile = Path(pidfile)
        self.journal = Path(str(pidfile) + '.identity.json')
        self.tag = tag
        self.binary = str(Path(binary).resolve())
        self.expected = [str(binary), *arguments]
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', tag):
            raise RuntimeError('Invalid daemon service tag.')

    def parent_matches(self, identity):
        if not identity or identity.get('executable') != '/usr/sbin/daemon' or identity.get('uid') != os.geteuid():
            return False
        title = r'daemon: ' + re.escape(self.tag) + r'\[[1-9][0-9]*\](?: \(daemon\))?'
        return isinstance(identity.get('argv'), list) and len(identity['argv']) == 1 and re.fullmatch(title, identity['argv'][0]) is not None

    def load_journal(self):
        try:
            record = json.loads(secure_read(self.journal))
        except FileNotFoundError:
            return None
        except (ValueError, TypeError) as error:
            raise RuntimeError('The process identity record is invalid.') from error
        if not isinstance(record, dict) or record.get('schema', 1) != 1 or not isinstance(record.get('boot'), str) or not isinstance(record.get('children'), list) or len(record['children']) > 128:
            raise RuntimeError('The process identity record is invalid.')
        argv = record.get('argv')
        if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or '\0' in arg for arg in argv) or len(json.dumps(argv)) > 65536 or str(Path(argv[0]).resolve()) != self.binary:
            raise RuntimeError('The recorded application command is invalid.')
        for kind, items in (('parent', [record.get('parent')] if record.get('parent') is not None else []), ('child', record['children'])):
            for item in items:
                if not isinstance(item, dict) or type(item.get('pid')) is not int or not 0 < item['pid'] < 2147483648 or not isinstance(item.get('birth'), str) or not re.fullmatch(r'[1-9][0-9]*:[0-9]{1,6}', item['birth']) or item.get('uid') != os.geteuid():
                    raise RuntimeError('A recorded process identity is invalid.')
                if kind == 'parent' and not self.parent_matches(item) or kind == 'child' and (item.get('executable') != self.binary or item.get('argv') != argv):
                    raise RuntimeError('A recorded process identity is not owned by this service.')
        return record

    def read(self, allow_empty=False):
        try:
            pid = positive_pid(secure_read(self.pidfile, 64).decode().strip())
        except FileNotFoundError:
            record = self.load_journal()
            if record is not None and record['boot'] != boot():
                # Processes cannot survive a kernel boot. With no current PID
                # file, the old receipt cannot authorize a signal and can be
                # retired so the configured service starts normally.
                if self.load_journal() == record:
                    self.journal.unlink(missing_ok=True)
                return None
            if record and record.get('parent'):
                # The durable birth/executable/title receipt remains sufficient
                # ownership if daemon(8) lost its PID file. Keep a live exact
                # supervisor recoverable; retire only an exited one.
                if not self.same(record['parent']):
                    record['parent'] = None
            return record
        identity = process(pid)
        record = self.load_journal()
        if record is not None:
            if record['boot'] != boot():
                raise RuntimeError('The process record belongs to a different kernel boot; settings were preserved.')
            parent = record.get('parent')
            recorded_pid = record.get('supervisor_pid', parent['pid'] if parent else None)
            if recorded_pid != pid:
                raise RuntimeError('The PID file does not match the service identity record.')
            if identity and (parent is None or identity['birth'] != parent['birth'] or not self.parent_matches(identity)):
                raise RuntimeError('The service PID was reused or belongs to another process.')
            if identity:
                # Snapshot current children for daemon -r; retained historical
                # children still cover a writer reparented by a partial stop.
                current = self.application_children(identity, record['argv'])
                retained = [child for child in record['children'] if self.same(child)]
                record['children'] = self.merge_children(current, retained)
                record['parent'] = identity
            else:
                record['parent'] = None
            return record
        if not identity:
            return {'schema': 1, 'parent': None, 'supervisor_pid': pid, 'children': [], 'argv': self.expected, 'boot': boot()}
        if not self.parent_matches(identity):
            raise RuntimeError('The PID does not identify this daemon supervisor.')
        application = self.application_children(identity, self.expected)
        if not application and not allow_empty:
            raise RuntimeError('Cannot establish ownership without the expected application child.')
        return {'schema': 1, 'parent': identity, 'supervisor_pid': pid, 'children': application, 'argv': self.expected, 'boot': boot()}

    @staticmethod
    def merge_children(*groups):
        result = {}
        for group in groups:
            for child in group:
                result[(child['pid'], child['birth'])] = child
        return list(result.values())

    def application_children(self, parent, expected):
        owned = []
        for pid in children(parent['pid']):
            identity = process(pid)
            if identity and identity['ppid'] == parent['pid']:
                if identity['uid'] != os.geteuid() or identity['executable'] != self.binary or identity['argv'] != expected:
                    raise RuntimeError('Unexpected supervisor child; refusing to stop or import settings.')
                owned.append(identity)
        return owned

    def same(self, identity):
        current = process(identity['pid'])
        if not current or any(current[key] != identity[key] for key in ('pid', 'birth', 'uid', 'executable')):
            return False
        if identity['executable'] == '/usr/sbin/daemon':
            return self.parent_matches(current)
        return current['argv'] == identity['argv'] and current['executable'] == self.binary

    def send(self, identity, sig):
        if self.same(identity):
            try:
                os.kill(identity['pid'], sig)
                return True
            except ProcessLookupError:
                pass
        return False

    def stop(self):
        record = self.read(allow_empty=True)
        if record is None:
            return
        parent = record.get('parent')
        frozen = False
        try:
            if parent:
                # Freeze respawning before enumerating children. Otherwise -r
                # can create an unrecorded writer between enumeration and TERM.
                frozen = self.send(parent, signal.SIGSTOP)
                if not frozen:
                    raise RuntimeError('The supervisor changed before respawn could be frozen; settings were preserved.')
                deadline = time.monotonic() + 1
                while self.same(parent) and not (process(parent['pid']) or {}).get('stopped') and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not self.same(parent) or not (process(parent['pid']) or {}).get('stopped'):
                    raise RuntimeError('The supervisor could not be frozen safely; settings were preserved.')
                if frozen:
                    current = self.application_children(parent, record['argv'])
                    record['children'] = self.merge_children(current, [child for child in record['children'] if self.same(child)])
            try:
                persist(self.journal, record)
            except OSError:
                if not parent or not frozen:
                    raise
                # A failed startup journal must not leave a healthy writer
                # running unnoticed. Keep the supervisor frozen and alive until
                # all captured writers exit, so its owned PID remains recovery
                # evidence if one ignores TERM. No respawn can occur meanwhile.
                for child in record['children']:
                    self.send(child, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while any(self.same(child) for child in record['children']) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if any(self.same(child) for child in record['children']):
                    raise RuntimeError('A writer survived journal failure; its supervisor PID was preserved.')
            if parent:
                self.send(parent, signal.SIGTERM)
                if frozen:
                    self.send(parent, signal.SIGCONT)
                    frozen = False
                deadline = time.monotonic() + 5
                while self.same(parent) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self.same(parent):
                    raise RuntimeError('The daemon supervisor did not stop; settings were preserved.')
            for child in record['children']:
                self.send(child, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while any(self.same(child) for child in record['children']) and time.monotonic() < deadline:
                time.sleep(0.05)
            if any(self.same(child) for child in record['children']):
                raise RuntimeError('An application writer did not stop; settings were preserved.')
            if self.pidfile.exists() or self.pidfile.is_symlink():
                text = secure_read(self.pidfile, 64).decode().strip()
                pid = positive_pid(text)
                if pid != record.get('supervisor_pid') or process(pid):
                    raise RuntimeError('A concurrent or foreign service PID was preserved.')
                self.pidfile.unlink()
            self.journal.unlink(missing_ok=True)
        finally:
            # A journal failure must never leave an owned supervisor suspended.
            if frozen:
                self.send(parent, signal.SIGCONT)

    def record(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                record = self.read(allow_empty=True)
            except RuntimeError:
                # daemon creates its PID file before writing the PID and forks
                # before the child execs. Retry those bounded startup windows;
                # malformed nonempty PIDs are always rejected immediately.
                raw = secure_read(self.pidfile, 64).decode().strip()
                if raw:
                    positive_pid(raw)
                record = None
            if record and record.get('parent'):
                # Record supervisor ownership even if its child has not exec'd
                # yet: the RC failure path can safely stop a respawning daemon.
                persist(self.journal, record)
                if record['children']:
                    return
            time.sleep(0.05)
        raise RuntimeError('The application did not establish a verified service identity.')

    def status(self):
        record = self.read()
        return bool(record and record.get('parent') and record['children'] and all(self.same(child) for child in record['children']))

    def idle(self):
        record = self.read()
        if record and (record.get('parent') or any(self.same(child) for child in record['children'])):
            raise RuntimeError('A live application writer prevents configuration import.')


def main():
    try:
        action, pidfile, tag, binary, *arguments = sys.argv[1:]
        controller = Control(pidfile, tag, binary, arguments)
        lockpath = Path(str(pidfile) + '.control.lock')
        descriptor = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'r+') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise RuntimeError('The process control lock has foreign ownership or writers.')
            acquire_lock(lock.fileno())
            if action == 'status':
                return 0 if controller.status() else 1
            if action == 'record':
                controller.record()
            elif action == 'stop':
                controller.stop()
            elif action == 'idle':
                controller.idle()
            else:
                raise RuntimeError('Unknown process control action.')
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        # Native arguments may contain credentials; return only fixed messages.
        print('Scoped service process control failed; settings and foreign processes were preserved.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
