#!/usr/local/bin/python3
"""Stop only the DDClient Python instance referenced by its verified PID file."""
import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import tempfile
import time


def kernel_value(name, pid):
    library = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 24)()
    count = ctypes.c_size_t(23)
    library.sysctlnametomib.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_size_t)]
    library.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                              ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    if library.sysctlnametomib(name.encode(), mib, ctypes.byref(count)) or count.value > 23:
        raise OSError(ctypes.get_errno(), 'Cannot resolve bounded process metadata.')
    mib[count.value] = pid
    count.value += 1
    size = ctypes.c_size_t()
    if library.sysctl(mib, count.value, None, ctypes.byref(size), None, 0) or size.value > 1048576:
        raise OSError(ctypes.get_errno(), 'Cannot read bounded process metadata.')
    buffer = ctypes.create_string_buffer(size.value)
    if library.sysctl(mib, count.value, buffer, ctypes.byref(size), None, 0):
        raise OSError(ctypes.get_errno(), 'Process metadata changed.')
    return buffer.raw[:size.value]


def precise_metadata(pid):
    if os.uname().machine != 'amd64' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError('Unsupported process identity ABI.')
    raw = kernel_value('kern.proc.pid', pid)
    if not raw:
        return None
    # FreeBSD 14/15 amd64 sys/user.h preserves this kinfo_proc ABI prefix.
    # Check its exported size and identity instead of assuming arbitrary layouts.
    if len(raw) != 1088 or struct.unpack_from('=i', raw)[0] != 1088:
        raise RuntimeError('Unrecognized process metadata layout.')
    actual, parent = struct.unpack_from('=ii', raw, 72)
    uid, = struct.unpack_from('=I', raw, 168)
    sec, usec = struct.unpack_from('=qq', raw, 336)
    state = raw[388]
    if actual != pid or parent < 0 or sec <= 0 or not 0 <= usec < 1000000 or not 1 <= state <= 7:
        raise RuntimeError('Invalid process identity metadata.')
    if state == 5:
        return None
    return {'pid': pid, 'ppid': parent, 'uid': uid, 'birth': str(sec) + ':' + str(usec)}


class ProcessTable:
    def read(self, pid):
        try:
            before = precise_metadata(pid)
            if before is None:
                return None
            executable = os.fsdecode(kernel_value('kern.proc.pathname', pid).rstrip(b'\0'))
            raw = kernel_value('kern.proc.args', pid)
            argv = [os.fsdecode(item) for item in raw.rstrip(b'\0').split(b'\0')]
            after = precise_metadata(pid)
            if after is None:
                return None
            if not executable or not argv or not argv[0] or before != after:
                raise RuntimeError('The DDClient process identity changed or is incomplete.')
            return {**before, 'executable': executable, 'argv': argv}
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH):
                return None
            raise RuntimeError('Cannot establish DDClient process ownership.') from error

    def signal(self, pid, number):
        os.kill(pid, number)


def secure_read(path, limit=1048576):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RuntimeError('The PID and identity files must be owned regular files.')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError('The process record is too large.')
        return data, info.st_dev, info.st_ino


def persist(path, document):
    descriptor, temporary = tempfile.mkstemp(prefix='.ddclient-identity-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(document, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Owner:
    def __init__(self, pidfile, script, interpreter, table=None):
        self.pidfile = Path(pidfile)
        self.journal = Path(str(pidfile) + '.identity.json')
        self.script = str(Path(script).absolute())
        self.interpreter = str(Path(interpreter).resolve())
        self.table = table or ProcessTable()

    def pid(self):
        try:
            snapshot = secure_read(self.pidfile, 64)
        except FileNotFoundError:
            return None, None
        text = snapshot[0].decode('ascii')
        if not re.fullmatch(r'[1-9][0-9]{0,9}\n?', text) or not 1 < int(text) <= 2147483647:
            raise RuntimeError('Refusing an invalid service PID.')
        return int(text), [snapshot[0].decode('ascii'), snapshot[1], snapshot[2]]

    def matches(self, identity):
        if not isinstance(identity, dict) or identity.get('uid') != os.geteuid() or identity.get('executable') != self.interpreter:
            return False
        argv = identity.get('argv', [])
        if (not isinstance(argv, list) or len(argv) < 2 or
                any(not isinstance(value, str) for value in argv) or argv[1] != self.script):
            return False
        parser = argparse.ArgumentParser(add_help=False, exit_on_error=False)
        for short, long in (('-c', '--config'), ('-s', '--status'), ('-p', '--pid')):
            parser.add_argument(short, long)
        parser.add_argument('-f', '--foreground', action='store_true')
        parser.add_argument('-l', '--list', action='store_true')
        if Path(self.script).name == 'perl_backend.py':
            parser.add_argument('--delay', type=int)
            parser.add_argument('action', nargs='?', default='run', choices=('run',))
        try:
            arguments, unknown = parser.parse_known_args(argv[2:])
        except (argparse.ArgumentError, SystemExit):
            return False
        return (not unknown and not arguments.list and
                str(Path(arguments.pid or '/var/run/ddclient_opn.pid').absolute()) == str(self.pidfile.absolute()))

    def current(self):
        pid, snapshot = self.pid()
        if pid is None:
            return None
        identity = self.table.read(pid)
        if not self.matches(identity):
            raise RuntimeError('The PID file does not reference this DDClient Python instance.')
        if self.pid() != (pid, snapshot) or self.table.read(pid) != identity:
            raise RuntimeError('The process identity changed.')
        return {'version': 1, 'snapshot': snapshot, 'identity': identity, 'script': self.script,
                'interpreter': self.interpreter, 'pidfile': str(self.pidfile.absolute())}

    def load(self):
        try:
            raw, _, _ = secure_read(self.journal)
            document = json.loads(raw)
        except FileNotFoundError:
            return None
        identity = document.get('identity') if isinstance(document, dict) else None
        snapshot = document.get('snapshot') if isinstance(document, dict) else None
        if (not isinstance(document, dict) or set(document) != {
                'version', 'snapshot', 'identity', 'script', 'interpreter', 'pidfile'} or
                document.get('version') != 1 or document.get('script') != self.script or
                document.get('interpreter') != self.interpreter or
                document.get('pidfile') != str(self.pidfile.absolute()) or
                not isinstance(snapshot, list) or len(snapshot) != 3 or
                not isinstance(snapshot[0], str) or
                any(type(value) is not int or value < 0 for value in snapshot[1:]) or
                not isinstance(identity, dict) or type(identity.get('pid')) is not int or
                not 1 < identity['pid'] <= 2147483647 or
                not isinstance(identity.get('birth'), str) or not self.matches(identity)):
            raise RuntimeError('The saved identity does not match this DDClient instance.')
        return document

    def same(self, expected):
        current = self.table.read(expected['pid'])
        return bool(current and self.matches(current) and all(
            current.get(key) == expected.get(key)
            for key in ('pid', 'birth', 'uid', 'executable', 'argv')))

    def record(self, timeout=5):
        deadline = time.monotonic() + timeout
        while True:
            try:
                document = self.current()
                if document is not None:
                    persist(self.journal, document)
                    if not self.check(document):
                        raise RuntimeError('The process changed while recording its identity.')
                    return
            except (RuntimeError, FileNotFoundError, UnicodeError):
                if time.monotonic() >= deadline:
                    raise
            if time.monotonic() >= deadline:
                raise RuntimeError('The DDClient Python daemon did not initialize its PID file.')
            time.sleep(0.1)

    def check(self, document):
        identity = document['identity']
        try:
            pid, snapshot = self.pid()
            return (pid == identity['pid'] and snapshot == document['snapshot'] and
                    self.same(identity))
        except (RuntimeError, FileNotFoundError, UnicodeError):
            return False

    def signal(self, document, number):
        identity = document['identity']
        pid, snapshot = self.pid()
        if ((pid is not None and (pid != identity['pid'] or snapshot != document['snapshot'])) or
                not self.same(identity)):
            raise RuntimeError('The process or PID file changed before signalling; no signal was sent.')
        self.table.signal(document['identity']['pid'], number)

    def stop(self, timeout=2):
        pid, snapshot = self.pid()
        document = self.load()
        if document is None and pid is None:
            return
        if document is None:
            # Legacy adoption requires the precise live script, interpreter and
            # configured PID path; a global process-name scan is never used.
            document = self.current()
        elif pid is not None:
            expected = document['identity']
            if pid != expected['pid'] or snapshot != document['snapshot']:
                raise RuntimeError('The saved identity does not match this DDClient instance.')
            current = self.table.read(pid)
            if current is not None and not self.same(expected):
                raise RuntimeError('The saved identity does not match this DDClient instance.')
        identity = document['identity']
        pid = identity['pid']
        if not self.same(identity):
            if self.table.read(pid) is not None:
                raise RuntimeError('The recorded PID belongs to another process; no signal was sent.')
            current_pid, current_snapshot = self.pid()
            if current_pid is not None:
                if (current_pid != pid or current_snapshot != document['snapshot'] or
                        self.table.read(pid) is not None):
                    raise RuntimeError('A concurrent or foreign service PID was preserved.')
                self.pidfile.unlink()
            if self.load() == document:
                self.journal.unlink(missing_ok=True)
            return
        self.signal(document, signal.SIGTERM)
        deadline = time.monotonic() + timeout
        while self.same(identity) and time.monotonic() < deadline:
            time.sleep(0.1)
        if self.same(identity):
            self.signal(document, signal.SIGKILL)
            deadline = time.monotonic() + timeout
            while self.same(identity) and time.monotonic() < deadline:
                time.sleep(0.1)
            if self.same(identity):
                raise RuntimeError('The verified DDClient process did not stop.')
        if self.table.read(pid) is not None:
            raise RuntimeError('The PID now references a different process; its files were preserved.')
        # Delete stale files only if their content/inode still belongs to this
        # captured instance. Concurrent replacement files are always preserved.
        if self.pid() == (pid, document['snapshot']):
            self.pidfile.unlink()
        try:
            if json.loads(secure_read(self.journal)[0]) == document:
                self.journal.unlink()
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('record', 'stop'))
    parser.add_argument('pidfile')
    parser.add_argument('script')
    parser.add_argument('interpreter')
    arguments = parser.parse_args()
    owner = Owner(arguments.pidfile, arguments.script, arguments.interpreter)
    try:
        lock_path = Path(str(owner.pidfile) + '.control.lock')
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise RuntimeError('The process control lock is not owned by this service.')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if arguments.action == 'record':
                owner.record()
            else:
                owner.stop()
    except (RuntimeError, OSError, ValueError, UnicodeError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
