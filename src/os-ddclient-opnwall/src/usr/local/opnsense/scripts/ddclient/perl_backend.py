#!/usr/local/bin/python3
"""Supervise one explicitly launched foreground Perl backend without global scans."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from process_owner import Owner, ProcessTable, persist, secure_read

PERL = '/usr/local/bin/perl'
PROGRAM = '/usr/local/sbin/ddclient'
CONFIG = '/usr/local/etc/ddclient.conf'
PIDFILE = '/var/run/ddclient.pid'
LAUNCH_CODE = ('import os,sys; fd=int(sys.argv[1]); token=os.read(fd,1); os.close(fd); '
               'token == b"1" or sys.exit(111); os.execv(sys.argv[2], sys.argv[2:])')


def stable(identity):
    return None if identity is None else {key: identity[key] for key in ('pid', 'birth', 'uid', 'executable')}


class Child:
    def __init__(self, pidfile=PIDFILE, table=None):
        self.pidfile = Path(pidfile)
        self.journal = Path(str(pidfile) + '.child.identity.json')
        self.table = table or ProcessTable()
        self.perl = str(Path(PERL).resolve())

    def load(self):
        try:
            record = json.loads(secure_read(self.journal)[0])
        except FileNotFoundError:
            return None
        if (not isinstance(record, dict) or record.get('version') not in (1, 2) or record.get('program') != PROGRAM or
                record.get('pidfile') != str(self.pidfile.absolute()) or record.get('perl') != self.perl or
                not isinstance(record.get('launch'), list) or record['launch'][:3] != [PERL, PROGRAM, '-foreground'] or
                not isinstance(record.get('identity'), dict)):
            raise RuntimeError('Invalid Perl child ownership; no process was adopted.')
        identity = record['identity']
        if (type(identity.get('pid')) is not int or not 1 < identity['pid'] <= 2147483647 or
                identity.get('uid') != os.geteuid() or identity.get('executable') != self.perl or
                not isinstance(identity.get('birth'), str)):
            raise RuntimeError('Invalid Perl child process identity.')
        if record['version'] == 2:
            launcher = record.get('launcher')
            if (not isinstance(launcher, dict) or set(launcher) != {
                    'pid', 'birth', 'uid', 'executable', 'argv'} or
                    any(launcher.get(key) != identity.get(key) for key in ('pid', 'birth', 'uid')) or
                    launcher.get('uid') != os.geteuid() or
                    launcher.get('executable') != str(Path(sys.executable).resolve()) or
                    not isinstance(launcher.get('argv'), list) or not launcher['argv'] or
                    any(not isinstance(value, str) or '\0' in value for value in launcher['argv'])):
                raise RuntimeError('Invalid Perl child launcher identity.')
        return record

    def owns(self, record, current):
        if current is None:
            return False
        expected = record['identity']
        if stable(current) == expected:
            return True
        launcher = record.get('launcher')
        return bool(launcher and all(current.get(key) == launcher[key]
                    for key in ('pid', 'birth', 'uid', 'executable', 'argv')))

    def cleanup(self, timeout=2):
        record = self.load()
        if record is None:
            return
        expected = record['identity']
        pid = expected['pid']
        current = self.table.read(pid)
        if current is not None and not self.owns(record, current):
            raise RuntimeError('The Perl child PID was replaced; no signal was sent.')
        # DDClient rewrites $0 while sleeping/updating. Ownership comes from the
        # exact Popen launch plus stable kernel birth/executable/UID, not its title.
        for number in (signal.SIGTERM, signal.SIGKILL):
            current = self.table.read(pid)
            if current is None:
                break
            if not self.owns(record, current):
                raise RuntimeError('The Perl child changed before signalling.')
            self.table.signal(pid, number)
            deadline = time.monotonic() + timeout
            while self.owns(record, self.table.read(pid)) and time.monotonic() < deadline:
                time.sleep(.05)
            current = self.table.read(pid)
            if current is not None and not self.owns(record, current):
                raise RuntimeError('The Perl child PID now belongs to another process.')
        if self.table.read(pid) is not None:
            raise RuntimeError('The owned Perl backend did not stop.')
        if self.load() == record:
            self.journal.unlink(missing_ok=True)

    def launch(self, delay, popen=subprocess.Popen):
        if self.load() is not None:
            raise RuntimeError('A previous Perl child needs recovery before starting.')
        arguments = [PERL, PROGRAM, '-foreground', '-daemon', str(delay), '-file', CONFIG,
                     '-pid', str(self.pidfile) + '.child.pid']
        read_gate, write_gate = os.pipe()
        launcher = [sys.executable, '-c', LAUNCH_CODE, str(read_gate), *arguments]
        process = None
        recorded = False
        try:
            # The launcher cannot exec DDClient until its exact identity is durable.
            # EOF before that point makes it exit without starting a writer.
            process = popen(launcher, pass_fds=(read_gate,))
            os.close(read_gate)
            read_gate = -1
            deadline = time.monotonic() + 2
            while True:
                current = self.table.read(process.pid)
                if (current and current.get('uid') == os.geteuid() and
                        current.get('executable') == str(Path(sys.executable).resolve()) and
                        current.get('argv') == launcher and isinstance(current.get('birth'), str)):
                    expected = {key: current[key] for key in ('pid', 'birth', 'uid')}
                    expected['executable'] = self.perl
                    launch_identity = {key: current[key] for key in ('pid', 'birth', 'uid', 'executable', 'argv')}
                    record = {'version': 2, 'identity': expected, 'launcher': launch_identity,
                              'launch': arguments, 'perl': self.perl,
                              'program': PROGRAM, 'pidfile': str(self.pidfile.absolute())}
                    persist(self.journal, record)
                    recorded = True
                    if self.table.read(process.pid) != current:
                        raise RuntimeError('The gated Perl launcher changed during registration.')
                    if os.write(write_gate, b'1') != 1:
                        raise RuntimeError('The gated Perl launcher was not released completely.')
                    os.close(write_gate)
                    write_gate = -1
                    return process
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('The gated Perl launcher did not initialize.')
                time.sleep(.02)
        except Exception:
            if recorded:
                self.cleanup()
            # Before the journal is durable, a live unreaped Popen child cannot
            # have had its PID reused. The closed gate also prevents DDClient exec.
            elif process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            raise
        finally:
            if read_gate >= 0:
                os.close(read_gate)
            if write_gate >= 0:
                os.close(write_gate)


def parent(pidfile=PIDFILE):
    return Owner(pidfile, str(Path(__file__).absolute()), '/usr/local/bin/python3')


def guard(pidfile=PIDFILE):
    control = parent(pidfile)
    pid, snapshot = control.pid()
    if pid is not None:
        identity = control.table.read(pid)
        if identity is not None:
            raise RuntimeError('An existing DDClient process lacks a new launch boundary. Stop the legacy backend explicitly before migration; its process and parameters were preserved.')
        if control.pid() == (pid, snapshot) and control.table.read(pid) is None:
            control.pidfile.unlink()
    Child(pidfile).cleanup()
    try:
        document = json.loads(secure_read(control.journal)[0])
    except FileNotFoundError:
        return
    if (not isinstance(document, dict) or document.get('version') != 1 or document.get('script') != control.script or document.get('pidfile') != str(control.pidfile.absolute()) or
            not control.matches(document.get('identity'))):
        raise RuntimeError('A previous supervisor record needs manual recovery.')
    expected = document['identity']
    deadline = time.monotonic() + 3
    while control.table.read(expected['pid']) == expected and time.monotonic() < deadline:
        time.sleep(.05)
    if control.table.read(expected['pid']) is not None:
        raise RuntimeError('A previous supervisor is still running; a new backend was not started.')
    if json.loads(secure_read(control.journal)[0]) == document:
        control.journal.unlink(missing_ok=True)


def stop(pidfile=PIDFILE):
    control = parent(pidfile)
    pid, snapshot = control.pid()
    if pid is not None:
        identity = control.table.read(pid)
        if identity is not None and not control.matches(identity):
            raise RuntimeError('The PID file does not prove ownership of a supervised backend. The legacy or foreign process was preserved.')
    # A missing parent PID file does not prevent recovery of an explicitly owned
    # child. A foreign/reused child causes failure before any backend is started.
    Child(pidfile).cleanup()
    pid, snapshot = control.pid()
    if pid is not None and control.table.read(pid) is None:
        if control.pid() == (pid, snapshot) and control.table.read(pid) is None:
            control.pidfile.unlink()
    else:
        control.stop(timeout=5)
    Child(pidfile).cleanup()
    try:
        document = json.loads(secure_read(control.journal)[0])
        if (isinstance(document, dict) and document.get('version') == 1 and document.get('script') == control.script and document.get('pidfile') == str(control.pidfile.absolute())
                and control.matches(document.get('identity')) and control.table.read(document['identity']['pid']) is None
                and json.loads(secure_read(control.journal)[0]) == document):
            control.journal.unlink(missing_ok=True)
    except FileNotFoundError:
        pass


def ready(pidfile=PIDFILE):
    control = parent(pidfile)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        record = Child(pidfile).load()
        pid, _ = control.pid()
        if pid is None or not control.matches(control.table.read(pid)):
            raise RuntimeError('The Perl supervisor did not remain running.')
        if record is not None and stable(control.table.read(record['identity']['pid'])) == record['identity']:
            return
        time.sleep(.05)
    raise RuntimeError('The launch-owned Perl backend did not become ready.')


def supervise(pidfile, delay):
    child = Child(pidfile)
    stopping = False
    def requested_stop(number, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, requested_stop)
    signal.signal(signal.SIGINT, requested_stop)
    process = child.launch(delay)
    try:
        while process.poll() is None and not stopping:
            time.sleep(.1)
        child.cleanup()
        process.wait(timeout=3)
        if not stopping and process.returncode:
            raise RuntimeError('The supervised Perl backend exited unsuccessfully.')
    finally:
        child.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', nargs='?', default='run', choices=('run', 'guard', 'stop', 'force', 'ready'))
    parser.add_argument('-p', '--pid', default=PIDFILE)
    parser.add_argument('--delay', type=int, default=300)
    parser.add_argument('-f', '--foreground', action='store_true')
    arguments = parser.parse_args()
    try:
        if not 1 <= arguments.delay <= 86400:
            raise RuntimeError('Invalid backend polling interval.')
        if arguments.action == 'guard':
            guard(arguments.pid)
        elif arguments.action == 'stop':
            stop(arguments.pid)
        elif arguments.action == 'ready':
            ready(arguments.pid)
        elif arguments.action == 'force':
            # This foreground one-shot has no daemon PID and is never included in
            # Stop's child journal, even while it executes the same Perl program.
            return subprocess.run([PERL, PROGRAM, '-foreground', '-daemon', '0', '-force', '-file', CONFIG,
                                   '-pid', arguments.pid + '.force.pid']).returncode
        else:
            guard(arguments.pid)
            sys.path.insert(0, '/usr/local/opnsense/site-python')
            from daemonize import Daemonize
            Daemonize(app='ddclient-opnwall-perl', pid=arguments.pid,
                      foreground=arguments.foreground,
                      action=lambda: supervise(arguments.pid, arguments.delay)).start()
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
