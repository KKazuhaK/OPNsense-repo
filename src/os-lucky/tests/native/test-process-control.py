#!/usr/local/bin/python3
"""Run owned native process fixtures; this is not fresh-install acceptance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import patch

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--run', action='store_true')
parser.add_argument('--directory', required=True)
parser.add_argument('--helpers', required=True)
args = parser.parse_args()
root = Path(args.directory)
if not args.run or not sys.platform.startswith('freebsd') or os.geteuid() != 0:
    raise SystemExit('Explicit FreeBSD root private-fixture execution is required.')
if not str(root).startswith('/tmp/network-process-native.') or root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o077:
    raise SystemExit('A private owned fixture directory is required.')
sys.path.insert(0, args.helpers)
spec = importlib.util.spec_from_file_location('native_owned_process_control', Path(args.helpers) / 'process_control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
from process_identity import process

checks = []
owners = []

def run(argv):
    answer = subprocess.run(argv, capture_output=True, timeout=20)
    if answer.returncode: raise RuntimeError('A private native fixture command failed.')
    return answer.stdout


def baseline():
    return {'config': hashlib.sha256(Path('/conf/config.xml').read_bytes()).hexdigest(),
            'packages': hashlib.sha256(run(['/usr/sbin/pkg', 'query', '%n %v'])).hexdigest(),
            'pf_rules': hashlib.sha256(run(['/sbin/pfctl', '-sr'])).hexdigest()}


def wait(predicate, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value: return value
        time.sleep(.05)
    raise RuntimeError('A private native process condition timed out.')


def launch(name, binary, argv):
    pid = root / (name + '.pid')
    tag = root.name + ':' + name
    run(['/usr/sbin/daemon', '-P', str(pid), '-r', '-R', '1', '-f', '-t', tag, binary, *argv])
    instance = control.Control(pid, tag, binary, argv)
    # Keep recovery identity even if a later assertion fails.
    wait(lambda: pid.exists() and pid.read_bytes().strip())
    parent = wait(lambda: process(int(pid.read_bytes())))
    record = {'parent': parent, 'children': [], 'argv': [binary, *argv]}
    owners.append((instance, record))
    instance.record()
    return instance


def force_cleanup(instance, saved):
    try:
        live = instance.read(allow_empty=True) or saved
    except RuntimeError:
        live = saved
    parent = live.get('parent')
    if parent and instance.same(parent):
        instance.send(parent, signal.SIGSTOP)
        # Include the current -r child, never a process found by name alone.
        for child in instance.application_children(parent, live['argv']):
            instance.send(child, signal.SIGKILL)
        instance.send(parent, signal.SIGTERM)
        instance.send(parent, signal.SIGCONT)
    for child in live.get('children', []): instance.send(child, signal.SIGKILL)
    try: instance.stop()
    except RuntimeError: pass

before = baseline()
try:
    for pid in (0, -1, 2147483648, True):
        try: process(pid)
        except RuntimeError: continue
        raise RuntimeError('An invalid native process PID was accepted.')
    checks.append('native_positive_pid_guard')

    instance = launch('respawn', '/bin/sleep', ['600'])
    first = instance.read()
    if not instance.status() or len(first['children']) != 1:
        raise RuntimeError('The real daemon identity did not establish a single owned child.')
    checks.append('native_exact_nul_argv_and_supervisor_identity')
    instance.send(first['children'][0], signal.SIGKILL)
    second = wait(lambda: (record if record and record.get('parent') and record['children'] and record['children'][0]['birth'] != first['children'][0]['birth'] else None)
                  if (record := instance.read(allow_empty=True)) else None)
    if not instance.status() or first['children'][0]['pid'] == second['children'][0]['pid']:
        raise RuntimeError('The real -r replacement child was not recognized.')
    instance.stop()
    if any(instance.same(item) for item in [second['parent'], *second['children']]):
        raise RuntimeError('An owned respawning native process survived stop.')
    checks.append('native_current_respawn_child_and_frozen_stop')

    foreign = launch('foreign', '/bin/sleep', ['600'])
    foreign_record = foreign.read()
    wrong = control.Control(foreign.pidfile, root.name + ':wrong', '/bin/sleep', ['600'])
    pid_before = foreign.pidfile.read_bytes()
    try: wrong.stop()
    except RuntimeError: pass
    else: raise RuntimeError('A foreign supervisor tag was accepted.')
    if foreign.pidfile.read_bytes() != pid_before or not foreign.status():
        raise RuntimeError('A foreign process or PID file was changed.')
    checks.append('native_foreign_process_and_pid_preservation')
    foreign.stop()

    failed = launch('journal-failure', '/bin/sleep', ['600'])
    with patch.object(control, 'persist', side_effect=OSError('private fixture write failure')):
        failed.stop()
    if failed.status(): raise RuntimeError('A healthy writer survived scoped journal-failure cleanup.')
    checks.append('native_healthy_writer_cleanup_on_journal_failure')

    script = root / 'ignore-term.py'
    script.write_text('import signal,time\nsignal.signal(signal.SIGTERM,lambda signum,frame:None)\nwhile True:time.sleep(.1)\n')
    script.chmod(0o600)
    writer = launch('writer', sys.executable, [str(script)])
    time.sleep(.2)
    try: writer.stop()
    except RuntimeError: pass
    else: raise RuntimeError('A live native writer incorrectly allowed stop.')
    retained = writer.load_journal()
    if not retained or not any(writer.same(child) for child in retained['children']):
        raise RuntimeError('Partial stop lost ownership of the surviving native writer.')
    try: writer.idle()
    except RuntimeError: pass
    else: raise RuntimeError('A surviving writer incorrectly allowed configuration import.')
    checks.append('native_partial_stop_retains_writer_journal_and_blocks_import')
    for child in retained['children']: writer.send(child, signal.SIGKILL)
    wait(lambda: not any(writer.same(child) for child in retained['children']))
    writer.stop()
    if writer.pidfile.exists() or writer.journal.exists():
        raise RuntimeError('Completed native partial-stop recovery left process records.')
    checks.append('native_partial_stop_recovery_without_foreign_signals')
finally:
    for instance, saved in reversed(owners): force_cleanup(instance, saved)
    after = baseline()
    report = {'ok': before == after, 'checks': checks, 'native_configuration_and_packages_preserved': before == after,
              'remaining_owned_processes': []}
    for instance, saved in owners:
        if any(instance.same(item) for item in [saved.get('parent'), *saved.get('children', [])] if item):
            report['remaining_owned_processes'].append(instance.tag)
    report['ok'] = report['ok'] and not report['remaining_owned_processes']
    target = root / 'report.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    target.chmod(0o600)
if not report['ok'] or len(checks) != 7:
    raise SystemExit('Private native fixture validation was incomplete.')
print(json.dumps(report))
