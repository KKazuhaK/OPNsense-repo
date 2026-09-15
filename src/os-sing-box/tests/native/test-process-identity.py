#!/usr/local/bin/python3
"""Read a real Python child through the packaged kernel process reader."""
import argparse
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--helpers', default='/usr/local/opnsense/scripts/singbox')
args = parser.parse_args()
if not sys.platform.startswith('freebsd') or os.geteuid() != 0:
    raise SystemExit('Requires FreeBSD root; no routes, PF rules or services are changed.')
sys.path.insert(0, args.helpers)
spec = importlib.util.spec_from_file_location('native_singbox_identity', Path(args.helpers) / 'integration.py')
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)

def wait(check):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.05)
    raise RuntimeError('The owned child did not reach its expected kernel state.')

argv = ['/usr/local/bin/python3', '-c', 'import time; time.sleep(30)', 'argument with spaces (literal)']
child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
record = None
try:
    wait(lambda: integration.identity(child.pid) is not None
         and integration.identity(child.pid)['arguments'] == argv)
    record = integration.identity(child.pid)
    assert record['arguments'] == argv and record['uid'] == os.geteuid()
    assert record['executable'] == os.path.realpath(argv[0]) and ':' in record['birth']
    assert integration.identity(child.pid) == record
    os.kill(child.pid, signal.SIGSTOP)
    wait(lambda: integration.process(child.pid)['stopped'])
    assert integration.identity(child.pid) == record, 'Health must not transfer PID ownership.'
    os.kill(child.pid, signal.SIGCONT)
    wait(lambda: not integration.process(child.pid)['stopped'])
    assert integration.identity(child.pid) == record
finally:
    # Signal only this exact child and preserve any reused foreign PID.
    if record is not None and integration.identity(child.pid) == record:
        os.kill(child.pid, signal.SIGCONT)
        os.kill(child.pid, signal.SIGTERM)
    elif record is None and child.poll() is None:
        child.terminate()
    child.wait(timeout=5)
print('Actual kernel argv, microsecond birth, UID/executable and paused-child ownership passed.')
