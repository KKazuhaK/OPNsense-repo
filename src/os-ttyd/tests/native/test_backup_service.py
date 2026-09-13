#!/usr/local/bin/python3
"""Exercise real native watcher lifecycle against private backup transport."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'src/common'))
from config_backup import ConfigBackup, revision_token, BackupError, WATCH_INTERVAL


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError('Private watcher did not reach the expected state.')


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


@unittest.skipUnless(platform.system() == 'FreeBSD' and Path('/usr/sbin/daemon').exists(), 'requires native FreeBSD daemon')
class WatcherTest(unittest.TestCase):
    def test_independent_watchers_capture_external_edits_and_stop_without_duplicates(self):
        for service in ['easytier', 'ttyd']:
            with self.subTest(service=service), tempfile.TemporaryDirectory(prefix='utility-watch-') as directory:
                root = Path(directory)
                package = ROOT / 'src' / ('os-' + service)
                source = package / 'src/usr/local/opnsense/scripts' / service / 'config_mirror.py'
                profile_spec = importlib.util.spec_from_file_location(service + '_watch_profile', source)
                profile_module = importlib.util.module_from_spec(profile_spec)
                profile_spec.loader.exec_module(profile_module)
                profile = profile_module.PROFILE
                prefix = root / 'prefix'
                prefix.mkdir()
                store = root / 'transport.json'
                child_pid = root / 'child.pid'
                pidfile = root / 'watcher.pid'
                driver = root / 'private-driver.py'
                driver.write_text('''import importlib.util,json,os,sys,tempfile
from pathlib import Path
sys.path.insert(0, %r)
from config_backup import ConfigBackup, revision_token, BackupError
spec=importlib.util.spec_from_file_location('private_profile', %r)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
store=Path(%r)
def transport(action,payload=None):
    previous=json.loads(store.read_text()) if store.exists() else {}
    if action=='import': return previous
    if payload.pop('_expected') != revision_token(previous):
        raise BackupError('The native configuration changed before its backup was saved.')
    fd,name=tempfile.mkstemp(dir=store.parent)
    with os.fdopen(fd,'w') as stream: json.dump(payload,stream)
    os.replace(name,store)
    return {'changed': previous != payload}
if sys.argv[1]=='watch': Path(%r).write_text(str(os.getpid()))
raise SystemExit(ConfigBackup(module.PROFILE,transport=transport).main())
''' % (str(ROOT / 'src/common'), str(source), str(store), str(child_pid)))
                script = root / 'rc-backup'
                rc_source = package / 'src/usr/local/etc/rc.d' / ('os-' + service + '-backup')
                script.write_text(rc_source.read_text()
                                  .replace('/usr/local/opnsense/scripts/' + service + '/config_mirror.py', str(driver))
                                  .replace('/var/run/' + service + '-config-backup.pid', str(pidfile))
                                  .replace('name=' + service + '_config_backup', 'name=utility_fixture_' + service + '_backup'))
                rc = prefix / 'etc/rc.conf.d' / service
                rc.parent.mkdir(parents=True)
                rc.write_text(service + '_enable="NO"\n')
                rc.chmod(0o600)
                if service == 'easytier':
                    config = prefix / 'usr/local/etc/easytier/config.toml'
                    config.parent.mkdir(parents=True)
                    config.write_text('network_secret="private-native-fixture"\n')
                    config.chmod(0o600)
                environment = dict(os.environ, **{profile['root_env']: str(prefix)})
                command = ['sh', str(script)]
                tracked_pids = []
                try:
                    subprocess.run(command + ['onestart'], env=environment, check=True, capture_output=True)
                    wait_for(lambda: pidfile.exists() and child_pid.exists() and store.exists())
                    parent = int(pidfile.read_text())
                    child = int(child_pid.read_text())
                    tracked_pids.extend([child, parent])
                    subprocess.run(command + ['onestart'], env=environment, check=True, capture_output=True)
                    self.assertEqual(int(pidfile.read_text()), parent)
                    self.assertEqual(int(child_pid.read_text()), child)
                    subprocess.run(command + ['onestatus'], env=environment, check=True, capture_output=True)
                    initial = json.loads(store.read_text())['checksum']
                    saved = (service + '_enable="NO"\n' + service + '_port="17681"\n').encode()
                    rc.write_bytes(saved)
                    wait_for(lambda: json.loads(store.read_text())['checksum'] != initial,
                             timeout=WATCH_INTERVAL + 5)
                    subprocess.run(command + ['onestop'], env=environment, check=True, capture_output=True)
                    wait_for(lambda: not alive(parent) and not alive(child))
                    self.assertFalse(pidfile.exists())
                    rc.write_text('accidental defaults\n')
                    def transport(action, payload=None):
                        return json.loads(store.read_text()) if action == 'import' else {'changed': False}
                    previous = os.environ.get(profile['root_env'])
                    os.environ[profile['root_env']] = str(prefix)
                    try:
                        result = ConfigBackup(profile, transport=transport).restore()
                    finally:
                        if previous is None:
                            del os.environ[profile['root_env']]
                        else:
                            os.environ[profile['root_env']] = previous
                    self.assertTrue(result['ok'])
                    self.assertEqual(rc.read_bytes(), saved)
                    self.assertEqual(rc.stat().st_mode & 0o777, 0o600)
                    print(service + ': real watcher preserved external disabled/port edits, rejected duplicate start, and stopped parent/child')
                finally:
                    subprocess.run(command + ['onestop'], env=environment, capture_output=True)
                    for file in [child_pid, pidfile]:
                        if file.exists():
                            try:
                                tracked_pids.append(int(file.read_text()))
                            except ValueError:
                                pass
                    for fixture_pid in set(tracked_pids):
                        process = subprocess.run(['ps', '-p', str(fixture_pid), '-o', 'command='], capture_output=True, text=True)
                        if 'daemon: utility_fixture_' + service + '_backup[' in process.stdout or str(driver) in process.stdout:
                            try:
                                os.kill(fixture_pid, 15)
                            except ProcessLookupError:
                                pass


if __name__ == '__main__':
    unittest.main()
