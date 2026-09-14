#!/usr/local/bin/python3
"""Return terminal metadata and service operations without SSH credentials."""
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

RC = '/usr/local/etc/rc.d/os-ttyd'
CONFIG = Path('/conf/config.xml')
RC_CONFIG = Path('/etc/rc.conf.d/ttyd')
LEGACY_COMMAND = 'printf "login: "; read -r ttyd_login; if [ -z "$ttyd_login" ]; then echo "login is required"; exit 1; fi; exec /usr/local/bin/ssh -tt -p 22 -o PreferredAuthentications=keyboard-interactive,password -o PubkeyAuthentication=no -o ServerAliveInterval=30 -o StrictHostKeyChecking=accept-new "$ttyd_login@127.0.0.1"'


def ssh_port():
    try:
        value = ET.parse(CONFIG).findtext('system/ssh/port', default='22') or '22'
        port = int(value)
        return port if 1 <= port <= 65535 else 22
    except (OSError, ValueError, ET.ParseError):
        return 22


def run(action):
    return subprocess.run([RC, 'one' + action], capture_output=True, text=True, timeout=30)


def mirror_configuration():
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('config_mirror.py')), 'mirror'],
                                capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout) if result.returncode == 0 else None
        return isinstance(data, dict) and data.get('ok') is True
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


def dispatch(action):
    if action == 'status':
        source = RC_CONFIG
        contents = source.read_text() if source.exists() else ''
        def setting(name, fallback):
            match = re.search(r'^' + re.escape(name) + r'="([^"\n]*)"', contents, re.M)
            return match.group(1) if match else fallback
        command = re.search(r'^ttyd_command=([\"\'])(.*?)\1\s*$', contents, re.M)
        target = '127.0.0.1:' + str(ssh_port())
        if command and command.group(2) not in ('', LEGACY_COMMAND):
            target = 'Custom command'
        return {'status': 'ok', 'running': run('status').returncode == 0,
                'listen': setting('ttyd_interface', '127.0.0.1'),
                'port': setting('ttyd_port', '7681'), 'target': target, 'path': '/ttyd/'}
    if action in {'start', 'stop', 'restart'}:
        result = run(action)
        response = {'status': 'ok' if result.returncode == 0 else 'failed',
                    'error': '' if result.returncode == 0 else 'Unable to start or stop the terminal service. Check that Secure Shell is enabled.'}
        if response['status'] == 'ok' and not mirror_configuration():
            response['warning'] = 'The operation completed, but its configuration backup could not be updated.'
        return response
    return {'status': 'failed', 'error': 'Unknown action.'}


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'ssh-port':
        print(ssh_port())
        sys.exit(0)
    try:
        result = dispatch(sys.argv[1] if len(sys.argv) > 1 else 'status')
    except (OSError, ValueError, subprocess.SubprocessError):
        result = {'status': 'failed', 'error': 'Unable to query the terminal service.'}
    print(json.dumps(result))
