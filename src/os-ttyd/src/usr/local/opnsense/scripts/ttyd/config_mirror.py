#!/usr/local/bin/python3
"""Mirror terminal settings and optional TLS files into configuration backups."""
from config_backup import ConfigBackup, run
from pathlib import Path

PROFILE = {
    'module': 'Ttyd',
    'script_dir': Path(__file__).parent,
    'root_env': 'OS_TTYD_BACKUP_ROOT',
    'trees': [],
    'files': [
        '/etc/rc.conf.d/ttyd',
        '/usr/local/etc/lighttpd_webgui/conf.d/ttyd.conf',
        '/usr/local/etc/ttyd.crt',
        '/usr/local/etc/ttyd.key',
    ],
    'rc_paths': [],
    'excludes': ['*.log', '*.pid', '*.lock'],
}


if __name__ == '__main__':
    raise SystemExit(run(PROFILE))
