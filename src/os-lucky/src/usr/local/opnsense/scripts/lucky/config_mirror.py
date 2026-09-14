#!/usr/local/bin/python3
"""Mirror persistent plugin files into the native OPNsense configuration backup."""
from config_backup import run

PROFILE = {
    'module': 'Lucky',
    'root_env': 'OS_LUCKY_BACKUP_ROOT',
    'trees': [],
    'files': ['/etc/rc.conf.d/lucky'],
    'rc_paths': [{'file': '/etc/rc.conf.d/lucky', 'variable': 'lucky_conf_dir', 'kind': 'tree', 'default': '/usr/local/etc/lucky'}],
    'excludes': ['.mvc-*', '.lucky-*', '*.log', '*.pid', '*.lock'],
}


if __name__ == '__main__':
    raise SystemExit(run(PROFILE))
