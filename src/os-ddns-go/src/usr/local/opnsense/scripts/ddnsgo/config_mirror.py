#!/usr/local/bin/python3
"""Mirror persistent plugin files into the native OPNsense configuration backup."""
from config_backup import run

PROFILE = {
    'module': 'Ddnsgo',
    'root_env': 'OS_DDNSGO_BACKUP_ROOT',
    'trees': ['/usr/local/etc/ddns-go'],
    'files': ['/etc/rc.conf.d/ddnsgo'],
    'rc_paths': [{'file': '/etc/rc.conf.d/ddnsgo', 'variable': 'ddnsgo_config', 'kind': 'file', 'default': '/usr/local/etc/ddns-go/config.yaml'}],
    'excludes': ['.mvc-*', '.ddnsgo-*', '*.log', '*.pid', '*.lock'],
}


if __name__ == '__main__':
    raise SystemExit(run(PROFILE))
