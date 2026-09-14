#!/usr/local/bin/python3
"""Mirror EasyTier's persistent files into the native configuration backup."""
from config_backup import ConfigBackup, run
from pathlib import Path

PROFILE = {
    'module': 'EasyTier',
    'script_dir': Path(__file__).parent,
    'root_env': 'OS_EASYTIER_BACKUP_ROOT',
    'trees': ['/usr/local/etc/easytier'],
    'files': ['/etc/rc.conf.d/easytier'],
    'rc_paths': [],
    'data_lock': Path('/var/run/easytier-config.lock'),
    'excludes': ['.mvc-*', '.config.*', '*.log', '*.pid', '*.lock'],
}


if __name__ == '__main__':
    raise SystemExit(run(PROFILE))
