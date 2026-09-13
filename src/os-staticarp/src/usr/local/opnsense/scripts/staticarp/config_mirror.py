#!/usr/local/bin/python3
"""Mirror persistent plugin files into the native OPNsense configuration backup."""
from config_backup import BackupError, ConfigBackup

PROFILE = {
    'module': 'Staticarp',
    'root_env': 'OS_STATICARP_BACKUP_ROOT',
    'trees': ['/usr/local/etc/staticarp'],
    'files': ['/etc/rc.conf.d/staticarp'],
    'rc_paths': [],
    'data_lock': '/var/db/os-staticarp-backup/settings.lock',
    'excludes': ['.mvc-*', '.staticarp-*', '*.log', '*.pid', '*.lock'],
}


class StaticarpBackup(ConfigBackup):
    """Keep failed-save recovery originals from being replaced by a watcher snapshot."""
    def __init__(self, profile, script_dir=None, transport=None):
        super().__init__(profile, script_dir, transport)
        original_transport = self.transport

        def guarded_transport(action, payload=None):
            result = original_transport(action, payload)
            if action == 'import' and not result and self._recoveries():
                raise BackupError('A previous settings save needs recovery. Save valid settings before updating the backup.')
            return result

        self.transport = guarded_transport

    def _recoveries(self):
        return sorted(self.path(self.profile['trees'][0]).glob('.staticarp-recovery-*'))

    def _marker(self):
        # Reconciliation must reapply a valid XML snapshot after a failed rollback,
        # even when that snapshot was already applied before the failed save.
        return None if self._recoveries() else super()._marker()

    def _snapshot(self):
        if self._recoveries():
            raise BackupError('A previous settings save needs recovery. Restore or save valid settings before updating the backup.')
        return super()._snapshot()

    def _apply(self, stored):
        changed = super()._apply(stored)
        for recovery in self._recoveries():
            if recovery.is_file() or recovery.is_symlink():
                self._parents_safe(self.profile['trees'][0] + '/' + recovery.name)
                recovery.unlink()
        return changed


if __name__ == '__main__':
    raise SystemExit(StaticarpBackup(PROFILE).main())
