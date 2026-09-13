#!/usr/local/bin/python3
"""Exercise real pkg upgrade hooks with an isolated database and file prefix."""
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


# Snapshot of the outgoing legacy hooks; native scratch does not need Git.
LEGACY_POST = {'easytier': '#!/bin/sh\n'
             'rm -f /var/run/easytier.pid\n'
             'service configd restart >/dev/null 2>&1 || true\n'
             '# Remove the cached menu model so the stale EasyTier entry disappears at once.\n'
             'rm -f /var/lib/php/tmp/opnsense_menu_cache.xml\n'
             'echo "EasyTier removed. Configuration and logs were preserved."\n',
 'ttyd': '#!/bin/sh\n'
         '\n'
         'rm -f \\\n'
         '\t/var/log/ttyd.log \\\n'
         '\t/usr/local/etc/ttyd.crt \\\n'
         '\t/usr/local/etc/ttyd.key\n'
         '\n'
         'rm -f \\\n'
         '\t/var/lib/php/tmp/opnsense_menu_cache.xml \\\n'
         '\t/var/lib/php/tmp/opnsense_acl_cache.json\n'
         '\n'
         'service configd restart >/dev/null 2>&1 || true\n'
         'configctl webgui restart >/dev/null 2>&1 || service lighttpd onerestart >/dev/null 2>&1 || true\n'
         '\n'
         'exit 0\n',
 'staticarp': '#!/bin/sh\n'
              '\n'
              'rm -f /etc/rc.conf.d/staticarp\n'
              'rm -rf /usr/local/etc/staticarp\n'
              'rm -f \\\n'
              '\t/var/lib/php/tmp/opnsense_menu_cache.xml \\\n'
              '\t/var/lib/php/tmp/opnsense_acl_cache.json\n'
              '\n'
              'service configd restart >/dev/null 2>&1 || true\n'
              'configctl webgui restart >/dev/null 2>&1 || service lighttpd onerestart >/dev/null 2>&1 || '
              'true\n'
              '\n'
              'exit 0\n',
 'lucky': '#!/bin/sh\n'
          '\n'
          'rm -f /etc/rc.conf.d/lucky /var/log/lucky.log\n'
          'rm -f \\\n'
          '\t/var/lib/php/tmp/opnsense_menu_cache.xml \\\n'
          '\t/var/lib/php/tmp/opnsense_acl_cache.json\n'
          '\n'
          'rmdir \\\n'
          '\t/usr/local/opnsense/mvc/app/models/OPNsense/Lucky/Menu \\\n'
          '\t/usr/local/opnsense/mvc/app/models/OPNsense/Lucky/ACL \\\n'
          '\t/usr/local/opnsense/mvc/app/models/OPNsense/Lucky 2>/dev/null || true\n'
          '\n'
          'service configd restart >/dev/null 2>&1 || true\n'
          'configctl webgui restart >/dev/null 2>&1 || service lighttpd onerestart >/dev/null 2>&1 || true\n'
          '\n'
          'exit 0\n',
 'ddnsgo': '#!/bin/sh\n'
           '\n'
           'rm -f \\\n'
           '\t/etc/rc.conf.d/ddnsgo \\\n'
           '\t/var/log/ddnsgo.log \\\n'
           '\t/var/run/ddnsgo.pid \\\n'
           '\t/var/lib/php/tmp/opnsense_menu_cache.xml \\\n'
           '\t/var/lib/php/tmp/opnsense_acl_cache.json\n'
           'rm -rf /usr/local/etc/ddns-go\n'
           '\n'
           'service configd restart >/dev/null 2>&1 || true\n'
           'configctl webgui restart >/dev/null 2>&1 || service lighttpd onerestart >/dev/null 2>&1 || true\n'
           '\n'
           'exit 0\n'}

def remap_paths(script, prefix):
    # Replace all filesystem roots in one pass, including cache and log removal.
    return re.sub(r'(?<![A-Za-z0-9_./-])/(usr/local|etc|var)(?=/)',
                  lambda match: str(prefix / match.group(1)), script)


def tree_snapshot(directory):
    if not directory.exists():
        return {}
    snapshot = {'.': ('directory', directory.stat().st_mode & 0o777)}
    for path in sorted(directory.rglob('*')):
        relative = str(path.relative_to(directory))
        mode = path.lstat().st_mode & 0o777
        if path.is_symlink():
            snapshot[relative] = ('symlink', mode, str(path.readlink()))
        elif path.is_dir():
            snapshot[relative] = ('directory', mode)
        else:
            snapshot[relative] = ('file', mode, path.read_bytes())
    return snapshot


class PathRemapTest(unittest.TestCase):
    def test_filesystem_roots_are_remapped_once(self):
        self.assertEqual(
            remap_paths('rm -f /usr/local/etc/ttyd.key /etc/rc.conf.d/ttyd /var/run/ttyd.pid', Path('/tmp/fixture')),
            'rm -f /tmp/fixture/usr/local/etc/ttyd.key /tmp/fixture/etc/rc.conf.d/ttyd /tmp/fixture/var/run/ttyd.pid')


class BootWatcherContractTest(unittest.TestCase):
    def test_early_callback_names_match_the_core_plugin_scanner_and_ship_the_watcher(self):
        callbacks = [('os-lucky', 'lucky_backup.inc', 'lucky_backup_reconcile'),
                     ('os-ddns-go', 'ddnsgo_backup.inc', 'ddnsgo_backup_reconcile'),
                     ('os-staticarp', 'staticarp_backup.inc', 'staticarp_backup_reconcile'),
                     ('os-easytier', 'easytier.inc', 'easytier_backup_configure'),
                     ('os-ttyd', 'ttyd.inc', 'ttyd_backup_configure')]
        for package, filename, callback in callbacks:
            with self.subTest(package=package):
                plugin = ROOT / 'src' / package / 'src/usr/local/etc/inc/plugins.inc.d' / filename
                source = plugin.read_text()
                self.assertRegex(source, r'function\s+' + re.escape(plugin.stem) + r'_configure\s*\(')
                self.assertRegex(source, r"'early'\s*=>\s*\[\s*'" + callback + r"'\s*\]")
                body = source.split('function ' + callback + '(', 1)[1].split('\n}', 1)[0]
                invocation = re.search(r'/usr/sbin/service\s+([^\s]+)\s+onestart', body)
                self.assertIsNotNone(invocation, 'Early restore must independently start the backup watcher')
                service = invocation.group(1)
                shipped = ROOT / 'src' / package / 'src/usr/local/etc/rc.d' / service
                self.assertTrue(shipped.is_file(), 'Boot calls a backup service that the package does not ship: ' + service)
                if not shipped.stat().st_mode & 0o111:
                    build = (ROOT / 'src' / package / 'build.sh').read_text()
                    self.assertRegex(build, r'chmod\s+0755[^\n]*"\$STAGEDIR/usr/local/etc/rc.d/' + re.escape(service) + '"',
                                     'The package must stage its backup service as executable')
                self.assertLess(body.index('config_mirror.py reconcile'), invocation.start())
                self.assertNotRegex(body, r'(?:lucky|ddnsgo|staticarp|easytier|ttyd)_enable',
                                    'Application disablement must not disable its independent watcher')

    def test_singbox_start_hook_calls_a_shipped_backup_script_before_freebsd_services(self):
        package = ROOT / 'src/os-sing-box/src/usr/local/etc'
        hook = package / 'rc.syshook.d/start/15-singbox-backup'
        source = hook.read_text()
        invocation = re.search(r'/usr/sbin/service\s+([^\s]+)\s+onestart', source)
        self.assertIsNotNone(invocation)
        self.assertTrue((package / 'rc.d' / invocation.group(1)).is_file(),
                        'service selects the rc script filename, not its PROVIDE or internal name')
        self.assertLess(hook.name, '20-freebsd')
        self.assertLess(source.index('config_mirror.py reconcile'), invocation.start())
        self.assertNotIn('sing_box_enable', source)

    @unittest.skipUnless(platform.system() == 'FreeBSD' and Path('/usr/local/etc/rc.freebsd').is_file(),
                         'requires genuine OPNsense boot scripts')
    def test_native_core_invokes_plugin_early_callbacks_and_start_syshooks_without_rc_defaults(self):
        boot = Path('/usr/local/etc/rc.bootup').read_text()
        rc = Path('/usr/local/etc/rc').read_text()
        freebsd = Path('/usr/local/etc/rc.freebsd').read_text()
        scanner = Path('/usr/local/etc/inc/plugins.inc').read_text()
        syshook = Path('/usr/local/etc/rc.syshook.d/start/20-freebsd').read_text()
        self.assertIn("plugins_configure('early', true);", boot)
        self.assertLess(rc.index('/usr/local/etc/rc.bootup'), rc.index('/usr/local/etc/rc.syshook start'))
        self.assertIn('/usr/local/etc/rc.freebsd start', syshook)
        self.assertIn("sprintf('%s_configure', $name)", scanner)
        self.assertIn('call_user_func_array($argf', scanner)
        self.assertRegex(freebsd, r'if ! rc_enabled[^\n]*; then\s+continue')
        self.assertNotIn('load_rc_config', freebsd, 'Changed Core selection rules need a fresh boot integration review')


@unittest.skipUnless(platform.system() == 'FreeBSD' and shutil.which('pkg'), 'requires native FreeBSD pkg')
class UpgradeTest(unittest.TestCase):
    def test_legacy_owned_rc_settings_survive_sample_conversion(self):
        packages = {'easytier': 'os-easytier', 'ttyd': 'os-ttyd', 'staticarp': 'os-staticarp',
                    'lucky': 'os-lucky', 'ddnsgo': 'os-ddns-go'}
        for service, package in packages.items():
            for run_legacy_cleanup in [False, True]:
                with self.subTest(service=service, legacy_post_cleanup=run_legacy_cleanup), tempfile.TemporaryDirectory(prefix='mvc-pkg-upgrade-') as directory:
                    root = Path(directory)
                    prefix = root / 'prefix'
                    live = prefix / 'etc/rc.conf.d' / service
                    events = root / 'events'
                    hooks = ROOT / 'src' / package / 'packaging/freebsd'
                    pre = (hooks / '+PRE_INSTALL').read_text()
                    post = (hooks / '+POST_INSTALL').read_text()
                    if '# Begin upgrade state restore.' in post:
                        post = '#!/bin/sh\nset -eu\n' + post.split('# Begin upgrade state restore.', 1)[1].split('# End upgrade state restore.', 1)[0]
                    else:
                        post = post.split('# Remove the retired entry point', 1)[0]
                    pre = remap_paths(pre, prefix)
                    post = remap_paths(post, prefix)
                    old_post = remap_paths(LEGACY_POST[service], prefix)
                    # Preserve the outgoing deletion logic while preventing daemon activity.
                    old_post = old_post.replace('#!/bin/sh', '#!/bin/sh\nservice() { :; }\nconfigctl() { :; }\necho old-post-deinstall >> ' + str(events), 1)
                    pre = pre.replace('set -eu', 'set -eu\necho pre-install >> ' + str(events), 1)
                    observations = 'if [ -f ' + str(live) + ' ]; then\n    echo post-live-present >> ' + str(events) + '\nelse\n    echo post-live-absent >> ' + str(events) + '\nfi\n'
                    state_directory = prefix / 'usr/local/etc' / {'ddnsgo': 'ddns-go'}.get(service, service)
                    if service in ['staticarp', 'ddnsgo']:
                        observations += 'if [ ! -e ' + str(state_directory) + ' ]; then echo post-state-absent >> ' + str(events) + '; fi\n'
                    if service == 'ttyd':
                        observations += 'if [ ! -e ' + str(prefix / 'usr/local/etc/ttyd.key') + ' ]; then echo post-key-absent >> ' + str(events) + '; fi\n'
                    post = post.replace('set -eu', 'set -eu\n' + observations, 1)
                    if run_legacy_cleanup:
                        # Ordinary pkg upgrades omit outgoing POST_DEINSTALL. Exercise it
                        # explicitly at the boundary before incoming state restoration.
                        cleanup_script = root / 'legacy-cleanup.sh'
                        cleanup_script.write_text(old_post)
                        post = post.replace('set -eu', 'set -eu\nsh ' + str(cleanup_script), 1)
                    repositories = root / 'repositories'
                    repositories.mkdir()
                    repository = root / 'repository'
                    repository.mkdir()
                    (repositories / 'fixture.conf').write_text('fixture: { url: "file://' + str(repository) + '", enabled: true, signature_type: "none" }')
                    db = root / 'db'
                    command = ['pkg', '-R', str(repositories), '-o', 'PKG_DBDIR=' + str(db), '-o', 'PKG_CACHEDIR=' + str(root / 'cache'), '-o', 'HANDLE_RC_SCRIPTS=false']
                    self.assertEqual(subprocess.check_output(command + ['config', 'PKG_DBDIR'], text=True).strip(), str(db))
                    abi = subprocess.check_output(['pkg', 'config', 'ABI'], text=True).strip()
                    name = 'mvc-rc-upgrade-' + service
                    archives = []
                    for version, suffix in [('1.0.0', ''), ('1.1.0', '.sample')]:
                        stage = root / ('stage-' + version)
                        meta = root / ('meta-' + version)
                        output = root / ('dist-' + version)
                        meta.mkdir()
                        output.mkdir()
                        destination = Path(str(live) + suffix)
                        staged = stage / str(destination).lstrip('/')
                        staged.parent.mkdir(parents=True)
                        staged.write_text(service + '_enable="YES"\n')
                        manifest = {'name': name, 'version': version, 'origin': 'tests/' + name,
                                    'comment': 'Isolated rc upgrade fixture', 'maintainer': 'test@example.invalid',
                                    'www': 'https://example.invalid', 'abi': abi, 'prefix': '/',
                                    'desc': 'Native hook ordering fixture'}
                        (meta / '+MANIFEST').write_text(json.dumps(manifest))
                        if suffix:
                            (meta / '+PRE_INSTALL').write_text(pre)
                            (meta / '+POST_INSTALL').write_text(post)
                        else:
                            (meta / '+POST_DEINSTALL').write_text(old_post)
                        plist = root / ('plist-' + version)
                        plist.write_text(str(destination) + '\n')
                        subprocess.run(['pkg', 'create', '-r', str(stage), '-m', str(meta), '-p', str(plist), '-o', str(output)], check=True, capture_output=True)
                        archives.append(output / (name + '-' + version + '.pkg'))
                    subprocess.run(command + ['add', '-q', str(archives[0])], check=True, capture_output=True)
                    saved = service + '_enable="NO"\n' + service + '_port="17681"\n' + service + '_interface="127.0.0.2"\n' + service + '_command=\'user override\'\n'
                    live.write_text(saved)
                    live.chmod(0o600)
                    # Seed unowned settings as legacy installers did, including unknown files.
                    state_directory.mkdir(parents=True)
                    state_directory.chmod(0o750)
                    filenames = {'staticarp': ['settings.conf', 'entries.conf', 'interfaces.conf'],
                                 'ddnsgo': ['config.yaml'], 'easytier': ['config.toml'],
                                 'lucky': ['lucky.conf'], 'ttyd': ['fixture.conf']}[service]
                    for filename in filenames:
                        state_file = state_directory / filename
                        state_file.write_text('preserved fixture credential and settings: ' + filename + '\n')
                        state_file.chmod(0o600)
                    nested = state_directory / 'custom/nested'
                    nested.mkdir(parents=True)
                    nested.chmod(0o700)
                    (nested / 'extra.conf').write_bytes(b'unknown settings\x00bytes\n')
                    (nested / 'extra.conf').chmod(0o640)
                    expected_state = tree_snapshot(state_directory)
                    tls_files = {}
                    if service == 'ttyd':
                        for filename, mode in [('ttyd.crt', 0o644), ('ttyd.key', 0o600)]:
                            tls = prefix / 'usr/local/etc' / filename
                            tls.write_text('legacy private TLS fixture: ' + filename + '\n')
                            tls.chmod(mode)
                            tls_files[tls] = (tls.read_bytes(), mode)
                    shutil.copy2(archives[1], repository / archives[1].name)
                    subprocess.run(['pkg', 'repo', str(repository)], check=True, capture_output=True)
                    subprocess.run(command + ['update', '-f', '-q'], check=True, capture_output=True)
                    subprocess.run(command + ['upgrade', '-q', '-y', '-r', 'fixture', name], check=True, capture_output=True)
                    self.assertEqual(live.read_text(), saved)
                    self.assertEqual(live.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(tree_snapshot(state_directory), expected_state)
                    for tls, (contents, mode) in tls_files.items():
                        self.assertEqual(tls.read_bytes(), contents)
                        self.assertEqual(tls.stat().st_mode & 0o777, mode)
                    backup = prefix / 'var/db' / package
                    self.assertFalse((backup / 'rc.conf.upgrade').exists())
                    self.assertFalse((backup / 'state.upgrade').exists())
                    self.assertFalse((backup / 'state.upgrade.new').exists())
                    self.assertFalse(list(backup.glob('*.upgrade')))
                    self.assertEqual(subprocess.check_output(command + ['query', '%v', name], text=True).strip(), '1.1.0')
                    order = events.read_text().splitlines()
                    expected_order = ['pre-install', 'post-live-absent']
                    if run_legacy_cleanup:
                        expected_order.insert(1, 'old-post-deinstall')
                    self.assertEqual(order[:len(expected_order)], expected_order)
                    if run_legacy_cleanup and service in ['staticarp', 'ddnsgo']:
                        self.assertIn('post-state-absent', order)
                    if run_legacy_cleanup and service == 'ttyd':
                        self.assertIn('post-key-absent', order)
                    print(service + (' with historical POST_DEINSTALL' if run_legacy_cleanup else '') + ' real pkg upgrade preserved rc/settings/TLS bytes and modes; events=' + ','.join(order))

if __name__ == '__main__':
    unittest.main()
