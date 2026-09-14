"""Keep native jail framework copies separate from live router configuration."""
import ast
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


JAIL = Path(__file__).resolve().parent / 'jail'


class JailPreparationTests(unittest.TestCase):
    def test_fresh_fixture_erases_only_mihomo_backup(self):
        source = ast.parse((JAIL / 'case.py').read_text())
        function = next(item for item in source.body
                        if isinstance(item, ast.FunctionDef) and item.name == 'erase_private_saved_backup')
        namespace = {'ET': ET}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(JAIL / 'case.py'), 'exec'), namespace)
        original = ET.fromstring('<opnsense><system><secret>private-fixture</secret></system>'
                                 '<OPNsense><Mihomo future="keep"><settings>keep</settings>'
                                 '<backup><service_enabled>0</service_enabled></backup></Mihomo>'
                                 '<Lucky><backup><archive>other-plugin</archive></backup></Lucky>'
                                 '</OPNsense><cron><item uuid="keep"/></cron></opnsense>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.xml'
            ET.ElementTree(original).write(path)
            namespace['erase_private_saved_backup'](path)
            original.find('./OPNsense/Mihomo').remove(original.find('./OPNsense/Mihomo/backup'))
            self.assertEqual(ET.tostring(original), ET.tostring(ET.parse(path).getroot()))

    def test_package_inventory_filter_copies_framework_and_excludes_live_data(self):
        source = (JAIL / 'prepare.sh').read_text()
        selected = re.search(r"pkg query -a '%Fp' \| awk[^\n]* '\n(.*?)\n' \|", source, re.DOTALL)
        self.assertIsNotNone(selected)
        accepted = [
            '/usr/local/lib/python3.13/os.py',
            '/usr/local/lib/php/20250925/dom.so',
            '/usr/local/opnsense/mvc/script/load_phalcon.php',
            '/usr/local/opnsense/mvc/app/config/AppConfig.php',
            '/usr/local/opnsense/mvc/app/config/config.php',
            '/usr/local/opnsense/mvc/app/library/OPNsense/Autoload/Loader.php',
            '/usr/local/opnsense/mvc/app/library/OPNsense/Core/Config.php',
            '/usr/local/opnsense/mvc/app/models/OPNsense/Base/FieldTypes/TextField.php',
        ]
        rejected = [
            '/conf/config.xml', '/conf/backup/config-1.xml',
            '/usr/local/etc/config.xml', '/usr/local/etc/php.ini',
            '/usr/local/etc/php/custom-secrets.ini', '/var/lib/php/cache/router.cache',
            '/usr/local/lib/python3.13/__pycache__/os.cpython-313.pyc',
            '/usr/local/lib/python3.13/site-packages/private.pyc',
            '/usr/local/lib/python3.14/os.py',
            '/usr/local/opnsense/mvc/app/models/OPNsense/Mihomo/Backup.php',
        ]
        result = subprocess.run(['awk', '-v', 'python_base=/usr/local/lib/python3.13/', selected.group(1)],
                                input='\n'.join(accepted + rejected) + '\n', text=True,
                                capture_output=True, check=True)
        self.assertEqual(accepted, result.stdout.splitlines())
        self.assertNotIn('cp -a /usr/local/etc/php', source)
        self.assertIn('pkg-owned-runtime.list', source)

    def test_config_adapter_uses_genuine_core_and_only_supplies_revision_helper(self):
        source = (JAIL / 'config.inc').read_text()
        self.assertIn("require_once('script/load_phalcon.php')", source)
        self.assertNotRegex(source, r'\bclass\s+Config\b')
        self.assertIn('function make_config_revision_entry', source)

    def test_legacy_process_command_paths_resolve_inside_the_jail(self):
        source = (JAIL / 'prepare.sh').read_text()
        selected = re.search(r'for source in /usr/bin/pgrep /usr/bin/pkill; do .*?; done', source)
        self.assertIsNotNone(selected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            host = root / 'host'
            jail = root / 'jail'
            (host / 'bin').mkdir(parents=True)
            (host / 'usr/bin').mkdir(parents=True)
            (jail / 'usr/bin').mkdir(parents=True)
            for name in ('pgrep', 'pkill'):
                program = host / 'bin' / name
                program.write_text('#!/bin/sh\nexit 0\n')
                program.chmod(0o755)
                (host / 'usr/bin' / name).symlink_to('../../bin/' + name)
            body = selected.group(0).replace('/usr/bin/', str(host) + '/usr/bin/')
            body = body.replace('"$jail_root$source"', '"$jail_root/usr/bin/$(basename "$source")"')
            subprocess.run(['sh', '-s', str(jail)], input='jail_root="$1"\n' + body,
                           text=True, capture_output=True, check=True)
            for name in ('pgrep', 'pkill'):
                copied = jail / 'usr/bin' / name
                self.assertFalse(copied.is_symlink())
                subprocess.run([str(copied)], check=True)

    def test_python_extension_link_requires_a_packaged_target(self):
        source = (JAIL / 'prepare.sh').read_text()
        selected = re.search(r'copy_runtime_file\(\)\n\{\n(.*?)\n\}', source, re.DOTALL)
        self.assertIsNotNone(selected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            python = root / 'usr/local/lib/python3.13'
            target = python / 'site-packages/_sqlite3.cpython-313.so'
            alias = python / 'lib-dynload/_sqlite3.cpython-313.so'
            target.parent.mkdir(parents=True)
            alias.parent.mkdir(parents=True)
            target.write_bytes(b'packaged extension fixture')
            alias.symlink_to('../site-packages/_sqlite3.cpython-313.so')
            jail = root / 'jail'
            (jail / 'root').mkdir(parents=True)
            (jail / 'root/pkg-owned-runtime.list').write_text(str(target) + '\n' + str(alias) + '\n')
            helper = 'copy_runtime_file() {\n' + selected.group(1) + '\n}\n'
            helper = helper.replace('/usr/local/lib/python', str(root) + '/usr/local/lib/python')
            body = 'python_version=3.13\njail_root="$1"\n' + helper
            body += 'copy_runtime_file "$2" && copy_runtime_file "$3"\n'
            result = subprocess.run(['sh', '-s', str(jail), str(target), str(alias)],
                                    input=body, text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)
            copied = jail / str(alias).lstrip('/')
            self.assertTrue(copied.is_symlink())
            self.assertEqual(target.read_bytes(), copied.read_bytes())
            private = root / 'private.txt'
            private.write_bytes(b'unpackaged data must stay outside')
            outside = alias.parent / 'unpackaged.so'
            outside.symlink_to(private)
            result = subprocess.run(['sh', '-s', str(jail), str(target), str(outside)],
                                    input=body, text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('outside the package-owned inventory', result.stderr)
            self.assertFalse((jail / str(outside).lstrip('/')).exists())

    def test_broad_and_noncanonical_jail_roots_fail_before_preparation(self):
        for root in ('/', '/root', '/etc', '/./', '/tmp/..', '/root//tmp', '/tmp/../etc', 'relative'):
            with self.subTest(root=root):
                result = subprocess.run(['sh', str(JAIL / 'prepare.sh')],
                                        env={**os.environ, 'JAIL_ROOT': root},
                                        text=True, capture_output=True)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('JAIL_ROOT', result.stderr)


if __name__ == '__main__':
    unittest.main()
