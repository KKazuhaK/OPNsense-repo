"""Keep native jail framework copies separate from live router configuration."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest import mock
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


def client_helper():
    spec = importlib.util.spec_from_file_location('jail_dns_client', JAIL / 'dns-client.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResolver:
    """Answer one A record, behind a compressed name, or NXDOMAIN, over UDP and TCP on loopback."""

    def __init__(self, rcode=0, address='192.0.2.30', skew=0):
        self.rcode, self.address, self.skew = rcode, address, skew
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(('127.0.0.1', self.port))
        self.tcp.listen(4)
        for target in (self.serve_udp, self.serve_tcp):
            threading.Thread(target=target, daemon=True).start()

    def reply(self, query):
        identifier = (struct.unpack('!H', query[:2])[0] + self.skew) & 0xFFFF
        question = query[12:]
        answers = 0 if self.rcode else 1
        header = struct.pack('!HHHHHH', identifier, 0x8180 | self.rcode, 1, answers, 0, 0)
        record = (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(self.address)) if answers else b''
        return header + question + record

    def serve_udp(self):
        while True:
            try:
                query, peer = self.udp.recvfrom(512)
            except OSError:
                return
            self.udp.sendto(self.reply(query), peer)

    def serve_tcp(self):
        while True:
            try:
                connection, _ = self.tcp.accept()
            except OSError:
                return
            with connection:
                size = struct.unpack('!H', connection.recv(2))[0]
                answer = self.reply(connection.recv(size))
                connection.sendall(struct.pack('!H', len(answer)) + answer)

    def close(self):
        self.udp.close()
        self.tcp.close()


class LanClientHelperTests(unittest.TestCase):
    """The client jail's helper is what tells Mihomo's answers from Unbound's in the captured round."""

    def resolver(self, **kwargs):
        resolver = FakeResolver(**kwargs)
        self.addCleanup(resolver.close)
        return resolver

    def test_answers_are_read_over_both_transports(self):
        helper = client_helper()
        port = self.resolver().port
        for transport in ('udp', 'tcp'):
            with self.subTest(transport=transport):
                self.assertEqual({'rcode': 0, 'addresses': ['192.0.2.30']},
                                 helper.query('127.0.0.1', '127.0.0.1', 'mihomo-only.test', transport, 2, port))
        port = self.resolver(rcode=3).port
        self.assertEqual({'rcode': 3, 'addresses': []},
                         helper.query('127.0.0.1', '127.0.0.1', 'mihomo-only.test', 'udp', 2, port))

    def test_a_reply_to_another_query_is_refused(self):
        helper = client_helper()
        port = self.resolver(skew=1).port
        with self.assertRaises(ValueError):
            helper.query('127.0.0.1', '127.0.0.1', 'mihomo-only.test', 'tcp', 2, port)

    def test_requests_and_answers_travel_as_files(self):
        helper = client_helper()
        port = self.resolver().port
        with tempfile.TemporaryDirectory() as directory:
            requests, answers = Path(directory) / 'requests', Path(directory) / 'answers'
            requests.mkdir()
            with mock.patch.object(helper, 'ANSWERS', answers):
                request = requests / '1-2.json'
                request.write_text(json.dumps({'source': '127.0.0.1', 'server': '127.0.0.1', 'port': port,
                                               'name': 'mihomo-only.test', 'transport': 'udp', 'timeout': 2}))
                helper.answer(request)
                self.assertFalse(request.exists())
                self.assertEqual({'rcode': 0, 'addresses': ['192.0.2.30']},
                                 json.loads((answers / '1-2.json').read_text()))
                # Nothing listening is an answer too, not a crash of the helper.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as silent:
                    silent.bind(('127.0.0.1', 0))
                    request.write_text(json.dumps({'source': '127.0.0.1', 'server': '127.0.0.1',
                                                   'port': silent.getsockname()[1], 'name': 'mihomo-only.test',
                                                   'transport': 'tcp', 'timeout': 1}))
                    helper.answer(request)
                self.assertIn('error', json.loads((answers / '1-2.json').read_text()))
                self.assertEqual([], [path.name for path in answers.iterdir() if path.name.startswith('.')])

    def test_the_harness_wires_the_client_lan_and_tears_it_down(self):
        run = (JAIL / 'run.sh').read_text()
        self.assertIn('MIHOMO_JAIL_CLIENT_IF="$epair"', run)
        self.assertIn('ifconfig "$epair" destroy', run)
        self.assertIn('cp "$TEST_DIR/dns-client.py" "$JAIL_ROOT/root/dns-client.py"', run)
        # The client jail goes before the router jail whose devfs it shares.
        self.assertLess(run.index('jail -r "$client_name"'), run.index('jail -r "$jail_name"'))
        self.assertLess(run.index('jail -r "$jail_name"'), run.index('ifconfig "$epair" destroy'))
        adapter = (JAIL / 'configctl').read_text()
        self.assertIn("rules = ['set skip on lo0', 'rdr-anchor \"mihomo\" all', 'anchor \"mihomo\" all']", adapter)
        self.assertIn('sockstat', (JAIL / 'prepare.sh').read_text())


if __name__ == '__main__':
    unittest.main()
