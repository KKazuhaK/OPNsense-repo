"""Execute the complete install hook with real backend and private transport."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class InstallBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='frp-install-backup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = self.root / 'events'
        self.store = self.root / 'stored.json'
        self.store.write_text('{}')
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        TEST_EVENTS=str(self.events), TEST_STORE=str(self.store))
        for command in ['service', 'configctl', 'chmod', 'chown']:
            self.executable('bin/' + command, "import os,sys\nfrom pathlib import Path\n"
                            "with Path(os.environ['TEST_EVENTS']).open('a') as out: out.write(Path(sys.argv[0]).name+' '+' '.join(sys.argv[1:])+'\\n')\n")
        self.executable('bin/install', "import pathlib,sys\na=sys.argv[1:]\n"
                        "assert a[:3]==['-d','-m','0700']\npathlib.Path(a[3]).mkdir(parents=True,exist_ok=True)\n")
        self.executable('usr/local/bin/php', '''import hashlib,json,os,sys
from pathlib import Path
verb=sys.argv[-1]
with Path(os.environ['TEST_EVENTS']).open('a') as out:out.write(verb+'\\n')
store=Path(os.environ['TEST_STORE'])
fields=json.loads(store.read_text())
if verb=='import':
    if os.environ.get('TEST_IMPORT_FAIL'):sys.exit(1)
    print(json.dumps(fields))
else:
    payload=json.load(sys.stdin)
    expected=payload.pop('_expected')
    assert expected==hashlib.sha256(json.dumps(fields,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if os.environ.get('TEST_EXPORT_FAIL'):sys.exit(1)
    fields.update({k:('1' if v else '0') if isinstance(v,bool) else v for k,v in payload.items()})
    store.write_text(json.dumps(fields))
    print('{"changed":true}')
''')
        self.executable('usr/sbin/sysrc', 'raise SystemExit(1)\n')
        python = self.root / 'usr/local/bin/python3'
        python.parent.mkdir(parents=True, exist_ok=True)
        python.symlink_to(sys.executable)
        module = PACKAGE / 'src/usr/local/opnsense/scripts/frp/manage.py'
        source = self.remap(module.read_text()).replace('if os.geteuid() != 0:', 'if False:')
        source = source.replace('arguments = parser.parse_args()',
                                'arguments = parser.parse_args()\n'
                                '    with open(os.environ["TEST_EVENTS"], "a") as out:\n'
                                '        out.write("manage " + arguments.side + " " + arguments.action + "\\n")')
        # All paths and subprocesses are private; the real privilege gate is
        # independently covered by the backend suite.
        self.write('usr/local/opnsense/scripts/frp/manage.py', source)
        self.write('usr/local/opnsense/scripts/frp/config_mirror.php', 'private transport')
        for side in ['frps', 'frpc']:
            self.write('usr/local/etc/frp/' + side + '.toml', '[auth]\ntoken="legacy-private-' + side + '"\n')
            self.write('etc/rc.conf.d/' + side, side + '_enable="NO"\n')
        self.hook = self.remap((PACKAGE / 'packaging/freebsd/+POST_INSTALL').read_text())

    def remap(self, source):
        return re.sub(r'/(?:usr/local|usr/sbin|var|etc|tmp)/', lambda m: str(self.root) + m.group(), source)

    def write(self, name, source):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        target.chmod(0o600)
        return target

    def executable(self, name, source):
        target = self.write(name, '#!' + sys.executable + '\n' + source)
        target.chmod(0o755)

    def run_hook(self, **environment):
        return subprocess.run(['sh', '-c', self.hook], env=dict(self.env, **environment),
                              capture_output=True, text=True, timeout=15)

    def calls(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def test_legacy_files_without_xml_are_enrolled_without_enabling_or_restarting_daemons(self):
        restart = self.write('var/db/os-frp/frps.restart', 'outgoing restart marker')
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = json.loads(self.store.read_text())
        for side in ['frps', 'frpc']:
            self.assertIn('legacy-private-' + side, fields[side + '_toml'])
            self.assertEqual('0', fields[side + '_enable'])
            self.assertEqual(side + '_enable="NO"\n', (self.root / 'etc/rc.conf.d' / side).read_text())
        self.assertIn('export', self.calls())
        self.assertFalse(restart.exists())
        self.assertFalse(any(re.search(r'service frp[sc] ', call) for call in self.calls()))
        self.assertFalse(any(re.search(r'manage frp[sc] (start|restart)', call) for call in self.calls()))

    def test_structured_import_warning_or_transport_failure_never_exports_over_saved_xml(self):
        for fields, environment in [({'frps_toml': '[auth]\ntoken="__KEEP__"\n'}, {}),
                                    ({'frps_toml': 'saved-private-configuration'}, {'TEST_IMPORT_FAIL': '1'})]:
            with self.subTest(environment=environment):
                self.events.write_text('')
                self.store.write_text(json.dumps(fields))
                before = self.store.read_bytes()
                result = self.run_hook(**environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('saved backup was retained', result.stderr)
                self.assertNotIn('export', self.calls())
                self.assertEqual(self.store.read_bytes(), before)

    def test_export_failure_warns_and_finishes_install_without_losing_legacy_files(self):
        result = self.run_hook(TEST_EXPORT_FAIL='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('backup could not be updated', result.stderr)
        self.assertEqual(json.loads(self.store.read_text()), {})
        self.assertIn('legacy-private-frps', (self.root / 'usr/local/etc/frp/frps.toml').read_text())
