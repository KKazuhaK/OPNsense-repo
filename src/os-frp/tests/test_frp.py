"""Hold the frp backend and its page to the contract the other parts were given.

Both daemons default --strict_config to true, so an unknown key, a value TOML
cannot express and a credential written back as its own placeholder are all the
same event: exit(1) at the next restart, with the tunnel down and nothing on the
page to say why. These tests therefore ask what actually reaches
/usr/local/etc/frp and what configd actually reads back, rather than what the
backend meant to produce.

The backend was written against this contract rather than before these tests, so
the only name they reach for directly is the TOML emitter, resolved once in
entry(). Everything else goes through main() exactly as configd does, or is
addressed by the documented runtime paths and the configd verbs.
"""
import ast
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ElementTree
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'src/usr/local/opnsense/scripts/frp/manage.py'
VIEWS = ROOT / 'src/usr/local/opnsense/mvc/app/views/OPNsense/Frp'
# One page per daemon, and the script they share. The side a page drives is
# rendered into that shared script, so a page's whole behaviour is its own file
# plus common.volt and nothing else.
COMMON = VIEWS / 'common.volt'
PAGES = {'frps': VIEWS / 'server.volt', 'frpc': VIEWS / 'client.volt'}
MENU = ROOT / 'src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Menu/Menu.xml'
ACL = ROOT / 'src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/ACL/ACL.xml'
CONTROLLER_DIR = ROOT / 'src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp'
ACTIONS = {side: ROOT / ('src/usr/local/opnsense/service/conf/actions.d/actions_%s.conf' % side)
           for side in ('frps', 'frpc')}

# The verbs both command groups expose, and whether each one takes an argument.
# An action whose type is parameters:%s receives a file path; one without takes
# nothing, and calling it through configdpRun sends the path nowhere.
VERBS = {'start': False, 'stop': False, 'restart': False, 'status': False,
         'settings': False, 'set-settings': True, 'verify': True, 'log': False}
KEEP = '__KEEP__'

spec = importlib.util.spec_from_file_location('frp_manage', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# Taken before anything is patched: a test that sets itself up twice must rebase
# the paths the module shipped with, not the ones the previous root left behind.
CONSTANTS = {name: value for name, value in vars(m).items() if name.isupper()}


def entry(*names):
    """The backend's own name for something these tests must call directly.

    The spelling may differ between the parts; the behaviour may not. Anything
    reachable through the CLI is reached through the CLI instead, so this list
    stays at one member.
    """
    for name in names:
        found = getattr(m, name, None)
        if found is not None:
            return found
    raise AssertionError('manage.py exposes none of: ' + ', '.join(names))


def render(data):
    """The TOML emitter. What it writes is the whole of what the daemon parses."""
    return entry('render', 'render_toml', 'dump_toml', 'to_toml', 'emit')(data)


# A refusal is a refusal whichever of these the backend raises; what matters is
# that it is not a file the daemon will reject on the next restart.
REFUSALS = tuple(kind for kind in (getattr(m, 'Error', None), ValueError, TypeError)
                 if isinstance(kind, type) and issubclass(kind, BaseException))

# Every key below is a v0.71.0 json: tag, character for character. A key spelled
# any other way is a daemon that exits instead of starting, so these fixtures
# are also the spelling reference for the rest of the plugin.
FRPS_TOML = '''\
bindAddr = "0.0.0.0"
bindPort = 7000
allowPorts = [{ start = 20000, end = 20100 }, { single = 22022 }]

[auth]
method = "token"
token = "server-token"

[webServer]
addr = "127.0.0.1"
port = 7500
user = "panel"
password = "panel-password"

[transport.tls]
force = true

[log]
level = "info"
maxDays = 3
'''

FRPC_TOML = '''\
serverAddr = "198.51.100.10"
serverPort = 7000
loginFailExit = false

[auth]
method = "token"
token = "client-token"

[transport.tls]
enable = true

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "db"
type = "stcp"
secretKey = "shared-secret"
localIP = "192.168.8.20"
localPort = 3306

[[proxies]]
name = "site"
type = "http"
localIP = "192.168.8.30"
localPort = 8080
customDomains = ["gw.example.invalid"]

[[proxies]]
name = "egress"
type = "tcp"
remotePort = 6090

[proxies.plugin]
type = "http_proxy"
httpUser = "gateway"
httpPassword = "plugin-password"
'''

FRPS = tomllib.loads(FRPS_TOML)
FRPC = tomllib.loads(FRPC_TOML)
SECRETS = ('server-token', 'panel-password', 'client-token', 'shared-secret', 'plugin-password')


class Output(str):
    """Output a caller may read as text or decode as bytes, since both are used."""

    def decode(self, *args, **kwargs):
        return str(self)


class User:
    """pwd.getpwnam('www') on a router; this machine has no such user."""

    def __init__(self, uid):
        self.pw_uid = self.pw_gid = uid
        self.pw_name = 'www'


def rebase(value, root):
    """Move an absolute path -- wherever the module keeps it -- under root."""
    if isinstance(value, Path):
        return Path(rebase(str(value), root))
    if isinstance(value, str):
        return str(root) + value if value.startswith('/') else value
    if isinstance(value, dict):
        return {key: rebase(item, root) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(rebase(item, root) for item in value)
    return value


def leaves(value):
    for item in (value.values() if isinstance(value, dict)
                 else value if isinstance(value, (list, tuple)) else [value]):
        if isinstance(item, (dict, list, tuple)):
            yield from leaves(item)
        elif isinstance(item, (str, Path)):
            yield str(item)


class BackendCase(unittest.TestCase):
    """Drive manage.py the way configd does, against a router that is not here.

    Every absolute path the module holds is moved under a temporary root: these
    tests write configuration files, and the real ones belong to the router.
    Rebasing the module's own constants keeps the harness from having to know
    what they are called, and PathDisciplineTests keeps them constants.
    """

    start_code = 0
    verify_code = 0

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.folder = self.root / 'usr/local/etc/frp'
        for name in ('usr/local/etc/frp', 'usr/local/etc/rc.d', 'usr/local/sbin',
                     'etc/rc.conf.d', 'var/run', 'var/log', 'var/db/os-frp', 'tmp'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        # The package installs both daemons and both rc scripts; a backend that
        # checks before it acts is right to, so the temporary router has them.
        for side in ('frps', 'frpc'):
            for name in ('usr/local/sbin/' + side, 'usr/local/etc/rc.d/' + side):
                (self.root / name).write_text('#!/bin/sh\nexit 0\n')
                (self.root / name).chmod(0o755)
        for name, value in CONSTANTS.items():
            self.repoint(name, value)
        self.commands = []
        self.running = set()
        self.override(getattr(m, 'subprocess', subprocess), 'run', self.record)
        # A test user cannot chown to root:wheel, and 'www' is a user the router
        # has and this machine may not. Neither is what any test is about.
        if hasattr(m, 'os'):
            self.override(m.os, 'chown', lambda *args, **kwargs: None)
            self.override(m.os, 'geteuid', lambda: 0)
        if hasattr(m, 'pwd'):
            self.override(m.pwd, 'getpwnam', lambda name: User(os.getuid()))
        # Waiting for a daemon that will never come up is a real wait, and this
        # suite would spend it on every run. Here the clock moves when it sleeps.
        if hasattr(m, 'time'):
            self.clock = [0.0]
            self.override(m.time, 'monotonic', lambda: self.clock[0])
            self.override(m.time, 'sleep', lambda seconds: self.clock.__setitem__(0, self.clock[0] + seconds))

    def override(self, target, name, value):
        patcher = patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def repoint(self, name, value):
        moved = rebase(value, self.root)
        if moved == value:
            return
        self.override(m, name, moved)
        for path in leaves(moved):
            if path.startswith(str(self.root)):
                Path(path).parent.mkdir(parents=True, exist_ok=True)

    def record(self, arguments, *args, **kwargs):
        """Just enough of an rc script that a start looks like a start."""
        argv = [str(part) for part in arguments] if not isinstance(arguments, str) else [arguments]
        self.commands.append(argv)
        side = 'frpc' if 'frpc' in ' '.join(argv) else 'frps'
        words = set(argv) | {Path(part).name for part in argv}
        if 'verify' in words:
            return self.answer(argv, self.verify_code)
        if words & {'start', 'onestart', 'faststart', 'restart', 'onerestart'}:
            if not self.start_code:
                self.running.add(side)
            return self.answer(argv, self.start_code)
        if words & {'stop', 'onestop'}:
            self.running.discard(side)
            return self.answer(argv, 0)
        if words & {'status', 'onestatus', 'pgrep'}:
            return self.answer(argv, 0 if side in self.running else 1)
        return self.answer(argv, 0)

    def answer(self, argv, code):
        return subprocess.CompletedProcess(argv, code, Output(''), Output(''))

    def ran(self, *words):
        """Whether any command carried all of these, by whole argument."""
        return any(set(words) <= (set(argv) | {Path(part).name for part in argv})
                   for argv in self.commands)

    def cli(self, *argv):
        """Exactly what configd runs, and exactly what the controller reads."""
        stream = io.StringIO()
        with patch.object(sys, 'argv', ['manage.py', '--json', *argv]), redirect_stdout(stream):
            status = m.main()
        self.assertIn(status, (0, None),
                      'the envelope carries the failure, so both answers exit 0')
        printed = stream.getvalue().strip()
        try:
            answer = json.loads(printed)
        except ValueError:
            raise AssertionError('configd reads one JSON object, not %r' % printed)
        self.assertIsInstance(answer.get('ok'), bool, printed)
        return answer

    def ok(self, *argv):
        answer = self.cli(*argv)
        self.assertTrue(answer['ok'], answer.get('error'))
        return answer.get('result')

    def refused(self, *argv):
        answer = self.cli(*argv)
        self.assertFalse(answer['ok'], answer.get('result'))
        self.assertTrue(str(answer.get('error', '')).strip(), 'a refusal has to say why')
        return str(answer['error'])

    def live(self, side):
        return self.folder / (side + '.toml')

    def install(self, side, text):
        path = self.live(side)
        path.write_text(text)
        path.chmod(0o600)
        return path

    def stage(self, payload, name=None):
        """The controller's private hand-off file: configd passes the path.

        Private, in /tmp, named for this plugin: a backend that checks the file
        it is handed is checking against the controller, so the harness stages
        one the same way the controller does.
        """
        folder = self.root / 'tmp'
        path = folder / (name or 'frp_api_%d.json' % len(list(folder.iterdir())))
        path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
        path.chmod(0o600)
        return str(path)

    def document(self, answer):
        """The settings document, whatever envelope the backend puts round it.

        The contract fixes the document, not the envelope: the page also wants
        the raw TOML and the guard list beside it. Where there is an envelope
        the document is under 'config', and the TOML has to say the same thing.
        """
        self.assertIsInstance(answer, dict)
        if isinstance(answer.get('config'), dict):
            if isinstance(answer.get('toml'), str):
                self.assertEqual(answer['config'], tomllib.loads(answer['toml']),
                                 'the TOML beside the document has to be that document')
            return answer['config']
        return answer

    def unchanged(self, side, *argv):
        """Run a verb that must refuse, and prove the live file survived it."""
        before = self.live(side).read_bytes()
        listing = sorted(p.name for p in self.folder.iterdir())
        error = self.refused(*argv)
        self.assertEqual(before, self.live(side).read_bytes(),
                         'a refused candidate replaced the running configuration')
        self.assertEqual(listing, sorted(p.name for p in self.folder.iterdir()),
                         'a refused candidate left a file behind')
        return error


class TomlEmitterTests(unittest.TestCase):
    """The emitter is the whole interface to two strict parsers."""

    def reparsed(self, document):
        text = render(document)
        self.assertIsInstance(text, str)
        return tomllib.loads(text)

    def test_a_server_document_comes_back_exactly_as_it_went_in(self):
        self.assertEqual(FRPS, self.reparsed(FRPS))

    def test_a_client_document_keeps_its_proxies_whole_and_in_order(self):
        parsed = self.reparsed(FRPC)
        self.assertEqual(FRPC, parsed)
        # Order is meaning here: two proxies may claim the same remote port and
        # the server takes the first, so a re-ordered array is a moved service.
        self.assertEqual(['ssh', 'db', 'site', 'egress'], [p['name'] for p in parsed['proxies']])
        # A table inside an array of tables is the shape a flat emitter loses.
        self.assertEqual({'type': 'http_proxy', 'httpUser': 'gateway',
                          'httpPassword': 'plugin-password'}, parsed['proxies'][3]['plugin'])
        self.assertEqual(['gw.example.invalid'], parsed['proxies'][2]['customDomains'])

    def test_the_port_allowance_stays_a_list_of_ranges(self):
        # allowPorts is the one array of tables on the server side; flattened to
        # a string or to a single table it stops restricting anything.
        self.assertEqual([{'start': 20000, 'end': 20100}, {'single': 22022}],
                         self.reparsed(FRPS)['allowPorts'])

    def test_a_top_level_key_stated_after_a_table_stays_top_level(self):
        # Insertion order is not emission order in TOML: bindPort written after
        # [auth] is auth.bindPort, which is an unknown key and a dead daemon.
        # The browser sends whatever order the form built, so this is reachable.
        document = {'auth': {'token': 'x'}, 'bindPort': 7000,
                    'webServer': {'port': 7500}, 'bindAddr': '0.0.0.0'}
        parsed = self.reparsed(document)
        self.assertEqual(document, parsed)
        self.assertNotIn('bindPort', parsed['auth'])
        self.assertNotIn('bindAddr', parsed['webServer'])

    def test_a_sub_table_keeps_its_full_path(self):
        document = {'transport': {'tls': {'enable': True, 'certFile': '/x.crt'},
                                  'poolCount': 5}, 'serverPort': 7000}
        self.assertEqual(document, self.reparsed(document))

    def test_writing_what_was_read_writes_the_same_bytes(self):
        # The page saves documents it was given, over and over. An emitter that
        # is not a fixed point rewrites the file on every save and eventually
        # drifts somewhere the daemon refuses.
        for document in (FRPS, FRPC):
            text = render(document)
            self.assertEqual(text, render(tomllib.loads(text)))

    def test_the_keys_reach_the_file_character_for_character(self):
        # Every key is a Go json: tag. Any normalisation -- case, underscores,
        # dashes -- produces a key no daemon knows.
        text = render(FRPC) + render(FRPS)
        for key in ('serverAddr', 'serverPort', 'loginFailExit', 'localIP', 'localPort',
                    'remotePort', 'customDomains', 'secretKey', 'httpUser', 'httpPassword',
                    'bindAddr', 'bindPort', 'allowPorts', 'webServer', 'maxDays'):
            self.assertIn(key, text, key)

    def test_quotes_and_backslashes_survive_a_round_trip(self):
        document = {'metadatas': {'note': 'a "quoted" \\ value\nsecond line',
                                  'unicode': 'gateway — 家'}}
        self.assertEqual(document, self.reparsed(document))

    def test_a_value_toml_cannot_express_is_refused_rather_than_written(self):
        # None is the reachable one: an empty form field that serialises as null
        # would be written as a bare word, which is a parse error at boot.
        for value in (None, object(), {1, 2}, complex(1, 2), Path('/x')):
            with self.assertRaises(REFUSALS, msg=repr(value)):
                render({'auth': {'token': value}})
        with self.assertRaises(REFUSALS):
            render({'proxies': [{'name': 'ssh', 'localPort': None}]})


REMOVE = object()


def masked(document, *paths):
    """The document as the page is allowed to see it: credentials replaced."""
    result = json.loads(json.dumps(document))
    for path in paths:
        node = result
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = KEEP
    return result


def variant(document, **changes):
    """A copy with dotted paths (written with __) changed or removed."""
    result = json.loads(json.dumps(document))
    for dotted, value in changes.items():
        steps = dotted.split('__')
        node = result
        for step in steps[:-1]:
            node = node.setdefault(step, {})
        if value is REMOVE:
            node.pop(steps[-1], None)
        else:
            node[steps[-1]] = value
    return result


class SettingsTests(BackendCase):
    """The settings are the TOML document, so there is no second schema to drift."""

    SERVER = (('auth', 'token'), ('webServer', 'password'))
    CLIENT = (('auth', 'token'), ('proxies', 1, 'secretKey'), ('proxies', 3, 'plugin', 'httpPassword'))

    def test_the_server_document_arrives_with_its_credentials_masked(self):
        self.install('frps', FRPS_TOML)
        answer = self.ok('frps', 'settings')
        result = self.document(answer)
        self.assertEqual(masked(FRPS, *self.SERVER), result)
        # The user name is not a credential; the form has to be able to show it,
        # and a masked one would be saved back over the real one.
        self.assertEqual('panel', result['webServer']['user'])
        for secret in SECRETS:
            self.assertNotIn(secret, json.dumps(answer), secret)

    def test_the_client_document_masks_every_shared_secret(self):
        self.install('frpc', FRPC_TOML)
        answer = self.ok('frpc', 'settings')
        result = self.document(answer)
        self.assertEqual(masked(FRPC, *self.CLIENT), result)
        self.assertEqual('gateway', result['proxies'][3]['plugin']['httpUser'])
        for secret in SECRETS:
            self.assertNotIn(secret, json.dumps(answer), secret)

    def test_each_side_reads_its_own_file(self):
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        self.assertIn('bindPort', self.document(self.ok('frps', 'settings')))
        self.assertIn('serverAddr', self.document(self.ok('frpc', 'settings')))

    def test_the_masked_document_saved_back_unchanged_changes_nothing(self):
        # This is the commonest save there is: open the page, press Save.
        for side, text, paths in (('frps', FRPS_TOML, self.SERVER), ('frpc', FRPC_TOML, self.CLIENT)):
            self.install(side, text)
            result = self.document(self.ok(side, 'settings'))
            self.assertEqual(masked(tomllib.loads(text), *paths), result)
            self.ok(side, 'set-settings', self.stage(result))
            self.assertEqual(tomllib.loads(text), tomllib.loads(self.live(side).read_text()), side)
            self.assertEqual(0o600, stat.S_IMODE(self.live(side).stat().st_mode), side)

    def test_an_edit_beside_a_credential_keeps_the_credential(self):
        self.install('frps', FRPS_TOML)
        result = self.document(self.ok('frps', 'settings'))
        result['bindPort'] = 7001
        result['webServer']['port'] = 7600
        self.ok('frps', 'set-settings', self.stage(result))
        stored = tomllib.loads(self.live('frps').read_text())
        self.assertEqual('server-token', stored['auth']['token'])
        self.assertEqual('panel-password', stored['webServer']['password'])
        self.assertEqual(7001, stored['bindPort'])
        self.assertEqual(7600, stored['webServer']['port'])

    def test_an_edited_proxy_keeps_the_secret_of_the_proxy_it_belongs_to(self):
        self.install('frpc', FRPC_TOML)
        result = self.document(self.ok('frpc', 'settings'))
        result['proxies'][1]['localPort'] = 5432
        self.ok('frpc', 'set-settings', self.stage(result))
        stored = tomllib.loads(self.live('frpc').read_text())
        self.assertEqual('shared-secret', stored['proxies'][1]['secretKey'])
        self.assertEqual(5432, stored['proxies'][1]['localPort'])
        self.assertEqual('plugin-password', stored['proxies'][3]['plugin']['httpPassword'])

    def test_a_stated_credential_replaces_the_stored_one(self):
        # Otherwise the placeholder is the only value the field can ever hold
        # and no credential can be rotated from the page.
        self.install('frps', FRPS_TOML)
        result = self.document(self.ok('frps', 'settings'))
        result['auth']['token'] = 'rotated-token'
        self.ok('frps', 'set-settings', self.stage(result))
        self.assertEqual('rotated-token', tomllib.loads(self.live('frps').read_text())['auth']['token'])

    def test_a_placeholder_where_nothing_was_stored_is_refused(self):
        # A placeholder is not a value: accepted anywhere it is sent, it becomes
        # a way to copy a credential to a field that will show it back.
        self.install('frps', FRPS_TOML)
        self.unchanged('frps', 'frps', 'set-settings',
                       self.stage(variant(FRPS, bindAddr=KEEP)))
        self.unchanged('frps', 'frps', 'set-settings',
                       self.stage(variant(FRPS, transport__tls__certFile=KEEP)))
        # Nothing was stored under auth at all, so there is nothing to keep.
        self.install('frps', render(variant(FRPS, auth=REMOVE)))
        self.unchanged('frps', 'frps', 'set-settings',
                       self.stage(variant(FRPS, auth__token=KEEP)))
        # A user with no password stored is the same case one level down.
        self.install('frps', render(variant(FRPS, webServer__password=REMOVE)))
        self.unchanged('frps', 'frps', 'set-settings',
                       self.stage(variant(FRPS, webServer__password=KEEP)))

    def test_a_new_proxy_cannot_inherit_another_proxy_s_secret(self):
        self.install('frpc', FRPC_TOML)
        result = self.document(self.ok('frpc', 'settings'))
        result['proxies'].append({'name': 'new', 'type': 'stcp', 'secretKey': KEEP,
                                  'localIP': '127.0.0.1', 'localPort': 9000})
        self.unchanged('frpc', 'frpc', 'set-settings', self.stage(result))


class CandidateTests(BackendCase):
    """A candidate the backend will not write must never reach the live file."""

    def setUp(self):
        super().setUp()
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)

    def test_a_candidate_that_cannot_be_written_never_replaces_the_live_file(self):
        # The live file is what the running daemon reloads and what the next
        # boot reads. A half-written or rejected candidate landing there is the
        # tunnel down until somebody with a console fixes it by hand.
        for candidate in (variant(FRPS, bindAddr=None),
                          variant(FRPS, webServer__port=None),
                          variant(FRPS, auth__token=KEEP, webServer__password=KEEP,
                                  log__level=KEEP),
                          ['not', 'a', 'document'],
                          'not a document either'):
            self.unchanged('frps', 'frps', 'set-settings', self.stage(candidate))

    def test_a_hand_off_that_is_not_there_or_not_json_is_an_error_not_a_crash(self):
        self.unchanged('frps', 'frps', 'set-settings', str(self.root / 'tmp/frp_absent.json'))
        self.unchanged('frps', 'frps', 'set-settings',
                       self.stage('{"bindPort": 7000,', 'frp_broken.json'))

    def test_verify_asks_the_daemon_about_the_candidate_and_writes_nothing(self):
        before = self.live('frps').read_bytes()
        staged = self.stage(self.document(self.ok('frps', 'settings')))
        self.ok('frps', 'verify', staged)
        self.assertTrue(self.ran('verify'), 'verify has to ask the daemon: %s' % self.commands)
        self.assertFalse(any(str(self.live('frps')) in argv for argv in self.commands),
                         'verify must check the candidate, not the running file')
        self.assertEqual(before, self.live('frps').read_bytes())
        # A rejection may arrive as a refusal or as a verdict beside the answer,
        # but it may not arrive as silence, and it may not write anything.
        self.verify_code = 1
        answer = self.cli('frps', 'verify', staged)
        self.assertFalse(answer['ok'] and answer.get('result', {}).get('valid', False),
                         'a rejected candidate reported as acceptable: %s' % answer)
        self.assertEqual(before, self.live('frps').read_bytes())

    def test_a_candidate_the_daemon_rejects_is_reported_rather_than_installed(self):
        # strict_config turns an accepted-but-wrong file into a daemon that
        # exits at the next restart, so the daemon itself is the last check.
        self.verify_code = 1
        self.unchanged('frps', 'frps', 'set-settings',
                       self.stage(self.document(self.ok('frps', 'settings'))))


class RequiredFieldTests(BackendCase):
    """The three fields whose absence is a hole rather than a default.

    An empty auth.token authenticates every client that sends an empty one; an
    empty webServer user and password bypass the admin API's auth middleware
    entirely, and that API can delete proxies; an unset allowPorts lets any
    client that gets in bind any remote port on the router. None of the three
    has a value this plugin could invent, so each one stops a start instead.
    """

    def reset(self):
        """A fresh router for the next variant; the patches stack and unwind."""
        self.setUp()

    def install_server(self, **changes):
        return self.install('frps', render(variant(FRPS, **changes)))

    def assertNames(self, error, field):
        tail = field.split('.')[-1]
        self.assertTrue(field in error or re.search(r'\b%s\b' % tail, error, re.I),
                        'the refusal has to name %s, not just fail: %r' % (field, error))

    def assertNothingStarted(self):
        self.assertEqual(set(), self.running, self.commands)
        # And nothing may be left set to come up on the next reboot either.
        self.assertFalse(any('enable' in part.lower() and 'YES' in part
                             for argv in self.commands for part in argv), self.commands)

    def test_a_start_without_an_authentication_token_is_refused(self):
        for changes in ({'auth': REMOVE}, {'auth__token': REMOVE}, {'auth__token': ''}):
            self.reset()
            self.install_server(**changes)
            self.assertNames(self.refused('frps', 'start'), 'auth.token')
            self.assertNothingStarted()

    def test_a_start_without_panel_credentials_is_refused(self):
        # The hazard is a bound port with no credentials on it, so each of these
        # states webServer.port; a configuration that binds no port at all is
        # serving no admin API and is not this case.
        for changes in ({'webServer__user': '', 'webServer__password': ''},
                        {'webServer__password': ''},
                        {'webServer__user': ''},
                        {'webServer__password': REMOVE}):
            self.reset()
            self.install_server(**changes)
            error = self.refused('frps', 'start')
            self.assertTrue(re.search(r'webServer|password|user', error, re.I),
                            'the refusal has to name the panel credentials: %r' % error)
            self.assertNothingStarted()

    def test_a_start_without_a_port_allowance_is_refused(self):
        # Unset means every port, so an empty list is the same statement made
        # twice rather than a deliberate allowance of nothing.
        for changes in ({'allowPorts': REMOVE}, {'allowPorts': []}):
            self.reset()
            self.install_server(**changes)
            self.assertNames(self.refused('frps', 'start'), 'allowPorts')
            self.assertNothingStarted()

    def test_a_restart_is_held_to_the_same_three_fields(self):
        # Otherwise the page offers a way around the check that starts the
        # daemon just the same.
        self.install_server(auth__token='')
        self.refused('frps', 'restart')
        self.assertNothingStarted()

    def test_a_complete_server_document_starts(self):
        # Without this the checks above are satisfied by a backend that refuses
        # every start for any reason at all.
        self.install('frps', FRPS_TOML)
        self.ok('frps', 'start')
        self.assertIn('frps', self.running, self.commands)

    def test_the_client_is_not_held_to_the_server_s_rules(self):
        # None of the three is a client field: a client with no token is a
        # client that fails to log in, not a router anyone can reach.
        self.install('frpc', FRPC_TOML)
        self.ok('frpc', 'start')
        self.assertIn('frpc', self.running, self.commands)
        self.reset()
        self.install('frpc', render({'serverAddr': '198.51.100.10', 'serverPort': 7000}))
        self.ok('frpc', 'start')
        self.assertIn('frpc', self.running, self.commands)

    def test_one_side_refusing_says_nothing_about_the_other(self):
        self.install_server(auth__token='')
        self.install('frpc', FRPC_TOML)
        self.refused('frps', 'start')
        self.ok('frpc', 'start')
        self.assertEqual({'frpc'}, self.running)


class EnvelopeTests(BackendCase):
    """configd reads one JSON object per call, for every verb and both sides."""

    def setUp(self):
        super().setUp()
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)

    def test_every_argument_less_verb_answers_for_both_sides(self):
        for side in ('frps', 'frpc'):
            for verb in ('status', 'settings', 'log', 'start', 'restart', 'stop'):
                answer = self.cli(side, verb)
                self.assertTrue(answer['ok'], '%s %s: %s' % (side, verb, answer.get('error')))

    def test_the_status_verb_says_whether_the_daemon_is_running(self):
        status = self.ok('frps', 'status')
        self.assertIsInstance(status, dict)
        self.assertIn('running', status)
        self.assertIs(False, bool(status['running']))
        self.ok('frps', 'start')
        self.assertIs(True, bool(self.ok('frps', 'status')['running']))

    def test_the_log_verb_reads_the_log_the_package_installs(self):
        (self.root / 'var/log/frps.log').write_text('first line\nlast line\n')
        self.assertIn('last line', json.dumps(self.ok('frps', 'log')))

    def test_a_daemon_that_does_not_come_up_is_not_reported_as_started(self):
        # An rc script can answer success and leave nothing behind, and a page
        # that believes it shows a tunnel that is not there.
        self.start_code = 1
        self.refused('frps', 'start')
        self.assertNotIn('frps', self.running)

    def test_an_unknown_verb_or_side_is_an_answer_and_not_a_traceback(self):
        for argv in (('frps', 'nonsense'), ('nonsense', 'status'),
                     ('../../etc/passwd', 'settings'), ('frps',), ()):
            try:
                answer = self.cli(*argv)
            except SystemExit as refusal:
                # The parser refusing the argument is an answer too, as long as
                # it is a refusal: a zero exit would read as success.
                self.assertNotEqual(0, refusal.code, argv)
                continue
            self.assertFalse(answer['ok'], argv)

    def test_the_envelope_carries_no_credential_from_a_failure(self):
        # A parser error quoting the line it failed on is a token in the page.
        broken = self.root / 'tmp/broken.json'
        broken.write_text(json.dumps({'auth': {'token': 'leaked-token'}, 'bindPort': None}))
        broken.chmod(0o600)
        answer = self.cli('frps', 'set-settings', str(broken))
        self.assertFalse(answer['ok'])
        self.assertNotIn('leaked-token', json.dumps(answer))


class PathDisciplineTests(unittest.TestCase):
    """Where the backend keeps the paths it writes to."""

    RUNTIME = ('/usr/local/etc/frp', '/usr/local/etc/rc.d', '/etc/rc.conf.d',
               '/var/run', '/var/log', '/var/db', '/usr/local/sbin/frp')

    def test_every_runtime_path_is_a_module_constant(self):
        # A path built inside a function cannot be pointed anywhere else, so the
        # tests above would have to write to the router's own files to run at
        # all -- and a packaging change would have nowhere single to land.
        tree = ast.parse(SCRIPT.read_text())
        literals = {id(node.value) for node in ast.walk(tree)
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)}
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(node):
                    if (isinstance(inner, ast.Constant) and isinstance(inner.value, str)
                            and inner.value.startswith(self.RUNTIME) and id(inner) not in literals):
                        found.add('%s: %s' % (node.name, inner.value))
        self.assertEqual([], sorted(found))


def actions_of(side):
    """Which actions the group defines, and which of them take an argument."""
    text = ACTIONS[side].read_text()
    return {name: ('parameters:%s' in body, body)
            for name, body in re.findall(r'\[([a-z-]+)\]\n(.*?)(?=\n\[|\Z)', text, re.S)}


def controllers():
    return sorted(CONTROLLER_DIR.rglob('*.php')) if CONTROLLER_DIR.is_dir() else []


class ConfigdContractTests(unittest.TestCase):
    """Two command groups, the same verbs, the side stated in the command."""

    def test_both_groups_exist_and_expose_the_same_verbs(self):
        for side in ACTIONS:
            self.assertTrue(ACTIONS[side].is_file(), ACTIONS[side])
            self.assertEqual(sorted(VERBS), sorted(actions_of(side)), side)

    def test_only_the_two_verbs_that_take_a_file_declare_a_parameter(self):
        # An action without parameters:%s drops the path it is handed, so the
        # backend reads its argument as None and saves an empty document; an
        # action with one that is called through configdRun never gets a path.
        for side in ACTIONS:
            for verb, (takes, body) in actions_of(side).items():
                self.assertEqual(VERBS[verb], takes, '%s %s' % (side, verb))
                self.assertIn('type:script_output', body, '%s %s' % (side, verb))

    def test_each_action_runs_manage_py_for_its_own_side(self):
        # Both files call the same script; the side is the first argument, and a
        # copied-and-edited file that forgot it drives the wrong daemon.
        for side in ACTIONS:
            for verb, (takes, body) in actions_of(side).items():
                command = re.search(r'command:(.*)', body).group(1).strip()
                self.assertIn('/usr/local/opnsense/scripts/frp/manage.py', command, verb)
                self.assertIn('--json', command, verb)
                # configd appends the parameters itself, so the path belongs in
                # parameters:%s and nowhere else; a %s in the command line is
                # passed to the backend as those two characters.
                self.assertEqual(['--json', side, verb], command.split('manage.py', 1)[1].split(),
                                 '%s %s' % (side, verb))


class ControllerTests(unittest.TestCase):
    """The controllers are thin, but each of these has been got wrong before."""

    def setUp(self):
        self.files = controllers()
        self.assertTrue(self.files, 'no controllers found under %s' % CONTROLLER_DIR)

    def test_the_controllers_are_there(self):
        self.assertEqual(['ClientController.php', 'IndexController.php', 'ServerController.php',
                          'ServiceController.php', 'SettingsController.php'],
                         sorted(path.name for path in self.files))

    def test_no_controller_calls_a_phalcon_request_method(self):
        # OPNsense has its own Request. Anything else raises at runtime and
        # reaches the browser as "Unexpected error, check log for details".
        allowed = {'getClientAddress', 'getHeader', 'getJsonRawBody', 'getMethod',
                   'getPost', 'getQuery', 'getRawBody', 'getScheme', 'getURI', 'isPost'}
        for path in self.files:
            for method in re.findall(r'\$this->request->(\w+)\(', path.read_text()):
                self.assertIn(method, allowed, '%s in %s' % (method, path.name))

    def test_every_backend_call_names_an_action_that_exists(self):
        for path in self.files:
            text = path.read_text()
            for runner, side, verb in re.findall(r"configd(p?)Run\(\s*'(frps|frpc) ([a-z-]+)'", text):
                self.assertIn(verb, VERBS, '%s in %s' % (verb, path.name))
                self.assertEqual(VERBS[verb], runner == 'p',
                                 '%s %s uses the wrong runner in %s' % (side, verb, path.name))
            for side, verb in re.findall(r"'(frps|frpc) ([a-z-]+)'", text):
                self.assertIn(verb, VERBS, '%s in %s' % (verb, path.name))

    def test_both_daemons_are_driven_from_the_page(self):
        text = ''.join(path.read_text() for path in self.files)
        for side in ACTIONS:
            self.assertIn(side, text, side)

    def test_the_verbs_that_take_a_file_are_only_ever_sent_one(self):
        for path in self.files:
            text = path.read_text()
            for verb in (name for name, takes in VERBS.items() if takes):
                if re.search(r"'(frps|frpc) %s'|'%s'" % (verb, verb), text):
                    self.assertIn('configdpRun', text,
                                  '%s names %s but never passes a path' % (path.name, verb))

    def test_the_argument_is_a_private_file_the_controller_removes(self):
        # configd actions whose type is parameters:%s receive a path, never a
        # value: a token on a command line is a token in the process table, and
        # a staged file left behind after configd fails is one on disk.
        settings = [path for path in self.files if path.name == 'SettingsController.php'][0].read_text()
        staged = re.search(r'(\$\w+)\s*=\s*tempnam\(', settings)
        self.assertIsNotNone(staged, 'the argument has to be staged in a file of its own')
        self.assertRegex(settings, r'chmod\(\s*%s\s*,\s*0600' % re.escape(staged.group(1)),
                         'the staged credentials must not be world readable')
        self.assertRegex(settings, r'configdpRun\(.*?\[\s*\$\w+\s*\]',
                         'the backend is handed a path, never the value')
        self.assertRegex(settings, r'finally\s*\{[^}]*unlink\s*\(\s*@?%s' % re.escape(staged.group(1)),
                         'the staged file must go even when configd fails')



    def test_a_page_per_daemon_is_a_controller_per_daemon(self):
        # OPNsense routes /ui/<module>/<name> to <Name>Controller::indexAction,
        # not to a <name>Action on IndexController. Getting that backwards gives
        # a correct-looking menu whose every entry answers "Page not found",
        # which is exactly what it did. OPNsense's own Network Time is built the
        # way asserted here: Ntpd/StatusController::indexAction picks
        # OPNsense/Ntpd/status.
        by_name = {path.name: path.read_text() for path in self.files}
        for name, view in (('ServerController.php', 'OPNsense/Frp/server'),
                           ('ClientController.php', 'OPNsense/Frp/client')):
            self.assertIn(name, by_name, name)
            text = by_name[name]
            self.assertRegex(text, r'class\s+\w+Controller\s+extends', name)
            self.assertRegex(text, r'function\s+indexAction\s*\(',
                             '%s must answer on indexAction, not a named action' % name)
            self.assertIn("pick('%s')" % view, text, view)
        # An old bookmark on /ui/frp must still land somewhere rather than on an
        # empty shell, so index stays and forwards.
        index = by_name['IndexController.php']
        self.assertRegex(index, r'function\s+indexAction\s*\(')
        self.assertRegex(index, r"redirect\(\s*'/ui/frp/server'")
        self.assertNotIn("pick('OPNsense/Frp/index')", index)

    def test_every_menu_entry_resolves_to_a_controller_and_a_view(self):
        # The property that actually broke: a url in the menu with nothing
        # behind it renders the heading and 404s on the click.
        import xml.etree.ElementTree as ET
        menu = ET.parse(MENU).getroot()
        urls = [node.get('url') for node in menu.iter() if node.get('url')]
        self.assertTrue(urls, 'the menu offers nothing')
        for url in urls:
            parts = [part for part in url.split('/') if part]
            self.assertEqual('ui', parts[0], url)
            self.assertEqual('frp', parts[1], url)
            if len(parts) == 2:
                continue
            controller = CONTROLLER_DIR / (parts[2].capitalize() + 'Controller.php')
            self.assertTrue(controller.exists(), '%s has no %s' % (url, controller.name))
            view = VIEWS / (parts[2] + '.volt')
            self.assertTrue(view.exists(), '%s has no %s' % (url, view.name))


class MenuTests(unittest.TestCase):
    """frp is two daemons, and the menu says so the way OPNsense's own do."""

    def setUp(self):
        self.assertTrue(MENU.is_file(), MENU)
        self.tree = ElementTree.parse(MENU).getroot()

    def test_the_heading_expands_and_carries_no_page_of_its_own(self):
        # This is the whole pattern being copied from Services > Network Time:
        # a parent with a url is a link and swallows its children's place in the
        # menu; a parent without one is a heading that expands.
        parent = self.tree.find('./Services/Frp')
        self.assertIsNotNone(parent, 'no Services > frp heading')
        self.assertIsNone(parent.get('url'), 'the heading must carry no url')
        self.assertEqual('frp', parent.get('VisibleName'))
        self.assertTrue(parent.get('cssClass'), 'the heading needs an icon of its own')

    def test_each_daemon_is_a_child_with_a_url_that_resolves(self):
        parent = self.tree.find('./Services/Frp')
        children = {child.tag: child for child in parent}
        self.assertEqual(['Client', 'Server'], sorted(children))
        self.assertEqual('/ui/frp/server', children['Server'].get('url'))
        self.assertEqual('/ui/frp/client', children['Client'].get('url'))
        for tag, child in children.items():
            self.assertTrue(child.get('VisibleName'), tag)
            self.assertTrue(child.get('order'), tag)
        # A url here is an action on IndexController; a view it cannot pick is a
        # blank page.
        for name in ('server', 'client'):
            self.assertTrue((VIEWS / ('%s.volt' % name)).is_file(), name)

    def test_the_privilege_reaches_both_pages_and_the_url_they_replaced(self):
        # Every url in the menu has to be inside the privilege, or the entry is
        # drawn and then refused. /ui/frp is in it too: it is what the combined
        # page answered on and what indexAction now forwards from, and a pattern
        # ending in /* matches the children but not the parent path itself.
        patterns = [node.text for node in ElementTree.parse(ACL).getroot().iter('pattern')]
        self.assertIn('ui/frp', patterns, 'the old bookmark must reach its own redirect')
        self.assertIn('ui/frp/*', patterns)
        self.assertIn('api/frp/*', patterns, 'the pages are driven entirely from the API')

        def covered(url):
            path = url.lstrip('/')
            return any(re.fullmatch(pattern.replace('*', '.*'), path) for pattern in patterns)

        parent = self.tree.find('./Services/Frp')
        for child in parent:
            self.assertTrue(covered(child.get('url')),
                            '%s is in the menu but outside the privilege' % child.get('url'))
        self.assertTrue(covered('/ui/frp'))


class ViewTests(unittest.TestCase):
    """Two pages, several panes each, three themes, and a framework that escapes.

    Each page is read together with common.volt, because that is what the
    browser is handed: the partial is rendered into the page, so a contract
    about "the script on this page" is a contract about the pair.
    """

    def setUp(self):
        self.assertFalse((VIEWS / 'index.volt').exists(),
                         'the combined page is gone; the two daemons have pages of their own')
        self.assertTrue(COMMON.is_file(), COMMON)
        self.common = COMMON.read_text()
        self.pages = {}
        for side, path in PAGES.items():
            self.assertTrue(path.is_file(), path)
            self.pages[side] = path.read_text()

    def panes_of(self, view):
        found = re.findall(r'<div id="([a-z0-9-]+)" class="tab-pane', view)
        self.assertTrue(found, 'no panes found')
        return found

    def whole(self, side):
        """A page as the browser gets it: its own file with the partial in it."""
        return self.pages[side] + self.common

    def test_each_page_names_its_daemon_and_pulls_in_the_shared_script(self):
        # The side is rendered in rather than chosen at runtime, so a page can
        # only ever reach its own daemon's .toml.
        for side in PAGES:
            view = self.pages[side]
            self.assertRegex(view, r"\{%%\s*set\s+side\s*=\s*'%s'\s*%%\}" % side, side)
            include = re.search(r'partial\(\s*"OPNsense/Frp/common"', view)
            self.assertIsNotNone(include, '%s does not include the shared script' % side)
            # Set first, included after: the other order hands the partial no side.
            self.assertLess(view.index("set side = '%s'" % side), include.start(), side)
        self.assertIn("'{{ side }}'", self.common,
                      'the shared script has to be told which daemon it drives')

    def test_neither_page_carries_the_other_daemon_s_fields(self):
        self.assertNotIn('id="frpc_', self.pages['frps'], 'the server page holds client fields')
        self.assertNotIn('id="frps_', self.pages['frpc'], 'the client page holds server fields')

    def test_tabs_and_panes_agree(self):
        for side in PAGES:
            view = self.pages[side]
            tabs = [re.search(r'href="#([a-z0-9-]+)"', tag) for tag in
                    re.findall(r'<a[^>]*data-toggle="tab"[^>]*>', view)]
            self.assertEqual([tab.group(1) for tab in tabs if tab], self.panes_of(view), side)

    def test_each_page_holds_the_tabs_its_daemon_needs(self):
        # Nothing was lost in the split: the server keeps its settings, its raw
        # document and its log; the client keeps those and the proxy editor.
        self.assertEqual(['status', 'settings', 'advanced', 'log'],
                         self.panes_of(self.pages['frps']))
        self.assertEqual(['status', 'settings', 'proxies', 'advanced', 'log'],
                         self.panes_of(self.pages['frpc']))

    def test_every_pane_sits_at_the_same_depth(self):
        # Comparing the tab list with the pane list says nothing about nesting.
        # One stray closing tag ends the container early and every pane after it
        # renders on whichever tab happens to be open.
        for side in PAGES:
            view = self.pages[side]
            body = view[view.index('<ul class="nav nav-tabs'):]
            self.assertEqual(len(re.findall(r'<div\b', body)), len(re.findall(r'</div>', body)),
                             '%s: the pane markup does not balance' % side)
            depth, depths = 0, []
            for token in re.findall(r'<div\b[^>]*>|</div>', body):
                if token == '</div>':
                    depth -= 1
                else:
                    if 'class="tab-pane' in token:
                        depths.append(depth)
                    depth += 1
            self.assertEqual(1, len(set(depths)), '%s: panes sit at differing depths: %s' % (side, depths))

    def test_every_pane_can_show_its_help(self):
        # The framework scopes the whole-page toggle to the nearest ancestor
        # form whose id starts with frm. With no such form it toggles nothing,
        # silently, and a toggle rendered on one pane reaches no other.
        for side in PAGES:
            view = self.pages[side]
            panes = self.panes_of(view)
            for pane in panes:
                self.assertRegex(view, r'<form[^>]*id="frm%s"' % pane, '%s %s' % (side, pane))
                self.assertIn('show_all_help_%s' % pane, view, '%s %s' % (side, pane))
            self.assertEqual(len(panes), view.count('</form>'), side)
        # They post nowhere, so Enter in a field must not reload the page. The
        # handler is shared, and it reaches both pages' forms by their prefix.
        self.assertRegex(self.common,
                         r"""form\[id\^=["']frm["']\]["']?\s*\)\s*\.on\(\s*["']submit""")

    def test_the_whole_response_is_decoded_once_on_arrival(self):
        # Array responses are HTML-escaped by the framework as an XSS defence,
        # so a value is only intact once decoded. Decoding per element is what
        # shipped a dashboard link whose "&" had become "&amp;"; one wrapper on
        # the way in cannot be forgotten the next time a field is added. The
        # wrapper lives in the shared script, so a page that added a read of its
        # own would show up here as a second one.
        self.assertIn('function decoded(', self.common)
        for side in PAGES:
            whole = self.whole(side)
            self.assertEqual(1, whole.count('ajaxGet('),
                             '%s: every read must go through the one decoding wrapper' % side)
            self.assertEqual(1, whole.count('htmlDecode('),
                             '%s: decoding belongs in the wrapper, not at each element' % side)

    def test_the_shared_script_drives_one_daemon_and_not_a_list_of_them(self):
        # It used to carry both sides at once. On a page that drives one daemon
        # a one-member list is indirection with nothing behind it, and it is the
        # kind of indirection that lets a call reach the wrong .toml.
        self.assertNotIn('SIDES', self.common)
        for verb in ('settings/get/', 'service/status/', 'service/log/'):
            self.assertEqual(1, self.common.count(verb), verb)

    def test_a_pressed_button_reports_that_it_is_working(self):
        # Starting a daemon takes seconds, and without a state of its own the
        # page looks identical throughout.
        self.assertIn('fa-spinner fa-spin', self.common)
        # ajaxCall reports through jQuery's complete, so the button comes back
        # on a failed request as much as a successful one.
        self.assertRegex(self.common, r'ajaxCall\([^)]*,\s*function\s*\(data\)\s*\{\s*\n\s*idle\(button\)')
        for side in PAGES:
            self.assertNotIn('onclick=', self.whole(side),
                             '%s: a button that forwards to another shows its spinner '
                             'on the wrong one' % side)

    def test_ids_are_unique_within_each_page(self):
        # Two pages may reuse an id between them -- they are never loaded at
        # once -- but a repeat inside one page is a field that writes to the
        # wrong box.
        for side in PAGES:
            ids = re.findall(r'id="([^"{]+)"', self.whole(side))
            self.assertEqual([], sorted({name for name in ids if ids.count(name) > 1}), side)

    def test_every_described_field_has_a_box_and_every_box_a_description(self):
        # The field table is what a save reads and writes. A descriptor without
        # a box silently writes undefined over a stored key; a box without a
        # descriptor is a field the operator fills in and the save ignores.
        for side, path in PAGES.items():
            view = self.pages[side]
            described = set(re.findall(r"\{id: '(%s_[a-z_]+)'" % side, view))
            drawn = set(re.findall(r'id="(%s_[a-z_]+)"' % side, view))
            self.assertTrue(described, '%s has no field table' % path.name)
            self.assertEqual(described, drawn, path.name)

    def test_nothing_the_old_single_page_edited_was_dropped(self):
        # Every key of the combined page, named here so the split cannot quietly
        # lose one.
        self.assertEqual({
            'frps_bind_addr', 'frps_bind_port', 'frps_auth_method', 'frps_auth_token',
            'frps_web_addr', 'frps_web_port', 'frps_web_user', 'frps_web_password',
            'frps_vhost_http', 'frps_vhost_https', 'frps_subdomain_host', 'frps_allow_ports',
            'frps_max_ports', 'frps_tls_force', 'frps_tls_cert', 'frps_tls_key', 'frps_tls_ca',
            'frps_log_to', 'frps_log_level', 'frps_log_maxdays',
        }, set(re.findall(r'id="(frps_[a-z_]+)"', self.pages['frps'])))
        self.assertEqual({
            'frpc_server_addr', 'frpc_server_port', 'frpc_user', 'frpc_auth_method',
            'frpc_auth_token', 'frpc_login_fail_exit', 'frpc_protocol', 'frpc_pool_count',
            'frpc_tcp_mux', 'frpc_heartbeat_interval', 'frpc_heartbeat_timeout',
            'frpc_tls_enable', 'frpc_tls_server_name', 'frpc_tls_cert', 'frpc_tls_key',
            'frpc_tls_ca', 'frpc_log_to', 'frpc_log_level', 'frpc_log_maxdays',
        }, set(re.findall(r'id="(frpc_[a-z_]+)"', self.pages['frpc'])))

    def test_each_page_can_start_stop_and_restart_its_own_daemon(self):
        for side in PAGES:
            verbs = set(re.findall(r'class="[^"]*frp-action[^"]*"\s+data-verb="([a-z]+)"',
                                   self.pages[side]))
            self.assertEqual({'start', 'stop', 'restart'}, verbs, side)
        # The side is no longer on the button: the shared script already knows it.
        self.assertRegex(self.common, r"api\.service \+ button\.data\('verb'\) \+ '/' \+ SIDE")

    def test_each_page_edits_its_own_raw_document_and_tails_its_own_log(self):
        for side, path in PAGES.items():
            view = self.pages[side]
            self.assertIn('%s.toml' % side, view, path.name)
            self.assertIn('/var/log/%s.log' % side, view, path.name)
            self.assertRegex(view, r'<textarea id="frp-document"', path.name)
            self.assertIn('id="frp-log"', view, path.name)
            for action in ('frp-document-save', 'frp-document-verify', 'frp-document-reload'):
                self.assertIn(action, view, '%s %s' % (path.name, action))
            self.assertNotIn('%s.toml' % ('frpc' if side == 'frps' else 'frps'), view, path.name)

    def test_the_server_page_says_where_its_dashboard_answers(self):
        # The same listener serves the admin API, which can delete a client's
        # proxies, so whether it is bound and where belongs on Status.
        view = self.pages['frps']
        self.assertIn('id="frp-dashboard"', view)
        self.assertRegex(view, r'function renderDashboard\(')
        self.assertIn('webServer', view)

    def test_a_dependent_warning_reads_a_port_of_zero_as_switched_off(self):
        # frps spells "no dashboard" as webServer.port = 0, and guards() in
        # manage.py agrees: port_of() returns 0 there, so no start is refused
        # over the credentials of a listener that was never bound. A page that
        # read that 0 as a value set would raise a danger alert naming two
        # settings that block nothing, and contradict its own Status tab, which
        # says in the same breath that frps serves no dashboard or admin API.
        self.assertRegex(self.common, r'function off\(')
        guard = self.common[self.common.index('function renderRequired('):]
        guard = guard[:guard.index('box.append(list);')]
        self.assertIn('off(pick(stored, entry.needs))', guard,
                      'the "needs" test has to treat a zero port as switched off')
        self.assertNotIn('blank(pick(stored, entry.needs))', guard)
        # And the dependent settings say what they hang on, rather than warning
        # about a dashboard nobody asked for.
        self.assertRegex(self.pages['frps'], r"needs:\s*'webServer\.port'")

    def test_the_proxy_editor_and_its_warnings_belong_to_the_client(self):
        client, server = self.pages['frpc'], self.pages['frps']
        for mark in ('frp-proxy-rows', 'frp-proxy-add', 'frp-proxy-remove', 'frp-proxy-note',
                     'frp-exposed-rows', 'function exposure('):
            self.assertIn(mark, client, mark)
            self.assertNotIn(mark, server, '%s does not belong on the server page' % mark)

    def test_every_proxy_row_states_what_it_makes_reachable(self):
        # This is the whole risk of the plugin, so it is written in the row
        # rather than in help nobody opens, and it is rewritten whenever the row
        # changes rather than only when the tab is drawn.
        client = self.pages['frpc']
        rendered = client[client.index('function renderProxies('):client.index('function noteFor(')]
        self.assertIn('frp-proxy-note', rendered)
        self.assertIn('exposure(row)', rendered)
        self.assertIn('exposure(proxies[index])', client, 'an edited row must restate its reach')
        self.assertRegex(client, r'noteFor\(index\);')
        # And the saved list says the same thing on Status.
        exposed = client[client.index('function renderExposed('):]
        self.assertIn('exposure(row)', exposed)
        for phrase in ('reachable by anyone who can open', 'reachable by anyone whose',
                       'presents the secret key'):
            self.assertIn(phrase, client, phrase)

    def test_the_pages_declare_no_colour(self):
        # Three themes ship, one of them dark; a declared colour survives none.
        for path in [COMMON] + sorted(PAGES.values()):
            self.assertEqual([], re.findall(r'(?:color|background)\s*:\s*(?:#|rgb)',
                                            path.read_text()), path.name)

    def test_the_raw_document_is_a_fallback_and_not_the_page(self):
        # Raw TOML editing is the advanced escape hatch. If it were the only
        # way in, every key would be hand-typed against a parser that exits on
        # the first typo.
        for side in PAGES:
            panes = self.panes_of(self.pages[side])
            self.assertGreaterEqual(len(panes), 3, '%s: %s' % (side, panes))


if __name__ == '__main__':
    unittest.main()
