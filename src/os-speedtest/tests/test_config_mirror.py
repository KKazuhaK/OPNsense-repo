"""What a rebuilt box gets back, and what it must never be handed.

The mirror only earns its place if three things hold: the settings an operator
chose come back unchanged, a configuration that is absent, partial or simply
wrong changes nothing, and a mirror that cannot be written is not allowed to
fail the save that produced it. Each of those is checked here against the real
files the package ships.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

PLUGIN = Path(__file__).resolve().parents[1]
SRC = PLUGIN / 'src'
SCRIPT = SRC / 'usr/local/opnsense/scripts/speedtest/config_mirror.py'
SHIM = SRC / 'usr/local/opnsense/scripts/speedtest/config_mirror.php'
MODEL = SRC / 'usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.xml'
API = SRC / 'usr/local/opnsense/scripts/speedtest/api.php'
HOOK = SRC / 'usr/local/etc/rc.syshook.d/start/98-speedtest'
POST_INSTALL = PLUGIN / 'packaging/freebsd/+POST_INSTALL'
IMPORT_COMMAND = 'config_mirror.py import-config'

spec = importlib.util.spec_from_file_location('speedtest_config_mirror', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# A settings.json as the page writes it, with every field set to something
# other than its default so a lost field cannot pass as a default.
CHOSEN = {'interface': 'wan', 'server_id': '16781', 'threads': '8'}

# The stand-in for php: it answers what a test told it to and records what it
# was asked, so the handoff can be exercised without an OPNsense tree.
STUB = '''
import json, os, sys
control = json.load(open(os.environ['SPEEDTEST_STUB']))
with open(control['record'], 'w') as handle:
    json.dump({'argv': sys.argv[1:], 'stdin': sys.stdin.read()}, handle)
sys.stdout.write(control['stdout'])
sys.stderr.write(control.get('stderr', ''))
sys.exit(control['returncode'])
'''


class Rooted(unittest.TestCase):
    """Every test gets its own /var/db/speedtest and nothing else."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        previous = os.environ.get('OS_SPEEDTEST_ROOT')
        os.environ['OS_SPEEDTEST_ROOT'] = str(self.root)
        self.addCleanup(lambda: os.environ.__setitem__('OS_SPEEDTEST_ROOT', previous)
                        if previous is not None else os.environ.pop('OS_SPEEDTEST_ROOT', None))
        self.state = self.root / 'var/db/speedtest'
        self.settings = self.state / 'settings.json'

    def write_settings(self, settings):
        self.state.mkdir(parents=True, exist_ok=True)
        self.settings.write_text(json.dumps(settings))

    def stored(self):
        return json.loads(self.settings.read_text())


class MirrorTests(Rooted):
    def test_a_round_trip_preserves_all_three_fields(self):
        self.write_settings(CHOSEN)
        payload = m.mirror_payload()
        self.assertEqual(CHOSEN, payload)
        # The disk the operator lost: only the configuration survives.
        self.settings.unlink()
        self.assertTrue(m.adopt_payload(payload))
        self.assertEqual(CHOSEN, self.stored())

    def test_only_the_settings_travel_and_the_caches_stay_where_they_are(self):
        self.write_settings(CHOSEN)
        for name in ['result.json', 'progress.json', 'servers-wan.json', 'run.lock']:
            (self.state / name).write_text('{"measured": true}')
        self.assertEqual(sorted(m.FIELDS), sorted(m.mirror_payload()))
        m.adopt_payload(m.mirror_payload())
        # A measurement is not intent; adopting must neither carry nor clear it.
        for name in ['result.json', 'progress.json', 'servers-wan.json', 'run.lock']:
            self.assertTrue((self.state / name).is_file(), name)

    def test_settings_that_were_never_written_mirror_as_the_page_would_show_them(self):
        self.assertEqual(m.DEFAULTS, m.mirror_payload())
        self.write_settings('this is not an object')
        self.assertEqual(m.DEFAULTS, m.mirror_payload())
        self.settings.write_text('{ truncated half way')
        self.assertEqual(m.DEFAULTS, m.mirror_payload())

    def test_a_value_the_page_would_refuse_never_reaches_the_configuration(self):
        self.write_settings({'interface': 'wan; rm -rf /', 'server_id': 'not-a-server', 'threads': '99'})
        self.assertEqual(m.DEFAULTS, m.mirror_payload())


class AdoptTests(Rooted):
    def test_a_missing_section_adopts_without_raising(self):
        self.assertFalse(m.adopt_payload({}))
        self.assertFalse(self.settings.exists())
        # Whatever the shim could not parse arrives as something that is not a
        # section at all; that is still not an error worth a traceback.
        for absent in [None, [], 'nothing', 0]:
            self.assertFalse(m.adopt_payload(absent))
        self.assertFalse(self.settings.exists())

    def test_a_partial_section_moves_only_what_it_carries(self):
        self.write_settings(CHOSEN)
        self.assertTrue(m.adopt_payload({'threads': '2'}))
        self.assertEqual(dict(CHOSEN, threads='2'), self.stored())

    def test_a_section_this_version_would_refuse_leaves_the_disk_alone(self):
        self.write_settings(CHOSEN)
        for refused in [{'threads': '0'}, {'threads': '17'}, {'threads': ''},
                        {'interface': 'wan lan'}, {'server_id': 'sixteen'},
                        {'interface': None}, {'threads': True}]:
            self.assertFalse(m.adopt_payload(refused), refused)
        self.assertEqual(CHOSEN, self.stored())

    def test_a_field_a_later_version_added_is_ignored_rather_than_written(self):
        self.write_settings(CHOSEN)
        self.assertFalse(m.adopt_payload(dict(CHOSEN, protocol='quic', transparent_consent='1')))
        self.assertEqual(CHOSEN, self.stored())
        self.assertEqual(sorted(m.FIELDS), sorted(self.stored()))

    def test_adopting_twice_changes_nothing_the_second_time(self):
        self.assertTrue(m.adopt_payload(CHOSEN))
        first = self.settings.read_bytes()
        for _ in range(3):
            self.assertFalse(m.adopt_payload(CHOSEN))
            self.assertEqual(first, self.settings.read_bytes())

    def test_the_file_it_writes_is_the_one_the_page_reads(self):
        m.adopt_payload(CHOSEN)
        self.assertEqual(0o600, stat.S_IMODE(self.settings.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(self.state.stat().st_mode))
        self.assertEqual(CHOSEN, json.loads(self.settings.read_text()))
        # No half-written temporary is left where the page could read it.
        self.assertEqual(['settings.json'], sorted(p.name for p in self.state.iterdir()))


class HandoffTests(Rooted):
    """The two verbs, with the configuration half replaced by a stand-in."""

    def setUp(self):
        super().setUp()
        stub = self.root / 'stub.py'
        stub.write_text(STUB)
        self.record = self.root / 'record.json'
        self.control = self.root / 'control.json'
        os.environ['SPEEDTEST_STUB'] = str(self.control)
        self.addCleanup(os.environ.pop, 'SPEEDTEST_STUB', None)
        php, shim = m.PHP, m.shim
        m.PHP, m.shim = sys.executable, lambda: str(stub)
        self.addCleanup(lambda: setattr(m, 'PHP', php))
        self.addCleanup(lambda: setattr(m, 'shim', shim))
        self.answer('{}')

    def answer(self, stdout, returncode=0, stderr=''):
        self.control.write_text(json.dumps({'stdout': stdout, 'returncode': returncode,
                                            'stderr': stderr, 'record': str(self.record)}))

    def asked(self):
        return json.loads(self.record.read_text())

    def run_main(self, argv):
        """The command line as a hook runs it: its status and what it said."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = m.main(argv)
        return status, json.loads(out.getvalue() or 'null'), err.getvalue()

    def test_the_export_verb_is_handed_the_whole_payload(self):
        self.write_settings(CHOSEN)
        section = {}
        calls = []
        def native(verb, payload=None):
            calls.append((verb, dict(payload) if payload is not None else None))
            if verb == 'import':
                return dict(section)
            section.update({name: payload[name] for name in m.FIELDS})
            return {'changed': True}
        with patch.object(m, 'run_shim', side_effect=native):
            self.assertEqual({'changed': True}, m.mirror())
        self.assertEqual(['import', 'export', 'import'], [verb for verb, _ in calls])
        payload = calls[1][1]
        self.assertEqual(m.revision_token({}), payload.pop('_expected'))
        self.assertEqual(CHOSEN, payload)

    def test_restore_during_mirror_is_rejected_without_changing_the_restored_xml(self):
        self.write_settings(CHOSEN)
        section = dict(CHOSEN)
        snapshot = m.mirror_payload
        def collect_after_restore():
            section.update(interface='lan', server_id='42')
            return snapshot()
        def native(verb, payload=None):
            if verb == 'import':
                return dict(section)
            if payload.pop('_expected') != m.revision_token(section):
                raise m.MirrorError('The configuration changed before its backup was saved.')
            section.update(payload)
            return {'changed': True}
        with patch.object(m, 'run_shim', side_effect=native), \
                patch.object(m, 'mirror_payload', side_effect=collect_after_restore):
            with self.assertRaises(m.MirrorError):
                m.mirror()
        self.assertEqual('lan', section['interface'])
        self.assertEqual('42', section['server_id'])
        self.assertEqual(CHOSEN, self.stored())

    def test_the_import_verb_adopts_what_the_configuration_carried(self):
        self.answer(json.dumps(CHOSEN))
        self.assertTrue(m.import_config())
        self.assertEqual(['import'], self.asked()['argv'])
        self.assertEqual(CHOSEN, self.stored())
        # Booting again with the same configuration is a no-op, not a rewrite.
        self.assertFalse(m.import_config())

    def test_an_absent_section_imports_as_nothing_at_all(self):
        self.answer('{}')
        self.assertFalse(m.import_config())
        self.assertFalse(self.settings.exists())
        self.assertEqual((0, {'changed': False}), self.run_main(['import-config'])[:2])
        self.assertFalse(self.settings.exists())

    def test_a_shim_that_fails_is_reported_and_leaves_the_settings_alone(self):
        self.write_settings(CHOSEN)
        for stdout, code in [('{"status":"failed","error":"no configuration"}', 1),
                             ('', 1), ('not json at all', 0), ('[]', 0), ('', 0)]:
            self.answer(stdout, code)
            with self.subTest(stdout=stdout, returncode=code):
                if (code, stdout) == (0, ''):
                    # An empty answer from a verb that succeeded is an empty
                    # section, which is the one case that is not a failure.
                    self.assertFalse(m.import_config())
                    continue
                with self.assertRaises(m.MirrorError):
                    m.mirror()
                with self.assertRaises(m.MirrorError):
                    m.import_config()
                # Reported by the command line, never raised through it.
                for verb in ['mirror', 'import-config']:
                    status, said, warned = self.run_main([verb])
                    self.assertEqual(1, status)
                    self.assertFalse(said['changed'])
                    self.assertTrue(said['error'] and warned.strip())
        self.assertEqual(CHOSEN, self.stored())

    def test_a_php_that_is_not_there_is_a_warning_not_a_traceback(self):
        self.write_settings(CHOSEN)
        m.PHP = str(self.root / 'no-such-php')
        with self.assertRaises(m.MirrorError):
            m.mirror()
        self.assertEqual(1, self.run_main(['mirror'])[0])
        self.assertEqual(CHOSEN, self.stored())

    def test_an_unknown_verb_says_so(self):
        for argv in [[], ['restore-everything']]:
            status, said, warned = self.run_main(argv)
            self.assertEqual(2, status)
            self.assertIsNone(said)
            self.assertIn('usage:', warned)

    def test_failed_mirror_keeps_newer_settings_on_boot_and_restore_is_still_detected(self):
        section = dict(CHOSEN)
        self.write_settings(CHOSEN)
        def native(verb, payload=None):
            if verb == 'import':
                return dict(section)
            section.update({name: payload[name] for name in m.FIELDS})
            return {'changed': True}
        with patch.object(m, 'run_shim', side_effect=native):
            m.mirror()
            self.write_settings(dict(CHOSEN, threads='2'))
            with patch.object(m, 'run_shim', side_effect=m.MirrorError('native unavailable')):
                with self.assertRaises(m.MirrorError):
                    m.mirror()
            self.assertFalse(m.import_config())
            self.assertEqual('2', self.stored()['threads'])
            section['threads'] = '12'
            with self.assertRaises(m.MirrorError):
                m.mirror()
            self.assertEqual('12', section['threads'])
            self.assertTrue(m.import_config())
            self.assertEqual('12', self.stored()['threads'])

    def test_erased_settings_store_restores_even_when_persistent_marker_matches(self):
        self.answer(json.dumps(CHOSEN))
        self.assertTrue(m.import_config())
        self.settings.unlink()
        self.assertTrue(m.import_config())
        self.assertEqual(CHOSEN, self.stored())
        marker = Path(m.root() + m.MARKER)
        self.assertEqual(0o600, stat.S_IMODE(marker.stat().st_mode))

    def test_future_scalar_is_preserved_in_actual_applied_revision_and_foreign_readback_is_rejected(self):
        section = dict(CHOSEN, future_scalar='retained')
        self.write_settings(CHOSEN)
        foreign = False
        def native(verb, payload=None):
            if verb == 'import':
                return dict(section)
            section.update({name: payload[name] for name in m.FIELDS})
            if foreign:
                section['threads'] = '12'
            return {'changed': True}
        with patch.object(m, 'run_shim', side_effect=native):
            m.mirror()
            self.assertEqual(m.revision_token(section), m.applied_backup())
            m.mirror()
            self.assertEqual('retained', section['future_scalar'])
            marker = m.applied_backup()
            foreign = True
            with self.assertRaises(m.MirrorError):
                m.mirror()
            self.assertEqual('12', section['threads'])
            self.assertEqual(marker, m.applied_backup())


def php_body(source, name):
    """The body of one PHP function, by counting braces from its signature."""
    start = source.index('function ' + name)
    opened = source.index('{', start)
    depth, index = 0, opened
    while index < len(source):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[opened + 1:index]
        index += 1
    raise AssertionError('unbalanced braces in ' + name)


class SaveFunnelTests(unittest.TestCase):
    """A mirror failure may not become the operator's failure.

    The behaviour is in PHP, where the settings are written, so it is pinned by
    shape rather than by running it: api.php answers every error with
    {"status":"failed"}, so anything the mirror could throw would report a save
    that did happen as one that did not.
    """

    def setUp(self):
        self.source = API.read_text()

    def test_the_mirror_runs_at_the_only_funnel_that_writes_the_settings(self):
        # One writer, and the mirror is the last thing it does, after the
        # rename that makes the new settings the ones the page reads.
        self.assertEqual(1, self.source.count('rename($temporary, SPEEDTEST_SETTINGS)'))
        funnel = php_body(self.source, 'speedtest_save_settings')
        self.assertIn('rename($temporary, SPEEDTEST_SETTINGS)', funnel)
        self.assertTrue(funnel.rstrip().endswith('speedtest_mirror();'), funnel)
        self.assertEqual(1, self.source.count('speedtest_mirror();'))
        # Both mutating actions still reach the settings through that funnel.
        self.assertEqual(1, self.source.count('speedtest_save_settings($settings);'))

    def test_nothing_in_the_mirror_can_escape_into_the_reply(self):
        body = php_body(self.source, 'speedtest_mirror')
        statements = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL).strip()
        self.assertTrue(statements.startswith('try {'), statements)
        self.assertRegex(statements, r'\}\s*catch\s*\(Throwable\s+\$\w+\)\s*\{')
        self.assertTrue(statements.endswith('}'), statements)
        self.assertNotIn('throw', statements)
        # A failure has to leave a trace somewhere the operator can find it.
        self.assertEqual(2, statements.count('log_msg('))
        self.assertIn('LOG_WARNING', statements)

    def test_the_mirror_cannot_hold_the_save_open_for_ever(self):
        body = php_body(self.source, 'speedtest_mirror')
        self.assertRegex(body, r'/bin/timeout\s+\d+\s')
        self.assertIn('escapeshellarg(SPEEDTEST_MIRROR)', body)


class ContractTests(unittest.TestCase):
    def test_the_model_mounts_where_the_shim_looks_for_it(self):
        mount = ET.parse(MODEL).getroot().find('mount').text.strip()
        self.assertEqual('//OPNsense/Speedtest/backup', mount)
        self.assertIn("const SPEEDTEST_SECTION = '%s';" % mount, SHIM.read_text())

    def test_the_section_carries_the_three_settings_and_requires_none_of_them(self):
        model = ET.parse(MODEL).getroot()
        items = [node.tag for node in model.find('items')]
        self.assertEqual(sorted(m.FIELDS), sorted(items))
        self.assertEqual(['TextField'] * len(items),
                         [node.get('type') for node in model.find('items')])
        # A restore that carries half a section still has to load.
        self.assertEqual([], model.findall('.//Required'))
        self.assertTrue(model.find('version').text.strip())

    def test_the_shim_keeps_no_policy_of_its_own(self):
        shim = SHIM.read_text()
        for word in m.FIELDS + ('auto', 'interface', 'threads'):
            self.assertNotIn("'%s'" % word, shim, 'the shim knows what %s means' % word)
        # It also may not write an identical section: a backup rotation is
        # a hundred copies deep, and this runs on every settings save.
        self.assertIn('if ($changed) {', shim)

    def test_both_hooks_replay_the_configuration_onto_a_box_that_missed_it(self):
        self.assertTrue(os.access(HOOK, os.X_OK), 'the boot hook is not executable')
        hook = HOOK.read_text()
        self.assertTrue(hook.startswith('#!/bin/sh\n'))
        self.assertIn(IMPORT_COMMAND, hook)
        self.assertIn(IMPORT_COMMAND, POST_INSTALL.read_text())
        # Neither may fail the boot or the installation it runs from.
        line = [text for text in hook.splitlines() if IMPORT_COMMAND in text][0]
        self.assertTrue(line.endswith('|| true'), line)
        self.assertIn('if /usr/local/bin/python3', POST_INSTALL.read_text())
        self.assertIn('its saved backup was retained.', POST_INSTALL.read_text())


if __name__ == '__main__':
    unittest.main()
