"""Hold the configuration mirror to what a restore actually needs from it.

An OPNsense backup is /conf/config.xml. frp keeps its state in two TOML
documents and two rc.conf.d fragments, so until //OPNsense/Frp/backup existed a
restored firewall came back with the shipped samples and both daemons disabled.
These tests therefore ask what a restore would get: the same bytes, including
the authentication token; the boot flags that decide whether frpc dials at all;
and nothing that would put a placeholder, a corrupted character or a daemon
restart where the operator did not ask for one.

The PHP end is stood in for rather than mocked away. What config_mirror.php
does is set model fields and read them back, and the one part of that which can
lose information is the XML leg: the emulation below really serialises to XML
and really parses it back, escaping a carriage return the way libxml2 does, so
a document that would not survive config.xml does not survive this either.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from test_frp import BackendCase, FRPC_TOML, FRPS_TOML, KEEP, ROOT, m

MIRROR = ROOT / 'src/usr/local/opnsense/scripts/frp/config_mirror.php'
MODEL = ROOT / 'src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Backup.xml'
MODEL_CLASS = ROOT / 'src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Backup.php'
BOOT_HOOK = ROOT / 'src/usr/local/etc/rc.syshook.d/start/15-frp'
POST_INSTALL = ROOT / 'packaging/freebsd/+POST_INSTALL'
PLUGIN = ROOT / 'src'

# A document with everything that can be lost on the way through XML: a
# credential, a comment in a script other than Latin, a tab, an indented
# continuation, a CRLF line, and a trailing newline.
AWKWARD_TOML = (
    '# 服务端配置 -- kept verbatim\r\n'
    'bindAddr = "0.0.0.0"\n'
    'bindPort = 7000\n'
    'allowPorts = [{ start = 20000, end = 20100 }]\n'
    '\n'
    '[auth]\n'
    'method = "token"\n'
    'token = "s3cr3t-token-äöü"\t# trailing tab comment\n'
    '\n'
    '[webServer]\n'
    'addr = "127.0.0.1"\n'
    'port = 7500\n'
    'user = "panel"\n'
    'password = "panel-password"\n'
    '\n'
    '[log]\n'
    '  level = "info"\n'
)

FRAGMENT = '''# rc.conf(5) fragment for %(side)s.
%(var)s="%(value)s"
'''


class Section:
    """What //OPNsense/Frp/backup holds, behaving the way the model does.

    The model is the thing that turns a payload into stored text: BooleanField
    normalises anything to 0 or 1, TextField stores what it was given, a field
    the payload does not mention keeps what it had, and a field the model does
    not have is not storage at all. Standing all of that in is what lets these
    tests state a round trip without a router underneath.
    """

    FIELDS = ('frps_toml', 'frpc_toml', 'frps_enable', 'frpc_enable')

    def __init__(self):
        self.document = None

    def exists(self):
        return self.document is not None

    def read(self):
        if self.document is None:
            return {}
        root = ElementTree.fromstring(self.document)
        return {child.tag: (child.text or '') for child in root}

    def write(self, fields):
        root = ElementTree.Element('backup')
        for name in self.FIELDS:
            ElementTree.SubElement(root, name).text = fields.get(name, '')
        # libxml2 escapes a carriage return in a text node rather than letting
        # the parser fold it into a newline; without this the emulation would
        # be kinder to a CRLF document than config.xml is.
        self.document = ElementTree.tostring(root, encoding='unicode').replace('\r', '&#13;')

    def export(self, payload):
        payload = dict(payload)
        if '_expected' in payload:
            expected = payload.pop('_expected')
            current = hashlib.sha256(json.dumps(self.read(), ensure_ascii=True, sort_keys=True,
                                                separators=(',', ':')).encode()).hexdigest()
            if expected != current:
                raise m.Error('The configuration could not be mirrored.')
        stored = self.read() if self.exists() else {name: '' for name in self.FIELDS}
        # A model with no section behind it still hands back BooleanField's own
        # default, which is why "0" and "never mirrored" are told apart by the
        # section existing rather than by any field's value.
        for name in self.FIELDS:
            if name.endswith('_enable') and not self.exists():
                stored[name] = '0'
        before = dict(stored)
        for name, value in payload.items():
            if name not in self.FIELDS:
                continue
            if name.endswith('_enable'):
                stored[name] = '1' if value in (True, 1, '1', 'YES', 'yes') else '0'
            else:
                stored[name] = '' if value is None else str(value)
        changed = not self.exists() or stored != before
        if changed:
            self.write(stored)
        return {'changed': changed}


class MirrorCase(BackendCase):
    """The backend, with the two things it talks to that this machine has not.

    sysrc(8) is emulated against the rebased fragments because the boot flags
    are half of what the mirror carries, and a harness that answered "not
    enabled" to everything would let a broken flag round trip pass.
    """

    def setUp(self):
        super().setUp()
        self.section = Section()
        self.exports = []
        self.imports = 0
        self.shim_code = 0
        self.shim_output = None
        # manage.py refuses to run a mirror it cannot find, so the temporary
        # router gets one where the package would have put it.
        m.MIRROR.parent.mkdir(parents=True, exist_ok=True)
        m.MIRROR.write_text('<?php // stood in for by the harness\n')
        for side in ('frps', 'frpc'):
            self.fragment(side, False)

    def fragment(self, side, enabled, extra=''):
        path = Path(m.SIDES[side]['rcconf'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(FRAGMENT % {'side': side, 'var': m.SIDES[side]['rcvar'],
                                    'value': 'YES' if enabled else 'NO'} + extra)
        return path

    def record(self, arguments, *args, **kwargs):
        argv = [str(part) for part in arguments] if not isinstance(arguments, str) else [arguments]
        if argv and argv[0].endswith('php') and len(argv) > 1 and argv[1].endswith('config_mirror.php'):
            self.commands.append(argv)
            return self.shim(argv, kwargs.get('input'))
        if argv and argv[0].endswith('sysrc'):
            self.commands.append(argv)
            return self.sysrc(argv)
        return super().record(arguments, *args, **kwargs)

    def shim(self, argv, payload):
        if self.shim_code:
            return self.answer(argv, self.shim_code)
        if self.shim_output is not None:
            return self.answer_with(argv, self.shim_output)
        if argv[2] == 'import':
            self.imports += 1
            return self.answer_with(argv, json.dumps(self.section.read()))
        decoded = json.loads(payload)
        self.exports.append(decoded)
        return self.answer_with(argv, json.dumps(self.section.export(decoded)))

    def sysrc(self, argv):
        """Enough of sysrc(8) for a value to be written and read back."""
        path = Path(argv[argv.index('-f') + 1])
        content = path.read_text() if path.exists() else ''
        if '-n' in argv:
            name = argv[-1]
            if not path.exists():
                return self.answer_with(argv, '', 1)
            process = subprocess.Popen(['sh', '-c', '. "$1"; printf "%s" "${' + name + '-}"',
                                        'sysrc-test', str(path)], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            value, _ = process.communicate(timeout=5)
            return self.answer_with(argv, value, process.returncode)
        name, _, value = argv[-1].partition('=')
        line = '%s="%s"' % (name, value)
        replaced, count = re.subn(r'^\s*' + name + r'\s*=.*$', line, content, flags=re.M)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(replaced if count else content + line + '\n')
        return self.answer_with(argv, '')

    def answer_with(self, argv, stdout, code=0):
        from test_frp import Output
        return subprocess.CompletedProcess(argv, code, Output(stdout), Output(''))

    def mirrored(self):
        """The section as config.xml would hand it back after the XML leg."""
        return self.section.read()

    def stored_document(self, side):
        return self.mirrored().get(side + '_toml', '')


class RoundTripTests(MirrorCase):
    """What a restore gets back is what the operator had."""

    def test_every_backend_export_binds_the_raw_imported_snapshot(self):
        self.install('frps', AWKWARD_TOML)
        self.install('frpc', FRPC_TOML)
        self.assertTrue(m.mirror()['ok'])
        self.assertEqual(hashlib.sha256(b'{}').hexdigest(), self.exports[-1]['_expected'])
        stored = self.section.read()
        expected = hashlib.sha256(json.dumps(stored, ensure_ascii=True, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
        self.assertTrue(m.mirror()['ok'])
        self.assertEqual(expected, self.exports[-1]['_expected'])
        self.assertNotIn('_expected', self.section.read())

    def test_restore_between_import_and_export_retains_the_restored_xml(self):
        self.install('frps', AWKWARD_TOML)
        self.install('frpc', FRPC_TOML)
        self.assertTrue(m.mirror()['ok'])
        restored = self.section.read()
        restored['frps_toml'] = FRPS_TOML
        original_payload = m.mirror_payload
        def concurrent_restore():
            payload = original_payload()
            self.section.write(restored)
            return payload
        with patch.object(m, 'mirror_payload', side_effect=concurrent_restore):
            report = m.mirror()
        self.assertFalse(report['ok'])
        self.assertTrue(report['warning'])
        self.assertEqual(restored, self.section.read())
        self.assertEqual(AWKWARD_TOML, self.live('frps').read_bytes().decode())
        self.assertNotIn('s3cr3t-token', report['warning'])

    def test_both_documents_survive_byte_for_byte_including_the_token(self):
        self.install('frps', AWKWARD_TOML)
        self.install('frpc', FRPC_TOML)
        note = m.mirror()
        self.assertTrue(note['ok'], note)
        self.assertTrue(note['changed'])
        # The stored copy came back through a real XML serialise and parse.
        self.assertEqual(AWKWARD_TOML, self.stored_document('frps'))
        self.assertEqual(FRPC_TOML, self.stored_document('frpc'))
        self.assertIn('s3cr3t-token-äöü', self.stored_document('frps'))

        # A restored box: the package has just put the samples back.
        self.install('frps', '# sample\n')
        self.install('frpc', '# sample\n')
        report = m.adopt_payload(self.mirrored())
        self.assertEqual(['frpc', 'frps'], sorted(report['documents']))
        self.assertEqual([], report['warnings'])
        self.assertEqual(AWKWARD_TOML.encode('utf-8'), self.live('frps').read_bytes())
        self.assertEqual(FRPC_TOML.encode('utf-8'), self.live('frpc').read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(self.live('frps').stat().st_mode))

    def test_a_document_that_is_not_there_is_left_alone_rather_than_emptied(self):
        # Starting one daemon mirrors both sides. If the other document were
        # carried as an empty string, that start would erase the stored copy of
        # a daemon it never touched.
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        m.mirror()
        self.assertEqual(FRPC_TOML, self.stored_document('frpc'))
        self.live('frpc').unlink()
        m.mirror()
        self.assertNotIn('frpc_toml', self.exports[-1])
        self.assertEqual(FRPC_TOML, self.stored_document('frpc'))
        # And an empty file is the same event: the rc script will not start on
        # one, so it is not a document either.
        self.install('frpc', '   \n')
        m.mirror()
        self.assertNotIn('frpc_toml', self.exports[-1])
        self.assertEqual(FRPC_TOML, self.stored_document('frpc'))

    def test_an_unchanged_mirror_does_not_rewrite_config_xml(self):
        # Every save and every start passes through here, and every save of
        # config.xml costs a rolling backup and an audit entry.
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        self.assertTrue(m.mirror()['changed'])
        self.assertFalse(m.mirror()['changed'])


class RepresentabilityTests(MirrorCase):
    """A document XML cannot hold must not reach a file that has to re-parse."""

    def test_a_control_character_is_refused_and_nothing_is_mirrored(self):
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        m.mirror()
        good = self.mirrored()
        self.exports = []
        # A vertical tab: legal in a TOML literal string, and something libxml2
        # silently replaces with U+FFFD rather than refusing.
        self.install('frps', FRPS_TOML.replace('token = "server-token"', 'token = "ser\x0bver"'))
        note = m.mirror()
        self.assertFalse(note['ok'], note)
        self.assertIn('U+000B', note['warning'])
        self.assertIn('line', note['warning'])
        self.assertIn('frps', note['warning'])
        self.assertEqual([], self.exports, 'the refused document was handed to the mirror anyway')
        self.assertEqual(good, self.mirrored(), 'a refusal rewrote the stored section')

    def test_one_unrepresentable_document_holds_back_the_whole_section(self):
        # The section is one statement about one firewall. Storing the client
        # half while the server half stayed at its previous value would make a
        # backup that restores two different moments with nothing saying so.
        self.install('frps', FRPS_TOML.replace('bindAddr = "0.0.0.0"', 'bindAddr = "0.\x00"'))
        self.install('frpc', FRPC_TOML)
        note = m.mirror()
        self.assertFalse(note['ok'], note)
        self.assertEqual([], self.exports)
        self.assertEqual({}, self.mirrored())

    def test_an_escaped_control_character_survives_save_mirror_and_restore(self):
        # The TOML encoder escapes the control character before the raw document
        # reaches XML, so this remains a representable backup.
        self.install('frps', FRPS_TOML)
        document = self.document(self.ok('frps', 'settings'))
        document['log'] = {'level': 'info', 'to': '/var/log/frps\x0b.log'}
        result = self.ok('frps', 'set-settings', self.stage(document))
        self.assertTrue(result['saved'])
        self.assertIn('frps\\u000b.log', self.live('frps').read_text())
        self.assertTrue(result['mirror']['ok'])
        written = self.live('frps').read_bytes()
        self.assertEqual(written, self.stored_document('frps').encode())
        self.live('frps').write_text('# shipped sample\n')
        report = m.adopt_payload(self.mirrored())
        self.assertEqual(['frps'], report['documents'])
        self.assertEqual(written, self.live('frps').read_bytes())
        self.assertEqual('/var/log/frps\x0b.log', m.read_document(self.live('frps'))['log']['to'])

    def test_a_tab_a_newline_and_a_carriage_return_are_not_refused(self):
        # These three are the whole of what XML 1.0 allows below 0x20, and a
        # TOML document is full of the first two.
        self.install('frps', FRPS_TOML.replace('\n[auth]', '\r\n\t[auth]'))
        self.assertTrue(m.mirror()['ok'])
        self.assertIn('\r\n\t[auth]', self.stored_document('frps'))


class PlaceholderTests(MirrorCase):
    """The transport mask is between the page and the backend and goes no further."""

    def test_the_mirror_carries_the_real_token_and_never_the_mask(self):
        self.install('frps', FRPS_TOML)
        # Exactly what the page posts back when nobody retypes the credential.
        document = self.document(self.ok('frps', 'settings'))
        self.assertEqual(KEEP, document['auth']['token'])
        self.ok('frps', 'set-settings', self.stage(document))
        mirrored = self.stored_document('frps')
        self.assertIn('server-token', mirrored)
        self.assertNotIn(KEEP, mirrored)
        self.assertNotIn(KEEP, json.dumps(self.exports))

    def test_the_mirror_is_taken_after_the_replace_and_not_before(self):
        self.install('frps', FRPS_TOML)
        document = self.document(self.ok('frps', 'settings'))
        document['bindPort'] = 7001
        self.ok('frps', 'set-settings', self.stage(document))
        self.assertEqual(self.live('frps').read_text(), self.exports[-1]['frps_toml'],
                         'the mirror was taken from a file that is not the one on disk')
        self.assertIn('bindPort = 7001', self.exports[-1]['frps_toml'])

    def test_a_masked_credential_is_never_written_back_to_a_real_document(self):
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML.replace('serverPort = 7000', 'serverPort = 7001'))
        before = self.live('frps').read_bytes()
        payload = {'frps_toml': FRPS_TOML.replace('"server-token"', '"%s"' % KEEP),
                   'frpc_toml': FRPC_TOML}
        report = m.adopt_payload(payload)
        self.assertEqual(before, self.live('frps').read_bytes(),
                         'a placeholder was written over a real configuration')
        self.assertNotIn(KEEP, self.live('frps').read_text())
        self.assertEqual(['frps'], [name for name in ('frps',) if any('frps' in w for w in report['warnings'])])
        self.assertTrue(any('auth.token' in warning for warning in report['warnings']), report)
        # The other document is independent and is restored regardless: each is
        # its own file, so writing the good one beats writing neither.
        self.assertEqual(['frpc'], report['documents'])
        self.assertEqual(FRPC_TOML.encode(), self.live('frpc').read_bytes())

    def test_a_masked_credential_inside_a_document_that_does_not_parse_is_refused(self):
        self.install('frps', FRPS_TOML)
        before = self.live('frps').read_bytes()
        report = m.adopt_payload({'frps_toml': 'token = "%s"\nbroken = [\n' % KEEP})
        self.assertEqual(before, self.live('frps').read_bytes())
        self.assertTrue(report['warnings'])
        self.assertEqual([], report['documents'])

    def test_the_placeholder_somewhere_that_is_not_a_credential_is_still_a_document(self):
        # mask() only ever writes it over a credential, so a copy anywhere else
        # is text the operator put there and refusing it would lose a restore.
        self.install('frps', FRPS_TOML)
        document = FRPS_TOML.replace('bindAddr = "0.0.0.0"', 'bindAddr = "0.0.0.0" # %s' % KEEP)
        report = m.adopt_payload({'frps_toml': document})
        self.assertEqual(['frps'], report['documents'])
        self.assertEqual(document, self.live('frps').read_text())


class BootFlagTests(MirrorCase):
    """The flags are the only thing deciding whether the tunnel comes back."""

    def test_the_flags_are_mirrored_when_they_are_flipped(self):
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        self.assertFalse(m.is_enabled('frpc'))
        result = self.ok('frpc', 'start')
        self.assertTrue(m.is_enabled('frpc'))
        self.assertTrue(result['mirror']['ok'], result['mirror'])
        self.assertEqual('1', self.mirrored()['frpc_enable'])
        self.assertEqual('0', self.mirrored()['frps_enable'])
        stopped = self.ok('frpc', 'stop')
        self.assertTrue(stopped['mirror']['ok'], stopped['mirror'])
        self.assertEqual('0', self.mirrored()['frpc_enable'])

    def test_the_flags_survive_a_restore(self):
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        self.ok('frpc', 'start')
        self.ok('frps', 'start')
        carried = self.mirrored()
        # A reinstall seeds both fragments back to NO, which is the state this
        # whole section exists to undo.
        for side in ('frps', 'frpc'):
            self.fragment(side, False)
        self.assertFalse(m.is_enabled('frpc'))
        report = m.adopt_payload(carried)
        self.assertEqual(['frpc', 'frps'], sorted(report['flags']))
        self.assertTrue(m.is_enabled('frpc'))
        self.assertTrue(m.is_enabled('frps'))

    def test_a_flag_the_mirror_does_not_state_is_left_alone(self):
        self.fragment('frpc', True)
        self.assertTrue(m.is_enabled('frpc'))
        report = m.adopt_payload({'frps_enable': '0'})
        self.assertEqual([], report['flags'])
        self.assertTrue(m.is_enabled('frpc'))
        for absent in ({'frpc_enable': None}, {'frpc_enable': ''}, {'frpc_enable': '  '}):
            m.adopt_payload(absent)
            self.assertTrue(m.is_enabled('frpc'), absent)

    def test_the_last_assignment_in_the_fragment_is_the_one_that_counts(self):
        # sh reads the file top to bottom, so a second assignment wins; a
        # mirror that read the first would carry the opposite of the truth.
        path = self.fragment('frpc', False)
        path.write_text(path.read_text() + 'frpc_enable="YES"\n')
        self.assertTrue(m.enabled_at_boot('frpc'))
        self.install('frpc', FRPC_TOML)
        self.install('frps', FRPS_TOML)
        m.mirror()
        self.assertEqual('1', self.mirrored()['frpc_enable'])

    def test_an_override_the_backup_cannot_carry_is_reported(self):
        # frpc_config points the daemon at a document nobody mirrors, so a
        # restore that reproduced the pointer would restore a broken firewall.
        # The pointer is left behind, and the operator is told it was.
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        self.fragment('frpc', True, extra='frpc_config="/usr/local/etc/frp/other.toml"\n')
        note = m.mirror()
        self.assertTrue(note['ok'], note)
        self.assertIn('frpc_config', note['warning'])
        self.assertNotIn('frpc_config', json.dumps(self.exports[-1]))
        self.assertNotIn('frpc_config', json.dumps(self.mirrored()))
        # A fragment that only sets the flag has nothing to report.
        self.fragment('frpc', True)
        self.assertNotIn('warning', m.mirror())


class RestoreMarkerTests(MirrorCase):
    def test_import_refuses_a_noncredential_placeholder_that_the_editor_cannot_resolve(self):
        self.install('frps', FRPS_TOML)
        carried = FRPS_TOML.replace('bindAddr = "0.0.0.0"', 'bindAddr = "__KEEP__"')
        report = m.adopt_payload({'frps_toml': carried})
        self.assertTrue(report['warnings'])
        self.assertEqual(FRPS_TOML, self.live('frps').read_text())

    def test_boot_retains_newer_local_edits_after_a_successful_mirror(self):
        self.install('frps', FRPS_TOML)
        self.assertTrue(m.mirror()['ok'])
        changed = FRPS_TOML.replace('7000', '7001')
        self.install('frps', changed)
        self.assertFalse(m.import_config()['imported'])
        self.assertEqual(changed, self.live('frps').read_text())

    def test_failed_mirror_does_not_undo_the_saved_document_on_boot(self):
        self.install('frps', FRPS_TOML)
        self.assertTrue(m.mirror()['ok'])
        changed = FRPS_TOML.replace('7000', '7001')
        self.install('frps', changed)
        self.shim_code = 1
        self.assertFalse(m.mirror()['ok'])
        self.shim_code = 0
        self.assertFalse(m.import_config()['imported'])
        self.assertEqual(changed, self.live('frps').read_text())

    def test_pending_restored_xml_is_imported_before_it_can_be_mirrored(self):
        self.install('frps', FRPS_TOML)
        self.assertTrue(m.mirror()['ok'])
        restored = self.section.read()
        restored['frps_toml'] = FRPS_TOML.replace('7000', '7001')
        self.section.write(restored)
        self.assertFalse(m.mirror()['ok'])
        self.assertEqual(restored, self.section.read())
        self.assertTrue(m.import_config()['imported'])
        self.assertEqual(restored['frps_toml'], self.live('frps').read_text())
        self.assertTrue(m.mirror()['ok'])

    def test_reinstall_without_files_or_marker_adopts_the_stored_configuration(self):
        self.install('frps', FRPS_TOML)
        self.assertTrue(m.mirror()['ok'])
        self.live('frps').unlink()
        m.APPLIED_BACKUP.unlink()
        self.assertTrue(m.import_config()['imported'])
        self.assertEqual(FRPS_TOML, self.live('frps').read_text())
        self.assertEqual(0o600, stat.S_IMODE(m.APPLIED_BACKUP.stat().st_mode))

    def test_mirror_uses_the_same_shell_boot_flag_as_the_settings_page(self):
        self.install('frps', FRPS_TOML)
        for fragment, wanted in [("frps_enable='YES'\n", '1'),
                                 ('export frps_enable="YES"\n', '1'),
                                 ('answer=NO\nfrps_enable="$answer"\n', '0')]:
            with self.subTest(fragment=fragment):
                self.fragment('frps', False).write_text(fragment)
                self.assertTrue(m.mirror()['ok'])
                self.assertEqual(wanted, self.mirrored()['frps_enable'])


class AdoptTests(MirrorCase):
    """What import-config does, and everything it must not do."""

    def test_adopting_twice_writes_nothing_the_second_time(self):
        self.install('frps', '# sample\n')
        self.install('frpc', '# sample\n')
        payload = {'frps_toml': FRPS_TOML, 'frpc_toml': FRPC_TOML,
                   'frps_enable': '1', 'frpc_enable': '1'}
        first = m.adopt_payload(payload)
        self.assertEqual(['frpc', 'frps'], sorted(first['documents']))
        self.assertEqual(['frpc', 'frps'], sorted(first['flags']))
        stamps = {side: self.live(side).stat().st_mtime_ns for side in ('frps', 'frpc')}
        second = m.adopt_payload(payload)
        self.assertEqual({'documents': [], 'flags': [], 'warnings': []}, second)
        for side, stamp in stamps.items():
            self.assertEqual(stamp, self.live(side).stat().st_mtime_ns,
                             '%s was rewritten with the bytes it already held' % side)

    def test_adopting_starts_restarts_and_reloads_nothing(self):
        self.install('frps', '# sample\n')
        self.install('frpc', '# sample\n')
        self.section.export({'frps_toml': FRPS_TOML, 'frpc_toml': FRPC_TOML,
                             'frps_enable': '1', 'frpc_enable': '1'})
        self.commands = []
        report = self.ok('frps', 'import-config')
        self.assertTrue(report['imported'])
        self.assertEqual(set(), self.running, self.commands)
        self.assertFalse(any(word in argv for argv in self.commands
                             for word in ('onestart', 'start', 'restart', 'onerestart', 'reload')),
                         self.commands)

    def test_an_absent_section_is_a_no_op_and_not_a_failure(self):
        self.install('frps', FRPS_TOML)
        before = self.live('frps').read_bytes()
        report = self.ok('frps', 'import-config')
        self.assertFalse(report['imported'])
        self.assertEqual([], report['warnings'])
        self.assertEqual(before, self.live('frps').read_bytes())
        self.assertFalse(m.is_enabled('frps'))

    def test_a_section_written_by_a_newer_version_is_tolerated(self):
        self.install('frps', '# sample\n')
        report = m.adopt_payload({'frps_toml': FRPS_TOML, 'something_new': 'value',
                                  'frps_enable': '1'})
        self.assertEqual(['frps'], report['documents'])
        self.assertEqual(FRPS_TOML, self.live('frps').read_text())

    def test_a_section_missing_a_field_this_version_expects_is_tolerated(self):
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        before = self.live('frpc').read_bytes()
        report = m.adopt_payload({'frps_toml': FRPS_TOML})
        self.assertEqual([], report['warnings'])
        self.assertEqual(before, self.live('frpc').read_bytes())

    def test_a_payload_that_is_not_an_object_is_refused(self):
        for payload in ('not a section', ['frps'], 7):
            with self.assertRaises(m.Error):
                m.adopt_payload(payload)

    def test_import_config_holds_both_locks_and_ignores_the_side_it_is_given(self):
        self.install('frps', '# sample\n')
        self.install('frpc', '# sample\n')
        self.section.export({'frps_toml': FRPS_TOML, 'frpc_toml': FRPC_TOML})
        # Either side restores the whole plugin: the mirrored section is one
        # statement about both daemons.
        report = self.ok('frpc', 'import-config')
        self.assertEqual(['frpc', 'frps'], sorted(report['documents']))
        for side in ('frps', 'frpc'):
            self.assertTrue((Path(m.STATE) / (side + '.lock')).exists(), side)


class FailureTests(MirrorCase):
    """A mirror that cannot run must cost nothing but a warning."""

    def test_a_mirror_that_fails_does_not_fail_the_save(self):
        self.install('frps', FRPS_TOML)
        self.shim_code = 1
        document = self.document(self.ok('frps', 'settings'))
        document['bindPort'] = 7002
        result = self.ok('frps', 'set-settings', self.stage(document))
        self.assertTrue(result['saved'])
        self.assertIn('bindPort = 7002', self.live('frps').read_text())
        self.assertFalse(result['mirror']['ok'])
        self.assertTrue(result['mirror']['warning'])

    def test_a_mirror_that_fails_does_not_fail_a_start(self):
        self.install('frpc', FRPC_TOML)
        self.shim_code = 1
        result = self.ok('frpc', 'start')
        self.assertIn('frpc', self.running)
        self.assertFalse(result['mirror']['ok'])

    def test_a_mirror_failure_never_quotes_a_credential_back(self):
        # The model reports a rejected value by appending it to the message,
        # and the value here is a document holding the authentication token.
        self.install('frps', FRPS_TOML)
        self.install('frpc', FRPC_TOML)
        self.shim_code = 1
        self.shim_output = None
        original = self.shim

        def leaking(argv, payload):
            from test_frp import Output
            return subprocess.CompletedProcess(
                argv, 1, Output(''), Output('[Backup:frps_toml] rejected {%s}' % FRPS_TOML))
        self.shim = leaking
        note = m.mirror()
        self.shim = original
        self.assertFalse(note['ok'])
        for secret in ('server-token', 'panel-password'):
            self.assertNotIn(secret, note['warning'], secret)

    def test_an_answer_that_is_not_json_is_a_warning_and_not_a_crash(self):
        self.install('frps', FRPS_TOML)
        self.shim_output = 'Fatal error: something went wrong'
        note = m.mirror()
        self.assertFalse(note['ok'])
        self.assertTrue(note['warning'])
        report = self.ok('frps', 'import-config')
        self.assertFalse(report['imported'])
        self.assertTrue(report['warnings'])

    def test_unattended_import_failure_is_logged_before_its_early_return(self):
        self.install('frps', FRPS_TOML)
        self.shim_code = 1
        with patch.object(m.syslog, 'syslog') as logged:
            report = m.import_config()
        self.assertFalse(report['imported'])
        self.assertTrue(report['warnings'])
        logged.assert_called_once()
        self.assertEqual(m.syslog.LOG_WARNING, logged.call_args.args[0])
        self.assertIn('os-frp:', logged.call_args.args[1])
        self.assertNotIn('server-token', logged.call_args.args[1])

    def test_a_mirror_that_is_not_installed_is_a_warning_and_not_a_crash(self):
        self.install('frps', FRPS_TOML)
        m.MIRROR.unlink()
        note = m.mirror()
        self.assertFalse(note['ok'])
        self.assertIn('config_mirror.php', note['warning'])
        self.assertEqual([], self.exports)


class ShapeTests(unittest.TestCase):
    """The parts that only exist on the router, checked where they are written."""

    def test_the_model_mounts_where_the_shim_looks_and_requires_nothing(self):
        self.assertTrue(MODEL.is_file(), MODEL)
        model = ElementTree.parse(MODEL).getroot()
        self.assertEqual('//OPNsense/Frp/backup', model.findtext('mount'))
        self.assertTrue(model.findtext('version'), 'an unversioned model cannot be migrated')
        items = model.find('items')
        self.assertIsNotNone(items)
        names = {child.tag: child for child in items}
        self.assertEqual({'frps_toml', 'frpc_toml', 'frps_enable', 'frpc_enable'}, set(names))
        for tag, child in names.items():
            # An absent or partial section has to load: a Required field would
            # turn a restore that is missing one value into a model that throws.
            self.assertNotEqual('Y', (child.findtext('Required') or 'N').upper(), tag)
        self.assertEqual('TextField', names['frps_toml'].get('type'))
        self.assertEqual('TextField', names['frpc_toml'].get('type'))
        self.assertEqual('BooleanField', names['frps_enable'].get('type'))

    def test_the_model_class_is_a_bare_basemodel_in_the_plugin_s_namespace(self):
        self.assertTrue(MODEL_CLASS.is_file(), MODEL_CLASS)
        source = MODEL_CLASS.read_text()
        self.assertIn('namespace OPNsense\\Frp;', source)
        self.assertRegex(source, r'class\s+Backup\s+extends\s+BaseModel')

    def test_the_mirror_offers_exactly_the_two_verbs_the_backend_calls(self):
        self.assertTrue(MIRROR.is_file(), MIRROR)
        source = MIRROR.read_text()
        self.assertIn("'//OPNsense/Frp/backup'", source)
        self.assertIn("$verb === 'import'", source)
        self.assertIn("$verb !== 'export'", source)
        # The payload holds the authentication token; a command line does not.
        self.assertIn('stream_get_contents(STDIN', source)
        self.assertNotIn('$argv[2]', source)
        # Policy lives in Python: the shim may not know what a field means.
        for word in ('frps_toml', 'frpc_toml', 'frps_enable', 'frpc_enable',
                     'CHANGE_ME', KEEP, 'toml'):
            self.assertNotIn(word, source, '%s is policy and belongs in manage.py' % word)
        # A save of config.xml is a rolling backup and an audit entry each time.
        self.assertIn('$changed', source)

    def test_the_mirror_is_reached_from_the_package_hook_and_from_boot(self):
        for path in (POST_INSTALL, BOOT_HOOK):
            source = path.read_text()
            self.assertIn('manage.py --json', source, path.name)
            self.assertIn('import-config', source, path.name)
        # Before 20-freebsd, which is what starts the services rc.conf.d
        # enables: adopting the flags one boot later is adopting them never.
        self.assertLess(BOOT_HOOK.name, '20-freebsd')
        self.assertTrue(os.access(BOOT_HOOK, os.X_OK), 'the boot hook is not executable')

    def test_no_reachable_path_in_this_plugin_writes_transparent_consent(self):
        # Nothing in a restore may turn on a consent the operator never gave.
        # frp has no such setting, and this is what keeps it that way.
        found = [str(path.relative_to(ROOT)) for path in PLUGIN.rglob('*')
                 if path.is_file() and '__pycache__' not in path.parts
                 and 'transparent_consent' in path.read_bytes().decode('utf-8', 'replace')]
        self.assertEqual([], found)

    @unittest.skipUnless(shutil.which('php'), 'php is not installed on this machine')
    def test_the_mirror_is_syntactically_valid_php(self):
        result = subprocess.run([shutil.which('php'), '-l', str(MIRROR)],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
