"""Drive the plugin manifest the repository hook keeps in a restored configuration.

register.php empties <system><firmware><plugins> on a router whose configuration
has just been restored, so the hook records what this repository has installed
somewhere resync cannot reach.  These tests run the real hook against a private
filesystem, the way test_repository.py already does, and read the resulting
config.xml back as XML.

The hook reaches config.xml through a small embedded PHP shim that moves one text
document in and out of //OPNsense/KazuhaRepo/backup.  Where PHP is unavailable --
a developer's macOS checkout -- a stand-in on PATH implements that same document
contract so the shell policy above it is still exercised end to end.  Where PHP is
available -- the FreeBSD builder the release workflow runs these tests on, and the
router itself -- RealInterpreterManifestTests runs every one of these cases again
against the shim that actually ships.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

PLUGIN = Path(__file__).resolve().parents[1]
HOOK = PLUGIN / 'src/usr/local/opnsense/scripts/firmware/repos/kazuha.sh'
KEY = PLUGIN / 'src/usr/local/share/kazuha-repo/kazuha.pub'

# A configuration shaped like the router's: the initial-wizard flag that makes
# register.php fall through to resync, a populated firmware plugin list, and an
# unrelated <OPNsense> section the hook has to leave exactly where it found it.
CONFIGURATION = """<?xml version="1.0"?>
<opnsense>
  <theme>opnsense</theme>
  <trigger_initial_wizard/>
  <system>
    <hostname>router</hostname>
    <firmware>
      <plugins>os-cloudflared,os-frp,os-kazuha-repo,os-mihomo</plugins>
      <type/>
    </firmware>
  </system>
  <OPNsense>
    <Unboundplus>
      <general><enabled>1</enabled></general>
    </Unboundplus>
  </OPNsense>
</opnsense>
"""

# The stand-in for the embedded shim: the same document contract, no policy.
INTERPRETER = '''
import os
import sys
import xml.etree.ElementTree as ET

sys.stdin.read()  # the shim program itself, which this stand-in does not need

verb = os.environ.get("_KAZUHA_VERB", "")
if verb not in ("read", "write") or os.environ.get("BREAK_PHP"):
    sys.exit(1)
path = os.environ.get("KAZUHA_REPO_ROOT", "").rstrip("/") + "/conf/config.xml"
if not os.path.isfile(path):
    sys.exit(1)
tree = ET.parse(path)
node = tree.getroot()
for name in ("OPNsense", "KazuhaRepo", "backup"):
    child = node.find(name)
    if child is None:
        if verb != "write":
            sys.exit(0)
        child = ET.SubElement(node, name)
    node = child
if verb == "read":
    sys.stdout.write(node.findtext("plugins") or "")
    sys.exit(0)
plugins = os.environ.get("_KAZUHA_PLUGINS", "")
if (node.findtext("plugins") or "") == plugins:
    sys.stdout.write("unchanged\\n")
    sys.exit(0)
for name, value in (("version", os.environ.get("_KAZUHA_SCHEMA", "")),
                    ("updated", "2026-09-13T00:00:00Z"),
                    ("plugins", plugins)):
    element = node.find(name)
    if element is None:
        element = ET.SubElement(node, name)
    element.text = value
tree.write(path)
sys.stdout.write("changed\\n")
'''

# pkg, answering the two questions the hook asks it, from the environment.
PKG = '''
import os
import sys

if os.environ.get("BREAK_PKG"):
    sys.exit(1)
args = sys.argv[1:]
if args[:1] == ["rquery"]:
    assert args[1:4] == ["-r", "kazuha", "%n"], args
    print(os.environ.get("OFFERED", ""), end="")
elif args[:1] == ["query"]:
    assert args[1] == "%R|%n|%v", args
    print(os.environ.get("INSTALLED", ""), end="")
else:
    raise AssertionError(args)
'''


class ManifestTests(unittest.TestCase):
    """The hook driven with a stand-in interpreter for its embedded shim."""

    interpreter = INTERPRETER

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        (self.root / 'usr/local/etc/pkg/repos').mkdir(parents=True)
        (self.root / 'usr/local/etc/pkg/keys').mkdir(parents=True)
        source_key = self.root / 'usr/local/share/kazuha-repo/kazuha.pub'
        source_key.parent.mkdir(parents=True)
        shutil.copyfile(KEY, source_key)
        self.configuration = self.root / 'conf/config.xml'
        self.configuration.parent.mkdir(parents=True)
        self.configuration.write_text(CONFIGURATION)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        KAZUHA_REPO_ROOT=str(self.root), SERIES='26.7',
                        INSTALLED='', OFFERED='', BREAK_PKG='', BREAK_PHP='')
        commands = {
            'opnsense-version': 'import os; print(os.environ["SERIES"])',
            'sha256': 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[-1], "rb").read()).hexdigest())',
            'pkg': PKG,
        }
        if self.interpreter is not None:
            commands['php'] = self.interpreter
        for name, code in commands.items():
            path = self.bin / name
            path.write_text('#!' + sys.executable + '\n' + code + '\n')
            path.chmod(0o755)

    # -- driving the hook ---------------------------------------------------

    def run_hook(self, *arguments, expect=0, **environment):
        env = dict(self.env, **{name: str(value) for name, value in environment.items()})
        result = subprocess.run(['sh', str(HOOK), *arguments], env=env,
                                capture_output=True, text=True)
        if expect is not None:
            self.assertEqual(expect, result.returncode, result.stdout + result.stderr)
        return result

    def installed(self, *entries, offered=(), **keywords):
        """Run a mirror with pkg reporting these '<repository> <name> <version>' facts."""
        return self.run_hook('mirror', INSTALLED=''.join(
            '|'.join(entry.split()) + '\n' for entry in entries),
            OFFERED=''.join(name + '\n' for name in offered), **keywords)

    # -- reading the result -------------------------------------------------

    def section(self):
        node = ET.parse(self.configuration).getroot().find('./OPNsense/KazuhaRepo/backup')
        return node

    def manifest(self):
        node = self.section()
        text = '' if node is None else (node.findtext('plugins') or '')
        return [line for line in text.splitlines() if line]

    def firmware_plugins(self):
        root = ET.parse(self.configuration).getroot()
        node = root.find('./system/firmware/plugins')
        return None if node is None else (node.text or '')

    def printed(self):
        return [line for line in self.run_hook('manifest').stdout.splitlines() if line]

    # -- the manifest has to exist without the element resync destroys ------

    def test_a_manifest_is_recorded_when_the_configuration_has_no_plugin_list(self):
        for removed in ('./system/firmware/plugins', './system/firmware', './system'):
            with self.subTest(removed=removed):
                self.configuration.write_text(CONFIGURATION)
                root = ET.parse(self.configuration).getroot()
                parent = root.find(removed.rsplit('/', 1)[0].replace('.//', './') or '.')
                parent.remove(parent.find(removed.rsplit('/', 1)[1]))
                ET.ElementTree(root).write(self.configuration)
                self.installed('kazuha os-mihomo 1.2.0', 'kazuha os-kazuha-repo 1.0.0')
                self.assertEqual(['os-kazuha-repo 1.0.0', 'os-mihomo 1.2.0'], self.manifest())

    def test_a_manifest_is_recorded_when_the_section_and_its_parents_are_absent(self):
        root = ET.parse(self.configuration).getroot()
        root.remove(root.find('OPNsense'))
        ET.ElementTree(root).write(self.configuration)
        self.installed('kazuha os-kazuha-repo 1.0.0')
        self.assertEqual(['os-kazuha-repo 1.0.0'], self.manifest())
        self.assertEqual('1.0.0', self.section().findtext('version'))
        self.assertTrue(self.section().findtext('updated'))

    def test_a_resync_emptied_plugin_list_does_not_empty_the_manifest(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0',
                       'kazuha os-speedtest 1.1.1')
        recorded = self.manifest()
        self.assertEqual(3, len(recorded))

        # What register.php resync leaves behind on a restored router, and what
        # that router's pkg database says at the same moment: nothing of ours is
        # installed yet except the package this hook came in.
        root = ET.parse(self.configuration).getroot()
        root.find('./system/firmware/plugins').text = ''
        ET.ElementTree(root).write(self.configuration)
        self.installed('kazuha os-kazuha-repo 1.0.0')

        self.assertEqual(recorded, self.manifest())
        self.assertEqual('', self.firmware_plugins())

    def test_a_restored_manifest_survives_a_router_with_nothing_installed(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-frp 1.0.0')
        recorded = self.manifest()
        result = self.installed()  # pkg sees nothing at all: mid-transaction, or a fresh box
        self.assertEqual(recorded, self.manifest())
        self.assertIn(result.returncode, (0,))

    # -- the read verb ------------------------------------------------------

    def test_the_read_verb_prints_the_manifest_that_was_written(self):
        self.assertEqual([], self.printed())
        self.installed('kazuha os-mihomo 1.2.0', 'kazuha os-kazuha-repo 1.0.0',
                       'kazuha os-speedtest 1.1.1')
        self.assertEqual(['os-kazuha-repo 1.0.0', 'os-mihomo 1.2.0', 'os-speedtest 1.1.1'],
                         self.printed())
        self.assertEqual(self.manifest(), self.printed())

    def test_the_read_verb_reports_failure_rather_than_an_empty_list(self):
        self.installed('kazuha os-mihomo 1.2.0')
        self.configuration.unlink()
        result = self.run_hook('manifest', expect=None)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual('', result.stdout)

    def test_names_pkg_could_not_have_produced_never_reach_the_read_verb(self):
        # A restored config.xml is operator data and these names are handed to
        # pkg afterwards, so a hand-edited or hostile section must not survive.
        self.installed('kazuha os-mihomo 1.2.0')
        root = ET.parse(self.configuration).getroot()
        root.find('./OPNsense/KazuhaRepo/backup/plugins').text = '\n'.join([
            'os-mihomo 1.2.0',
            '../../etc/passwd 1.0.0',
            'os-evil; rm -rf / 1.0.0',
            'os-evil 1.0.0; reboot',
            '-rf 1.0.0',
            'os-Upper 1.0.0',
            'os-partial',
        ])
        ET.ElementTree(root).write(self.configuration)
        self.assertEqual(['os-mihomo 1.2.0'], self.printed())

        # And the next mirror writes the cleaned document back.
        self.installed('kazuha os-mihomo 1.2.0')
        self.assertEqual(['os-mihomo 1.2.0'], self.manifest())

    # -- what counts as one of ours -----------------------------------------

    def test_a_side_loaded_package_the_catalog_still_offers_is_recorded(self):
        # os-frp reached this router through pkg add, so pkg cannot name its
        # repository; the catalog still offers it, which is enough.
        self.installed('kazuha os-kazuha-repo 1.0.0', 'unknown-repository os-frp 1.0.0',
                       'OPNsense os-dnscrypt-proxy 2.0.0',
                       offered=('os-frp', 'os-kazuha-repo', 'os-mihomo'))
        self.assertEqual(['os-frp 1.0.0', 'os-kazuha-repo 1.0.0'], self.manifest())

    def test_a_plugin_from_another_repository_is_not_claimed(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'OPNsense os-wireguard 1.0.0')
        self.assertEqual(['os-kazuha-repo 1.0.0'], self.manifest())

    def test_an_upgraded_plugin_updates_its_recorded_version(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.3.0')
        self.assertEqual(['os-kazuha-repo 1.0.0', 'os-mihomo 1.3.0'], self.manifest())

    # -- cost and blast radius ----------------------------------------------

    def test_an_unchanged_manifest_does_not_rewrite_the_configuration(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
        before = self.configuration.read_bytes()
        for _ in range(3):
            result = self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
            self.assertIn('unchanged', result.stdout)
        self.assertEqual(before, self.configuration.read_bytes())

    def test_the_firmware_plugin_list_is_never_written_by_this_hook(self):
        listed = self.firmware_plugins()
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
        self.assertEqual(listed, self.firmware_plugins())
        self.assertEqual('1', ET.parse(self.configuration).getroot().findtext(
            './OPNsense/Unboundplus/general/enabled'))

    # -- mirroring may never break the thing it rides on --------------------

    def test_a_broken_interpreter_cannot_fail_the_repository_configuration(self):
        # Break the executable itself, including when the real PHP runs this case.
        broken = self.bin / 'php'
        broken.write_text('#!/bin/sh\nexit 1\n')
        broken.chmod(0o755)
        result = self.run_hook(BREAK_PHP='yes', INSTALLED='kazuha|os-kazuha-repo|1.0.0\n')
        self.assertEqual(0, result.returncode, result.stderr)
        configuration = (self.root / 'usr/local/etc/pkg/repos/kazuha.conf').read_text()
        self.assertIn('signature_type: "pubkey"', configuration)
        self.assertEqual(KEY.read_bytes(), (self.root / 'usr/local/etc/pkg/keys/kazuha.pub').read_bytes())
        self.assertIsNone(self.section())

    def test_a_broken_pkg_cannot_fail_the_repository_configuration_or_the_manifest(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
        recorded = self.manifest()
        result = self.run_hook(BREAK_PKG='yes')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('signature_type: "pubkey"',
                      (self.root / 'usr/local/etc/pkg/repos/kazuha.conf').read_text())
        self.assertEqual(recorded, self.manifest())

    def test_an_absent_interpreter_cannot_fail_the_repository_configuration(self):
        # PHP lives in /usr/local/bin on both FreeBSD and macOS; a PATH without
        # it is how a build chroot or a rescue shell reaches this hook.
        result = self.run_hook(PATH=str(self.bin) + ':/usr/bin:/bin:/usr/sbin:/sbin',
                               INSTALLED='kazuha|os-kazuha-repo|1.0.0\n')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('signature_type: "pubkey"',
                      (self.root / 'usr/local/etc/pkg/repos/kazuha.conf').read_text())

    def test_the_default_verb_configures_the_repository_and_records_the_manifest(self):
        self.run_hook(INSTALLED='kazuha|os-kazuha-repo|1.0.0\nkazuha|os-mihomo|1.2.0\n')
        self.assertIn('repo/${ABI}"', (self.root / 'usr/local/etc/pkg/repos/kazuha.conf').read_text())
        self.assertEqual(['os-kazuha-repo 1.0.0', 'os-mihomo 1.2.0'], self.manifest())

    def test_an_unknown_verb_is_refused(self):
        for arguments in (['resync'], ['forget'], ['forget', 'not-a-plugin'], ['forget', '../x']):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(0, self.run_hook(*arguments, expect=None).returncode)

    # -- the only way an entry leaves ---------------------------------------

    def test_forget_drops_one_entry_and_leaves_the_rest(self):
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0',
                       'kazuha os-speedtest 1.1.1')
        self.run_hook('forget', 'os-mihomo')
        self.assertEqual(['os-kazuha-repo 1.0.0', 'os-speedtest 1.1.1'], self.printed())

        # Forgetting something that was never there changes nothing at all.
        before = self.configuration.read_bytes()
        self.run_hook('forget', 'os-mihomo')
        self.assertEqual(before, self.configuration.read_bytes())

    def test_forget_does_not_survive_the_plugin_still_being_installed(self):
        # An operator who forgets a plugin that is still on the box gets it back
        # on the next firmware configuration, which is the honest answer.
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
        self.run_hook('forget', 'os-mihomo')
        self.assertEqual(['os-kazuha-repo 1.0.0'], self.printed())
        self.installed('kazuha os-kazuha-repo 1.0.0', 'kazuha os-mihomo 1.2.0')
        self.assertEqual(['os-kazuha-repo 1.0.0', 'os-mihomo 1.2.0'], self.printed())


@unittest.skipUnless(shutil.which('php'), 'php is unavailable')
class RealInterpreterManifestTests(ManifestTests):
    """Every case above, run against the PHP shim the package actually ships."""

    interpreter = None


if __name__ == '__main__':
    unittest.main()
