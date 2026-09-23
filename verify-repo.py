#!/usr/bin/env python3
"""Verify signed catalogs, every listed package, and the tested release report."""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import importlib.util
import os
import shutil

ABI_PATTERN = r'FreeBSD:[0-9]+:amd64'
INDEPENDENT_ABI = 'FreeBSD:*:amd64'
VERSION_PATTERN = r'[0-9][0-9A-Za-z._,+]*'
PHASES = ('pre-install', 'post-install', 'pre-deinstall', 'post-deinstall')
REGISTRY = 'packaging/plugins.json'
RECORD_FIELDS = {'staging', 'abi', 'version', 'stage', 'shared', 'deps', 'vendored', 'generated',
                 'version_file', 'reason', 'notes'}
VENDOR_FIELDS = {'artifact', 'sha256', 'sha256_file', 'checksums_file', 'archive',
                 'members', 'install'}
SOURCE_NOISE = {'.pyc', '.pyo'}
# Manifest keys that make libpkg act beyond the files{} this verifier reconstructs:
# a second (Lua) hook interpreter, filesystem objects, accounts and config handling.
MANIFEST_SIDE_EFFECTS = ('lua_scripts', 'directories', 'dirs', 'config', 'users', 'groups')
# libpkg records each manifest file sum as "<type>$<digest>": type 1 is SHA256 in
# hex, and type 2 (the pkg 2.x default) is BLAKE2b in libpkg's z-base32 alphabet.
# Both shapes ship from supported targets, so verification accepts either one.
ZBASE32 = 'ybndrfg8ejkmcpqxot1uwisza345h769'


def zbase32(data):
    """Encode bytes exactly like libpkg's pkg_checksum_encode_base32()."""
    output, remain = [], -1
    for index, byte in enumerate(data):
        step = index % 5
        if step == 0:
            value = byte
            remain = byte >> 5
        elif step == 1:
            value = remain | byte << 3
            output.append(ZBASE32[value & 0x1F])
            output.append(ZBASE32[(value >> 5) & 0x1F])
            remain = value >> 10
            continue
        elif step == 2:
            value = remain | byte << 1
            remain = value >> 5
        elif step == 3:
            value = remain | byte << 4
            output.append(ZBASE32[value & 0x1F])
            output.append(ZBASE32[(value >> 5) & 0x1F])
            remain = (value >> 10) & 0x3
            continue
        else:
            value = remain | byte << 2
            output.append(ZBASE32[value & 0x1F])
            output.append(ZBASE32[(value >> 5) & 0x1F])
            remain = -1
            continue
        output.append(ZBASE32[value & 0x1F])
    if remain >= 0:
        output.append(ZBASE32[remain])
    return ''.join(output)


def file_checksum_matches(entry, content):
    """Accept both manifest file shapes: 1$SHA256 hex and 2$BLAKE2b z-base32."""
    if isinstance(entry, dict):
        entry = entry.get('sum')
    if not isinstance(entry, str):
        return False
    prefix, separator, digest = entry.partition('$')
    if not separator:
        return False
    if prefix == '1':
        return digest == hashlib.sha256(content).hexdigest()
    if prefix == '2':
        return digest == zbase32(hashlib.blake2b(content).digest())
    return False


def target_module(source):
    path = source / 'src/os-mihomo/packaging/target.py'
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location('package_target', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_path(site, value):
    if not isinstance(value, str) or not re.fullmatch(r'repo/FreeBSD:[0-9]+:amd64(?:/[0-9]{2}\.[17])?/All/[A-Za-z0-9_.+,-]+\.pkg', value):
        raise ValueError('Unsafe release package path.')
    path = site / value
    if not path.resolve().is_relative_to((site / 'repo').resolve()):
        raise ValueError('Unsafe release package path.')
    return path


def unique_keys(pairs):
    """libpkg parses a manifest with UCL, which keeps a repeated key this reader drops."""
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Package manifest repeats the key: ' + str(key))
        value[key] = item
    return value


def manifest_of(package, member='+MANIFEST'):
    try:
        payload = subprocess.check_output(['tar', '-xOf', str(package), '-P', '--', member],
                                          stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as error:
        raise ValueError('Package has no readable ' + member + ': ' + str(package)) from error
    try:
        return json.loads(payload, object_pairs_hook=unique_keys)
    except json.JSONDecodeError as error:
        raise ValueError('Package manifest is not the JSON form this verifier reads: ' + str(package)) from error


def check_manifest_shape(package, manifest):
    """Refuse manifest machinery no committed source can describe.

    scripts{} is compared against the committed hooks below, but libpkg runs more
    than that: lua_scripts is a second hook interpreter, and directories, config,
    users and groups create things on the client that files{} never mentions.
    +COMPACT_MANIFEST is not decoration either -- 'pkg repo' copies it into the
    signed catalog, so a package whose two manifests disagree publishes one story
    to the catalog and another to the installer.
    """
    for key in MANIFEST_SIDE_EFFECTS:
        if manifest.get(key):
            raise ValueError('Package manifest carries ' + key + ', which no committed source describes.')
    compact = manifest_of(package, '+COMPACT_MANIFEST')
    for key, value in compact.items():
        if key not in manifest or manifest[key] != value:
            raise ValueError('Catalog manifest differs from the package manifest: ' + str(key))
    if any(compact.get(key) != manifest.get(key) for key in ('name', 'version', 'abi')):
        raise ValueError('Catalog manifest does not carry the package identity.')


ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'


def python_members(package):
    """What Python's own tar reader sees in the archive.

    tarfile learned zstd in 3.14 and the signing host runs 3.13, while tzst is
    what libpkg writes unless a build asks for something else. Decompressing
    with the base system's zstd keeps this reader independent of libarchive,
    which is the whole point of consulting it: the container format is not what
    the comparison is about, the member list is.
    """
    try:
        with tarfile.open(package) as archive:
            return archive.getmembers()
    except tarfile.ReadError:
        with open(package, 'rb') as stream:
            if stream.read(len(ZSTD_MAGIC)) != ZSTD_MAGIC:
                raise
    plain = subprocess.run(['zstd', '-dc', '--', str(package)], check=True, stdout=subprocess.PIPE).stdout
    with tarfile.open(fileobj=io.BytesIO(plain)) as archive:
        return archive.getmembers()


def archive_members(package):
    """Read the archive twice and refuse anything but plain files.

    tar -tf is libarchive, the same reader libpkg installs with; tarfile is this
    verifier's own. Requiring both to see the same members closes the gap between
    what is inventoried and what is extracted. Only regular files may carry
    content, and none of them may carry a setuid, setgid or sticky bit, which the
    committed source has no way to ask for.
    """
    listed = subprocess.check_output(['tar', '-tf', str(package)], text=True).splitlines()
    items = python_members(package)
    if [item.name for item in items] != listed:
        raise ValueError('Package archive does not read the same way twice.')
    paths = {}
    for item in items:
        if item.isdir():
            continue
        if not item.isreg():
            raise ValueError('Package archive member is not a regular file: ' + item.name)
        if item.mode & 0o7000:
            raise ValueError('Package archive member carries a setuid, setgid or sticky bit: ' + item.name)
        path = '/' + item.name.removeprefix('./').lstrip('/')
        if path in paths:
            raise ValueError('Package archive lists a member twice: ' + path)
        paths[path] = item.name
    return paths


def validate_attestation(entry, manifest, target=None):
    checks = entry.get('checks')
    if entry.get('ok') is not True or not isinstance(checks, list) or len(checks) < 10 or any(not isinstance(c, str) or not c.strip() for c in checks) or len(set(checks)) != len(checks):
        raise ValueError('The release has no complete native lifecycle test report.')
    abi = entry.get('abi', '')
    if not re.fullmatch(ABI_PATTERN, abi) or manifest.get('abi') != abi or entry.get('native_abi') != abi:
        raise ValueError('Package ABI differs from its native test environment.')
    metadata = manifest.get('annotations', {})
    if metadata.get('product_abi') != entry.get('product_abi') or entry.get('native_product_abi') != entry.get('product_abi'):
        raise ValueError('Product ABI differs from the native test report.')
    python = entry.get('python', '')
    if not re.fullmatch(r'3\.[0-9]+', python) or 'python' + python.replace('.', '') not in manifest.get('deps', {}):
        raise ValueError('Python dependency differs from the native test report.')
    native = entry.get('native_release', '')
    if not re.match(r'^' + abi.split(':')[1] + r'\.[0-9]+(?:-|$)', native):
        raise ValueError('Native FreeBSD release differs from the package ABI.')
    kernel = entry.get('native_kernel_version', '')
    if not isinstance(kernel, str) or not kernel.isdigit() or int(kernel) // 100000 != int(abi.split(':')[1]):
        raise ValueError('Native kernel differs from the package ABI.')
    if target:
        if any(entry.get(field) != target[field] for field in ('abi', 'product_abi', 'python')):
            raise ValueError('Test report differs from the committed target recipe.')
        if not re.match(r'^' + re.escape(target['native_freebsd']) + r'(?:-|$)', native):
            raise ValueError('Native release differs from the committed target recipe.')
        if not entry['path'].startswith(target['repository'] + '/All/'):
            raise ValueError('Repository differs from the committed target recipe.')


def plugin_records(source):
    """Read the committed staging records that describe what each package may contain.

    Every publishable plugin except os-mihomo -- which is described by its own
    committed recipe module, src/os-mihomo/packaging/target.py -- has a record in
    packaging/plugins.json:

      staging      "tree" reconstructs the package from src/, "repository" adds the
                   signed product-series rewrite of os-kazuha-repo, "unsupported"
                   names a plugin this verifier refuses to publish and why.
      abi          "target" requires FreeBSD:<major>:amd64, "independent" requires
                   FreeBSD:*:amd64, or a concrete FreeBSD ABI pins one runtime.
      version      the version this source publishes; a package may carry no other.
      stage        {source directory under the plugin: install directory}. Every
                   committed file under src/ must fall inside one of them.
      shared       {repository-relative source file: install file} for regular
                   files copied from outside the plugin, inside the repository.
      deps         {package: origin} the manifest must declare, exactly.
      vendored     artifacts unpacked into the stage. Each one pins a sha256 that
                   this verifier recomputes before it unpacks anything.
      generated    {install path: {"literal": text}} for files the build writes
                   instead of copying; @VERSION@ becomes the package version.
      version_file the product version metadata, cross-checked against the package.

    A record is committed source. It cannot make the verifier trust a build: it can
    only say which committed bytes end up where, and every byte is still hashed.
    """
    path = source / REGISTRY
    if not path.exists():
        return {}
    value = json.loads(path.read_bytes())
    if value.get('schema_version') != 1 or not isinstance(value.get('plugins'), dict):
        raise ValueError('Committed plugin staging records are required.')
    for plugin, record in value['plugins'].items():
        if not re.fullmatch(r'os-[a-z0-9][a-z0-9-]*', plugin) or not isinstance(record, dict):
            raise ValueError('Invalid committed plugin staging record: ' + str(plugin))
        if set(record) - RECORD_FIELDS:
            raise ValueError('Unknown fields in the staging record for ' + plugin + ': ' + ', '.join(sorted(set(record) - RECORD_FIELDS)))
        if record.get('staging') not in {'tree', 'repository', 'unsupported'}:
            raise ValueError('Unsupported staging shape for ' + plugin + '.')
    return value['plugins']


def plugin_record(source, plugin):
    """Refuse anything the committed records do not describe."""
    record = plugin_records(source).get(plugin)
    if record is None:
        raise ValueError('Unsupported additional release package: ' + plugin)
    if record['staging'] == 'unsupported':
        raise ValueError('Unsupported additional release package: ' + plugin + ': ' + str(record.get('reason', '')))
    abi = record.get('abi')
    if abi not in {'target', 'independent'} and (not isinstance(abi, str) or not re.fullmatch(ABI_PATTERN, abi)):
        raise ValueError('The staging record for ' + plugin + ' declares no ABI policy.')
    return record


def package_version(manifest):
    version = manifest.get('version')
    if not isinstance(version, str) or not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError('Release package has no usable version.')
    return version


def abi_allowed(record, abi):
    if record['abi'] == 'independent':
        return abi == INDEPENDENT_ABI
    if record['abi'] != 'target':
        return abi == record['abi']
    return bool(re.fullmatch(ABI_PATTERN, abi))


def source_path(root, value):
    """Resolve a path a staging record names, without leaving the plugin."""
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.+,@-]+(?:/[A-Za-z0-9_.+,@-]+)*', value) or '..' in PurePosixPath(value).parts:
        raise ValueError('Unsafe committed source path: ' + str(value))
    path = root / value
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Committed source file is missing or unsafe: ' + value)
    return path


def install_path(value, directory=False):
    if not isinstance(value, str) or not value.startswith('/') or '..' in PurePosixPath(value).parts:
        raise ValueError('Unsafe install path: ' + str(value))
    if value != '/' and (value.endswith('/') or not re.fullmatch(r'(?:/[A-Za-z0-9_.+,@-]+)+', value)):
        raise ValueError('Unsafe install path: ' + value)
    if not directory and value == '/':
        raise ValueError('Unsafe install path: ' + value)
    return value


def hook_source(src, phase):
    """A lifecycle hook is committed source: a regular file inside the plugin.

    Without this a hook can be a symbolic link, and the bytes the package runs
    then come from wherever the link points on the build host rather than from
    anything the repository carries.
    """
    relative = 'packaging/freebsd/+' + phase.upper().replace('-', '_')
    path = src / relative
    if not path.exists() and not path.is_symlink():
        return None
    return source_path(src, relative)


def checksum_entry(path, name):
    """Read one 'digest  filename' line out of a committed checksum list."""
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip('*') == name:
            return fields[0]
    raise ValueError('Committed checksum list does not cover ' + name + '.')


def vendored_files(root, record):
    """Unpack only artifacts whose committed digest this verifier has just checked."""
    staged, artifacts = {}, set()
    for item in record.get('vendored', []):
        if not isinstance(item, dict) or set(item) - VENDOR_FIELDS:
            raise ValueError('Invalid vendored artifact record.')
        pin = item.get('sha256')
        if not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin):
            raise ValueError('A vendored artifact may only be unpacked with a pinned digest: ' + str(item.get('artifact')))
        artifact = source_path(root, item.get('artifact'))
        data = artifact.read_bytes()
        if hashlib.sha256(data).hexdigest() != pin:
            raise ValueError('Vendored artifact differs from its committed digest: ' + item['artifact'])
        for field in ('sha256_file', 'checksums_file'):
            if item.get(field) and checksum_entry(source_path(root, item[field]), artifact.name) != pin:
                raise ValueError('Committed checksum file disagrees with the pinned digest: ' + item[field])
        artifacts.add(artifact.resolve())
        if item.get('archive') == 'xz':
            if item.get('members'):
                raise ValueError('A compressed stream has no members to select.')
            members = {None: install_path(item.get('install'))}
            contents = {None: lzma.decompress(data)}
        elif item.get('archive') == 'tar.gz':
            if item.get('install') or not isinstance(item.get('members'), dict) or not item['members']:
                raise ValueError('A vendored archive must name the members it stages.')
            members = {name: install_path(value) for name, value in item['members'].items()}
            contents = {}
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                for name in members:
                    try:
                        member = archive.getmember(name)
                    except KeyError as error:
                        raise ValueError('The vendored archive has no such member: ' + name) from error
                    if not member.isreg():
                        raise ValueError('A vendored archive may only stage regular files: ' + name)
                    contents[name] = archive.extractfile(member).read()
        elif item.get('archive') == 'pkg':
            if item.get('install') or not isinstance(item.get('members'), dict) or not item['members']:
                raise ValueError('A vendored archive must name the members it stages.')
            members = {name: install_path(value) for name, value in item['members'].items()}
            contents = {}
            inventory = python_members(artifact)
            for name in members:
                install_path(name)
                selected = [member for member in inventory if member.name == name]
                if len(selected) != 1 or not selected[0].isreg() or selected[0].mode & 0o7000:
                    raise ValueError('A vendored archive may only stage unique regular files: ' + name)
                contents[name] = subprocess.check_output(['tar', '-xOf', str(artifact), '-P', '--', name])
        else:
            raise ValueError('Unsupported vendored archive format: ' + str(item.get('archive')))
        for name, install in members.items():
            if install in staged:
                raise ValueError('Two vendored members claim the same install path: ' + install)
            staged[install] = contents[name]
    return staged, artifacts


def staged_tree(root, record, artifacts=frozenset()):
    """Map every committed file under src/ onto the path the build installs it at."""
    stage = record.get('stage')
    if not isinstance(stage, dict) or not stage:
        raise ValueError('The staging record names no source directory.')
    entries = []
    for prefix, destination in stage.items():
        if not isinstance(prefix, str) or not re.fullmatch(r'src(?:/[A-Za-z0-9_.+,@-]+)*', prefix):
            raise ValueError('A staged source directory must live under src/: ' + str(prefix))
        base = root / prefix
        if base.is_symlink() or not base.is_dir():
            raise ValueError('Staged source directory is missing: ' + prefix)
        entries.append((base, install_path(destination, directory=True).rstrip('/')))
    entries.sort(key=lambda entry: -len(str(entry[0])))
    result = {}
    for path in sorted((root / 'src').rglob('*')):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise ValueError('Committed source must not contain symbolic links: ' + relative.as_posix())
        if not path.is_file():
            continue
        parts = relative.parts
        if '__pycache__' in parts or path.suffix in SOURCE_NOISE or any(p == '.DS_Store' or p.startswith('._') for p in parts):
            continue
        if path.resolve() in artifacts:
            continue
        for base, destination in entries:
            if path.is_relative_to(base):
                install = install_path(destination + '/' + path.relative_to(base).as_posix())
                if install in result:
                    raise ValueError('Two committed files stage onto the same install path: ' + install)
                result[install] = path.read_bytes()
                break
        else:
            raise ValueError('Committed source file is outside every staged directory: /' + relative.as_posix())
    return result


def shared_files(repository, record):
    """Read explicitly registered shared files without leaving the repository."""
    shared = record.get('shared', {})
    if not isinstance(shared, dict):
        raise ValueError('Invalid shared file staging record.')
    result = {}
    for relative, destination in shared.items():
        path = source_path(repository, relative)
        install = install_path(destination)
        if any(install == other or install.startswith(other + '/') or other.startswith(install + '/')
               for other in result):
            raise ValueError('Shared files claim conflicting install paths: ' + install)
        result[install] = path.read_bytes()
    return result


def record_files(root, record, manifest, plugin, repository):
    """Rebuild, from committed source alone, what the package is allowed to contain."""
    version = package_version(manifest)
    shared = shared_files(repository, record)
    staged, artifacts = vendored_files(root, record)
    expected = staged_tree(root, record, artifacts)
    for install, content in staged.items():
        if install in expected:
            raise ValueError('A vendored member replaces a committed file: ' + install)
        expected[install] = content
    for install, content in shared.items():
        if any(install == other or install.startswith(other + '/') or other.startswith(install + '/')
               for other in expected):
            raise ValueError('A shared file conflicts with another staged file: ' + install)
        expected[install] = content
    for install, item in (record.get('generated') or {}).items():
        if not isinstance(item, dict) or set(item) != {'literal'} or not isinstance(item['literal'], str):
            raise ValueError('Invalid generated file record: ' + str(install))
        content = item['literal'].replace('@VERSION@', version).encode()
        install = install_path(install)
        if any(install == other or install.startswith(other + '/') or other.startswith(install + '/')
               for other in shared):
            raise ValueError('A generated file conflicts with a shared file: ' + install)
        if install in expected and expected[install] != content:
            raise ValueError('Generated file differs from the committed copy: ' + install)
        expected[install] = content
    if record['staging'] == 'repository':
        # The repository plugin rewrites its own product metadata; everything the
        # other shapes must satisfy still applies to it.
        expected = repository_files(expected, manifest, record)
    if record.get('version') != version:
        raise ValueError('Package version differs from the committed staging record: ' + version)
    declared = record.get('deps')
    dependencies = manifest.get('deps') or {}
    if not isinstance(declared, dict) or set(dependencies) != set(declared) or any(
            (dependencies[name] or {}).get('origin') != origin for name, origin in declared.items()):
        raise ValueError('Package dependencies differ from the committed staging record.')
    annotations = manifest.get('annotations') or {}
    if annotations.get('product_version', version) != version or annotations.get('product_id', plugin) != plugin:
        raise ValueError('Package annotations differ from the package identity.')
    check_version_file(expected, record, manifest, plugin)
    if manifest['abi'] == INDEPENDENT_ABI and any(content.startswith(b'\x7fELF') for content in expected.values()):
        raise ValueError('An ABI independent package must not contain native executables.')
    return expected


def check_version_file(expected, record, manifest, plugin):
    """The product metadata a package installs must describe the package.

    It must also be the JSON object OPNsense reads. register.php json_decodes
    every file under /usr/local/opnsense/version and skips any that does not
    decode or carries no product_id, printing "Ignoring invalid metadata" and
    leaving the plugin out of the configuration's plugin list for good: it is
    then never reinstalled by a firmware sync and never offered in the web
    interface. A package that ships anything else installs and then quietly does
    not exist, so json is the only format this accepts.
    """
    item = record.get('version_file')
    if not isinstance(item, dict) or set(item) != {'path', 'format'}:
        raise ValueError('The staging record names no product version file.')
    content = expected.get(install_path(item['path']))
    if content is None:
        raise ValueError('The package installs no product version file: ' + item['path'])
    if item['format'] != 'json':
        raise ValueError('Unsupported product version format: ' + str(item['format']))
    try:
        value = json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError('Product version metadata is not the JSON OPNsense registers: '
                         + item['path']) from error
    if not isinstance(value, dict):
        raise ValueError('Product version metadata is not the JSON OPNsense registers: ' + item['path'])
    if value.get('product_version') != manifest['version'] or value.get('product_id') != plugin:
        raise ValueError('Product version metadata differs from the package: ' + item['path'])


def repository_files(expected, manifest, record):
    """The repository plugin republishes its own metadata for the signed series."""
    version_path = install_path(record['version_file']['path'])
    if version_path not in expected:
        raise ValueError('The package installs no product version file: ' + version_path)
    metadata = json.loads(expected[version_path])
    product_abi = manifest.get('annotations', {}).get('product_abi', '')
    if not re.fullmatch(r'[0-9]{2}\.[17]', product_abi):
        raise ValueError('Repository plugin has an invalid product series.')
    metadata.update(product_abi=product_abi, product_version=manifest['version'])
    expected[version_path] = (json.dumps(metadata, separators=(',', ':')) + '\n').encode()
    if manifest.get('annotations') != metadata or manifest.get('deps', {}):
        raise ValueError('Repository plugin annotations or dependencies differ from source.')
    return expected


def manifest_script(text):
    """libpkg percent-encodes '%' and every non-ASCII byte when it serializes a hook."""
    return ''.join('%25' if byte == 0x25 else chr(byte) if byte < 0x80 else '%%%02x' % byte
                   for byte in text.encode())


def published_versions(site, name, version):
    for path in sorted((site / 'repo').rglob(name + '-' + version + '.pkg')):
        if path.parent.name == 'All' and path.is_file():
            yield path


def check_published_version(site, manifest):
    """A version that is already published may never be republished with new content."""
    name, version = manifest.get('name'), package_version(manifest)
    if not isinstance(name, str) or not re.fullmatch(r'os-[a-z0-9][a-z0-9-]*', name):
        raise ValueError('Release package has incorrect identity or ABI.')
    for published in published_versions(site, name, version):
        try:
            earlier = manifest_of(published)
        except (subprocess.CalledProcessError, ValueError) as error:
            raise ValueError('Published ' + name + ' ' + version + ' cannot be compared with this build.') from error
        if earlier.get('files') != manifest.get('files') or earlier.get('scripts') != manifest.get('scripts'):
            raise ValueError('Source changed without a version bump: ' + name + ' ' + version
                             + ' is already published with different content.')


def prepare_release(site, source, commit, packages):
    """Collect individually tested native targets before local signing."""
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('SOURCE_COMMIT must identify the tested source revision.')
    module = target_module(source)
    if module is None:
        raise ValueError('Committed build target recipes are required.')
    targets = module.enabled_targets(source / 'src/os-mihomo')
    by_tuple = {(t['abi'], t['product_abi']): t for t in targets}
    if len(by_tuple) != len(targets) or len({t['repository'] for t in targets}) != len(targets):
        raise ValueError('Enabled targets must have distinct ABI/product tuples and repositories.')
    released, additional, seen = [], [], set()
    for candidate in packages:
        candidate = candidate.resolve()
        manifest = manifest_of(candidate)
        abi, name = manifest['abi'], manifest['name']
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        check_published_version(site, manifest)
        # Publish under the identity the package carries, never under the file name a
        # build happened to leave it with: os-lang.pkg must not land on another package.
        filename = name + '-' + package_version(manifest) + '.pkg'
        if name == 'os-mihomo':
            key = (abi, manifest.get('annotations', {}).get('product_abi'))
            if key not in by_tuple or key in seen:
                raise ValueError('Unknown, disabled or duplicate native release target.')
            seen.add(key)
            target = by_tuple[key]
            report_path = Path(os.environ.get('TEST_REPORT', '')) if not released and os.environ.get('TEST_REPORT') else candidate.parent / 'test-report.json'
            value = json.loads(report_path.read_bytes())
            if value.get('package_sha256') != digest:
                raise ValueError('Package changed after native lifecycle testing.')
            value.update(path=target['repository'] + '/All/' + filename, sha256=digest, abi=abi)
            validate_attestation(value, manifest, target)
            verify_source_package(candidate, source, target=target)
            released.append(value)
            destinations = [value['path']]
        else:
            # Every other plugin is published through its committed staging record.
            plugin_record(source, name)
            verify_source_package(candidate, source, plugin=name)
            if abi == INDEPENDENT_ABI:
                repositories = {t['repository'] for t in targets}
                repositories.update('repo/' + p.name for p in (site / 'repo').glob('FreeBSD:*:amd64'))
                destinations = [repository + '/All/' + filename for repository in sorted(repositories)]
            else:
                matching = [t for t in targets if t['abi'] == abi]
                if len(matching) != 1:
                    raise ValueError('Additional package needs one unambiguous target repository.')
                destinations = [matching[0]['repository'] + '/All/' + filename]
        for destination in destinations:
            path = release_path(site, destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, path)
            if name != 'os-mihomo':
                additional.append({'path': destination, 'sha256': digest, 'name': name, 'abi': abi})
    if seen != set(by_tuple):
        raise ValueError('Every enabled target requires its own native tested package.')
    report = {'schema_version': 2, 'source_commit': commit, 'packages': released, 'additional_packages': additional,
              'superseded': superseded_archives(site)}
    (site / 'release.json').write_text(json.dumps(report, sort_keys=True) + '\n')
    return report


def superseded_archives(site):
    """Digests of the archives no catalog offers, so the signed report still covers them."""
    superseded = []
    for all_dir in sorted({path.parent for path in (site / 'repo').rglob('*.pkg') if path.parent.name == 'All'}):
        offered = set(newest_archives(all_dir))
        for path in sorted(all_dir.glob('*.pkg')):
            if path not in offered:
                superseded.append({'path': path.relative_to(site).as_posix(),
                                   'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return superseded

FINGERPRINT = '92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b'


def signature_check(payload, signature, public_key):
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(signature)
        stream.flush()
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key), '-signature', stream.name], input=payload, capture_output=True)
    if result.returncode:
        raise ValueError('Signature verification failed.')


def verify_catalog(archive, member, public_key):
    payload = subprocess.check_output(['tar', '-xOf', str(archive), member])
    signature = subprocess.check_output(['tar', '-xOf', str(archive), 'signature'])
    signature_check(hashlib.sha256(payload).hexdigest().encode(), signature, public_key)
    return payload


def pkg_version_key(version):
    """Order versions the way pkg(8) compares them: epoch, dotted parts, revision."""
    match = re.fullmatch(r'([^_,]+)(?:_([0-9]+))?(?:,([0-9]+))?', version)
    if not match:
        raise ValueError('Unrecognized package version in a catalog.')
    parts = [(int(number) if number else -1, rest)
             for number, rest in (re.fullmatch(r'([0-9]*)(.*)', part).groups() for part in match.group(1).split('.'))]
    return int(match.group(3) or 0), parts, int(match.group(2) or 0)


ARCHIVE_NAME = re.compile(r'(os-[a-z0-9][a-z0-9-]*?)-(' + VERSION_PATTERN + r')\.pkg')


def newest_archives(all_dir):
    """Choose what a catalog offers: the newest archive of every package in All/.

    Every published archive stays downloadable from All/, but each catalog lists
    one version per package. Offered several versions of one name, pkg 2.3 does not
    reliably take the newest: the published catalog served 1.2.9 over 1.2.10 to
    fresh installs and to upgrades from this repository. Offered one, pkg compares
    versions the usual way (1.2.10 > 1.2.9) and upgrades to it.
    """
    newest = {}
    for path in sorted(Path(all_dir).glob('*.pkg')):
        # Archives are published under the identity they carry (name-version.pkg).
        # Early archives use pkg's UCL manifest, so the name is what can be read
        # for every one of them; a JSON manifest must agree with it.
        match = ARCHIVE_NAME.fullmatch(path.name)
        if not match:
            raise ValueError('Archive is not published as name-version.pkg: ' + path.name)
        name, version = match.groups()
        try:
            manifest = manifest_of(path)
        except ValueError:
            manifest = None
        if manifest is not None and (manifest.get('name'), manifest.get('version')) != (name, version):
            raise ValueError('Archive name differs from the package it carries: ' + path.name)
        if name in newest and pkg_version_key(version) == pkg_version_key(newest[name][1]):
            raise ValueError('Two archives carry %s %s.' % (name, version))
        if name not in newest or pkg_version_key(version) > pkg_version_key(newest[name][1]):
            newest[name] = (path, version)
    return sorted(path for path, version in newest.values())


def check_catalog_versions(manifests, repo, relative):
    """Refuse a catalog that offers several versions of a package, or not its newest."""
    offered = {}
    for item in manifests:
        name, version = item.get('name'), item.get('version')
        if isinstance(name, str) and isinstance(version, str):
            if name in offered:
                raise ValueError('%s offers %s more than once; pkg would not reliably install the newest.'
                                 % (relative, name))
            offered[name] = version
    for path in sorted((repo / 'All').glob('*.pkg')):
        match = ARCHIVE_NAME.fullmatch(path.name)
        if match and match.group(1) in offered and \
                pkg_version_key(match.group(2)) > pkg_version_key(offered[match.group(1)]):
            raise ValueError('%s offers %s %s although %s is published.'
                             % (relative, match.group(1), offered[match.group(1)], path.name))


def verify(site, source=None):
    public_key = site / 'kazuha.pub'
    if hashlib.sha256(public_key.read_bytes()).hexdigest() != FINGERPRINT:
        raise ValueError('Incorrect fleet trust anchor.')
    report = json.loads((site / 'release.json').read_bytes())
    signature_check((site / 'release.json').read_bytes(), (site / 'release.sig').read_bytes(), public_key)
    if not re.fullmatch('[0-9a-f]{40}', report.get('source_commit', '')):
        raise ValueError('The signed release has no complete FreeBSD test report.')
    modern = report.get('schema_version') == 2
    entries = report.get('packages', []) if modern else [dict(report, path=report.get('package_path'), sha256=report.get('package_sha256'))]
    if not entries or (not modern and (report.get('ok') is not True or len(report.get('checks', [])) < 10)):
        raise ValueError('The signed release has no complete FreeBSD test report.')
    targets = {}
    if modern and source:
        module = target_module(source)
        enabled = module.enabled_targets(source / 'src/os-mihomo')
        targets = {(t['abi'], t['product_abi']): t for t in enabled}
        if len(targets) != len(enabled) or len({t['repository'] for t in enabled}) != len(enabled):
            raise ValueError('Enabled targets must have distinct ABI/product tuples and repositories.')
    seen = set()
    for entry in entries:
        package = release_path(site, entry['path'])
        if hashlib.sha256(package.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Package changed after FreeBSD testing.')
        target = None
        if modern:
            key = (entry.get('abi'), entry.get('product_abi'))
            if key in seen or (source and key not in targets):
                raise ValueError('Unknown, disabled or duplicate native release target.')
            seen.add(key)
            target = targets.get(key)
            manifest = manifest_of(package)
            if manifest.get('name') != 'os-mihomo':
                raise ValueError('Native lifecycle report must describe Mihomo.')
            validate_attestation(entry, manifest, target)
        if source:
            verify_source_package(package, source, target=target)
    if modern and source and seen != set(targets):
        raise ValueError('An enabled target has no native release report.')
    count = 0
    repositories = sorted({p.parent for p in (site / 'repo').rglob('packagesite.pkg')})
    listed = set()
    for repo in repositories:
        relative = repo.relative_to(site).as_posix()
        if not re.fullmatch(r'repo/FreeBSD:[0-9]+:amd64(?:/[0-9]{2}\.[17])?', relative):
            raise ValueError('Unsafe repository directory.')
        abi = relative.split('/')[1]
        if not (repo / 'meta.conf').is_file():
            raise ValueError('Repository has no meta.conf.')
        verify_catalog(repo / 'data.pkg', 'data', public_key)
        payload = verify_catalog(repo / 'packagesite.pkg', 'packagesite.yaml', public_key)
        manifests = [json.loads(line) for line in payload.splitlines() if line.strip()]
        check_catalog_versions(manifests, repo, relative)
        for item in manifests:
            path = (repo / item['path']).resolve()
            if not path.is_relative_to((repo / 'All').resolve()) or path.suffix != '.pkg' or item['abi'] not in {abi, 'FreeBSD:*:amd64'}:
                raise ValueError('Unsafe package path or incorrect ABI.')
            if hashlib.sha256(path.read_bytes()).hexdigest() != item['sum']:
                raise ValueError('Package digest verification failed.')
            count += 1
            listed.add(path)
    if any(release_path(site, entry['path']).resolve() not in listed for entry in entries):
        raise ValueError('Tested release package is missing from its catalog.')
    for entry in report.get('additional_packages', []):
        extra = release_path(site, entry['path'])
        if extra.resolve() not in listed or hashlib.sha256(extra.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Additional release package differs from the signed report.')
        if source:
            verify_source_package(extra, source, plugin=entry.get('name', 'os-sing-box'))
    # Catalogs offer only the newest version; every other published archive must
    # carry the digest the signed report recorded for it.
    superseded = {}
    for entry in report.get('superseded', []):
        superseded[release_path(site, entry.get('path')).resolve()] = entry.get('sha256')
    archives = sorted(path for path in (site / 'repo').rglob('*.pkg') if path.parent.name == 'All')
    for path in archives:
        if path.resolve() in listed:
            continue
        if superseded.get(path.resolve()) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('Archive is neither offered by a signed catalog nor recorded in the signed report: '
                             + path.relative_to(site).as_posix())
        count += 1
    if any(not path.is_file() for path in superseded):
        raise ValueError('A superseded archive recorded in the signed report is missing.')
    print('Catalog signatures, ' + str(count) + ' package digests and FreeBSD release report verified.')
    return report


def verify_source_package(package, source, plugin='os-mihomo', binary='mihomo', asset='clash-meta-freebsd-amd64.xz', target=None):
    """Rebuild the package from committed source and compare every byte of it."""
    manifest = manifest_of(package)
    check_manifest_shape(package, manifest)
    src = source / 'src' / plugin
    module = target_module(source) if plugin == 'os-mihomo' else None
    record = None
    if plugin == 'os-mihomo':
        allowed = bool(re.fullmatch(ABI_PATTERN, manifest['abi']))
    else:
        record = plugin_record(source, plugin)
        allowed = abi_allowed(record, manifest['abi'])
    if manifest['name'] != plugin or not allowed:
        raise ValueError('Release package has incorrect identity or ABI.')
    if record is None:
        expected = {'/' + str(p.relative_to(src / 'src')): p.read_bytes() for p in (src / 'src').rglob('*')
                    if p.is_file() and p.suffix not in {'.xz', '.pyc', '.pyo'} and '__pycache__' not in p.parts
                    and not any(part == '.DS_Store' or part.startswith('._') for part in p.parts)}
        if module:
            python_package = next((name for name in manifest.get('deps', {}) if re.fullmatch(r'python3[0-9]+', name)), 'python313')
            target = target or module.resolve_target(src, {'TARGET_ABI': manifest['abi'], 'TARGET_PRODUCT_ABI': manifest.get('annotations', {}).get('product_abi', ''), 'TARGET_PYTHON': '3.' + python_package[7:]})
            expected = module.staged_files(src, target, manifest['version'])
            if manifest.get('annotations') != module.product_metadata(src, target, manifest['version']) or manifest.get('arch') != target['arch']:
                raise ValueError('Product annotations or architecture differ from the target recipe.')
            origins = {'curl': 'ftp/curl', target['python_package']: 'lang/' + target['python_package'], target['pyyaml_package']: 'devel/py-pyyaml'}
            dependencies = manifest.get('deps', {})
            if set(dependencies) != set(origins) or any(dependencies[name].get('origin') != origin for name, origin in origins.items()):
                raise ValueError('Package dependencies differ from the target recipe.')
        elif binary:
            expected['/usr/local/bin/' + binary] = lzma.decompress((src / 'src/usr/local/bin' / asset).read_bytes())
    else:
        expected = record_files(src, record, manifest, plugin, source)
    actual = manifest['files']
    archive_paths = archive_members(package)
    if any('__pycache__' in Path(name).parts or Path(name).suffix in {'.pyc', '.pyo'} for name in archive_paths.values()):
        raise ValueError('Python bytecode must not be packaged.')
    if set(archive_paths) != set(actual) | {'/+MANIFEST', '/+COMPACT_MANIFEST'}:
        raise ValueError('Package archive inventory differs from its manifest.')
    if set(expected) != set(actual):
        raise ValueError('Package file inventory does not match the tested source.')
    for path in sorted(expected):
        # A reconstructed path is also a tar pattern below; keep it a plain path.
        install_path(path)
    for path, content in expected.items():
        if not file_checksum_matches(actual[path], content):
            raise ValueError('Package content differs from source: ' + path)
        archived = subprocess.check_output(['tar', '-xOf', str(package), '-P', '--', archive_paths[path]])
        if archived != content:
            raise ValueError('Package archive differs from its manifest: ' + path)
    scripts = manifest.get('scripts') or {}
    if set(scripts) - set(PHASES):
        raise ValueError('Package lifecycle hook differs from source.')
    for phase in PHASES:
        hook = hook_source(src, phase)
        content = None if hook is None else module.transform_hook(src, phase, target) if module else hook.read_text()
        if content is None:
            if phase in scripts:
                raise ValueError('Package lifecycle hook differs from source.')
            continue
        # libpkg url-decodes a hook it is handed and percent-encodes the one it
        # writes, so a build may escape before serialization or not at all.
        if scripts.get(phase, '').rstrip() not in {content.rstrip(), manifest_script(content).rstrip()}:
            raise ValueError('Package lifecycle hook differs from source.')


def audit_versions(site, source):
    """Report plugins whose committed source no longer matches a published version."""
    findings = []
    records = dict(plugin_records(source))
    # Mihomo uses its native target recipe instead of the additional-plugin registry.
    metadata = source / 'src/os-mihomo/src/usr/local/opnsense/version/mihomo'
    if metadata.is_file():
        records['os-mihomo'] = {'staging': 'target',
                                'version': package_version({'version': json.loads(metadata.read_text()).get('product_version')})}
    for plugin, record in sorted(records.items()):
        if record['staging'] == 'unsupported':
            findings.append((plugin, 'rejected', str(record.get('reason', ''))))
            continue
        version = record.get('version')
        if version is None:
            # Every shape pins its version; fall back to the committed metadata anyway.
            metadata = source / 'src' / plugin / 'src' / record['version_file']['path'].lstrip('/')
            version = json.loads(metadata.read_text()).get('product_version') if metadata.is_file() else None
        published = list(published_versions(site, plugin, version or ''))
        if not published:
            findings.append((plugin, 'unpublished', str(version)))
            continue
        for package in published:
            try:
                verify_source_package(package, source, plugin=plugin)
                findings.append((plugin, 'unchanged', str(version)))
            except (ValueError, subprocess.CalledProcessError) as error:
                findings.append((plugin, 'changed without a version bump', str(version) + ': ' + str(error)))
    for plugin, state, detail in findings:
        print(plugin + ': ' + state + (' (' + detail + ')' if detail else ''))
    return findings


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--audit', action='store_true', help='report plugins whose source changed without a version bump')
    parser.add_argument('--source-commit')
    parser.add_argument('--catalog-into', type=Path,
                        help='copy the newest archive of each package in SITE (an All/ directory) into this directory')
    parser.add_argument('packages', nargs='*', type=Path)
    args = parser.parse_args()
    if args.catalog_into:
        for archive in newest_archives(args.site):
            shutil.copyfile(archive, args.catalog_into / archive.name)
    elif args.prepare:
        prepare_release(args.site.resolve(), args.source.resolve(), args.source_commit or '', args.packages)
    elif args.audit:
        audit_versions(args.site.resolve(), args.source.resolve())
    else:
        verify(args.site.resolve(), args.source.resolve() if args.source else None)
