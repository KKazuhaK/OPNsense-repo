#!/usr/bin/env python3
"""Verify signed catalogs, every listed package, and the tested release report."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import importlib.util
import os
import shutil

ABI_PATTERN = r'FreeBSD:[0-9]+:amd64'


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


def manifest_of(package):
    return json.loads(subprocess.check_output(['tar', '-xOf', str(package), '+MANIFEST']))


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
            value.update(path=target['repository'] + '/All/' + candidate.name, sha256=digest, abi=abi)
            validate_attestation(value, manifest, target)
            verify_source_package(candidate, source, target=target)
            released.append(value)
            destinations = [value['path']]
        elif name == 'os-kazuha-repo' and abi == 'FreeBSD:*:amd64':
            verify_source_package(candidate, source, plugin=name, binary=None, asset=None)
            repositories = {t['repository'] for t in targets}
            repositories.update('repo/' + p.name for p in (site / 'repo').glob('FreeBSD:*:amd64'))
            destinations = [repository + '/All/' + candidate.name for repository in sorted(repositories)]
        elif name == 'os-sing-box' and re.fullmatch(ABI_PATTERN, abi):
            matching = [t for t in targets if t['abi'] == abi]
            if len(matching) != 1:
                raise ValueError('Additional package needs one unambiguous target repository.')
            verify_source_package(candidate, source, name, 'sing-box', 'bsd-box-reF1nd-freebsd-amd64.xz')
            destinations = [matching[0]['repository'] + '/All/' + candidate.name]
        else:
            raise ValueError('Unsupported additional release package.')
        for destination in destinations:
            path = release_path(site, destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, path)
            if name != 'os-mihomo':
                additional.append({'path': destination, 'sha256': digest, 'name': name, 'abi': abi})
    if seen != set(by_tuple):
        raise ValueError('Every enabled target requires its own native tested package.')
    report = {'schema_version': 2, 'source_commit': commit, 'packages': released, 'additional_packages': additional}
    (site / 'release.json').write_text(json.dumps(report, sort_keys=True) + '\n')
    return report

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
            if entry.get('name', 'os-sing-box') == 'os-kazuha-repo':
                verify_source_package(extra, source, 'os-kazuha-repo', None, None)
            else:
                verify_source_package(extra, source, 'os-sing-box', 'sing-box', 'bsd-box-reF1nd-freebsd-amd64.xz')
    print('Catalog signatures, ' + str(count) + ' package digests and FreeBSD release report verified.')
    return report


def verify_source_package(package, source, plugin='os-mihomo', binary='mihomo', asset='clash-meta-freebsd-amd64.xz', target=None):
    import lzma
    manifest = json.loads(subprocess.check_output(['tar', '-xOf', str(package), '+MANIFEST']))
    src = source / 'src' / plugin
    if manifest['name'] != plugin or not (re.fullmatch(ABI_PATTERN, manifest['abi']) or plugin == 'os-kazuha-repo' and manifest['abi'] == 'FreeBSD:*:amd64'):
        raise ValueError('Release package has incorrect identity or ABI.')
    expected = {'/' + str(p.relative_to(src / 'src')): p.read_bytes() for p in (src / 'src').rglob('*')
                if p.is_file() and p.suffix not in {'.xz', '.pyc', '.pyo'} and '__pycache__' not in p.parts
                and not any(part == '.DS_Store' or part.startswith('._') for part in p.parts)}
    module = target_module(source) if plugin == 'os-mihomo' else None
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
    elif plugin == 'os-kazuha-repo':
        version_path = '/usr/local/opnsense/version/kazuha-repo'
        metadata = json.loads(expected[version_path])
        product_abi = manifest.get('annotations', {}).get('product_abi', '')
        if not re.fullmatch(r'[0-9]{2}\.[17]', product_abi):
            raise ValueError('Repository plugin has an invalid product series.')
        metadata.update(product_abi=product_abi, product_version=manifest['version'])
        expected[version_path] = (json.dumps(metadata, separators=(',', ':')) + '\n').encode()
        if manifest.get('annotations') != metadata or manifest.get('deps', {}):
            raise ValueError('Repository plugin annotations or dependencies differ from source.')
    elif binary:
        expected['/usr/local/bin/' + binary] = lzma.decompress((src / 'src/usr/local/bin' / asset).read_bytes())
    actual = manifest['files']
    members = subprocess.check_output(['tar', '-tf', str(package)], text=True).splitlines()
    archive_paths = { '/' + name.removeprefix('./').lstrip('/'): name for name in members }
    if any('__pycache__' in Path(name).parts or Path(name).suffix in {'.pyc', '.pyo'} for name in members):
        raise ValueError('Python bytecode must not be packaged.')
    archived_files = [ '/' + name.removeprefix('./').lstrip('/') for name in members if not name.endswith('/') ]
    if len(archived_files) != len(set(archived_files)) or set(archived_files) != set(actual) | {'/+MANIFEST', '/+COMPACT_MANIFEST'}:
        raise ValueError('Package archive inventory differs from its manifest.')
    if set(expected) != set(actual):
        raise ValueError('Package file inventory does not match the tested source.')
    for path, content in expected.items():
        if actual[path] != '1$' + hashlib.sha256(content).hexdigest():
            raise ValueError('Package content differs from source: ' + path)
        archived = subprocess.check_output(['tar', '-xOf', str(package), archive_paths[path]])
        if archived != content:
            raise ValueError('Package archive differs from its manifest: ' + path)
    for phase in ('pre-install', 'post-install', 'pre-deinstall', 'post-deinstall'):
        hook = src / 'packaging/freebsd' / ('+' + phase.upper().replace('-', '_'))
        content = module.transform_hook(src, phase, target) if module else hook.read_text() if hook.exists() else None
        if content is not None and manifest['scripts'][phase].rstrip() != content.rstrip():
            raise ValueError('Package lifecycle hook differs from source.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--source-commit')
    parser.add_argument('packages', nargs='*', type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare_release(args.site.resolve(), args.source.resolve(), args.source_commit or '', args.packages)
    else:
        verify(args.site.resolve(), args.source.resolve() if args.source else None)
