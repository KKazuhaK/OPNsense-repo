#!/usr/bin/env python3
"""Verify signed catalogs, every listed package, and the tested release report."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

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
    if report.get('ok') is not True or len(report.get('checks', [])) < 10 or not re.fullmatch('[0-9a-f]{40}', report.get('source_commit', '')):
        raise ValueError('The signed release has no complete FreeBSD test report.')
    package = site / report['package_path']
    if not package.resolve().is_relative_to((site / 'repo/FreeBSD:15:amd64/All').resolve()):
        raise ValueError('Unsafe release package path.')
    if hashlib.sha256(package.read_bytes()).hexdigest() != report['package_sha256']:
        raise ValueError('Package changed after FreeBSD testing.')
    count = 0
    for repo in sorted((site / 'repo').glob('FreeBSD:*:amd64')):
        verify_catalog(repo / 'data.pkg', 'data', public_key)
        payload = verify_catalog(repo / 'packagesite.pkg', 'packagesite.yaml', public_key)
        manifests = [json.loads(line) for line in payload.splitlines() if line.strip()]
        for item in manifests:
            path = (repo / item['path']).resolve()
            if not path.is_relative_to((repo / 'All').resolve()) or path.suffix != '.pkg' or item['abi'] not in {repo.name, 'FreeBSD:*:amd64'}:
                raise ValueError('Unsafe package path or incorrect ABI.')
            if hashlib.sha256(path.read_bytes()).hexdigest() != item['sum']:
                raise ValueError('Package digest verification failed.')
            count += 1
    if source:
        verify_source_package(package, source)
    for entry in report.get('additional_packages', []):
        extra = site / entry['path']
        if not extra.resolve().is_relative_to((site / 'repo/FreeBSD:15:amd64/All').resolve()) or hashlib.sha256(extra.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Additional release package differs from the signed report.')
        if source:
            verify_source_package(extra, source, 'os-sing-box', 'sing-box', 'bsd-box-reF1nd-freebsd-amd64.xz')
    print('Catalog signatures, ' + str(count) + ' package digests and FreeBSD release report verified.')
    return report


def verify_source_package(package, source, plugin='os-mihomo', binary='mihomo', asset='clash-meta-freebsd-amd64.xz'):
    import lzma
    manifest = json.loads(subprocess.check_output(['tar', '-xOf', str(package), '+MANIFEST']))
    src = source / 'src' / plugin
    if manifest['name'] != plugin or manifest['abi'] != 'FreeBSD:15:amd64':
        raise ValueError('Release package has incorrect identity or ABI.')
    expected = {'/' + str(p.relative_to(src / 'src')): p.read_bytes() for p in (src / 'src').rglob('*')
                if p.is_file() and p.suffix != '.xz' and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    expected['/usr/local/bin/' + binary] = lzma.decompress((src / 'src/usr/local/bin' / asset).read_bytes())
    actual = manifest['files']
    members = subprocess.check_output(['tar', '-tf', str(package)], text=True).splitlines()
    archive_paths = { '/' + name.removeprefix('./').lstrip('/'): name for name in members }
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
        if hook.exists() and manifest['scripts'][phase].rstrip() != hook.read_text().rstrip():
            raise ValueError('Package lifecycle hook differs from source.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', type=Path)
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    verify(args.site.resolve(), args.source.resolve() if args.source else None)
