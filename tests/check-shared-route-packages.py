#!/usr/bin/env python3
"""Bind all route-owning package candidates to one committed shared source."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile


REQUIRED = {
    'os-mihomo': ('route_control.py', 'tun_policy_routing.py'),
    'os-sing-box': ('route_control.py', 'tun_policy_routing.py'),
    'os-easytier': ('route_control.py',),
}


def load_verifier(source):
    path = source / 'verify-repo.py'
    spec = importlib.util.spec_from_file_location('shared_route_release_verifier', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shared_destinations(source, verifier):
    """Return the committed source-to-install mapping for each affected package."""
    records = verifier.plugin_records(source)
    target = verifier.target_module(source)
    if target is None:
        raise ValueError('The Mihomo target recipe is unavailable.')
    mappings = {
        'os-mihomo': {'src/common/' + name: destination
                      for name, destination in target.SHARED_FILES.items()},
    }
    for plugin in ('os-sing-box', 'os-easytier'):
        mappings[plugin] = dict(records[plugin].get('shared', {}))
    result = {}
    for plugin, names in REQUIRED.items():
        expected = {'src/common/' + name for name in names}
        selected = {name: destination for name, destination in mappings[plugin].items()
                    if name in expected}
        if set(selected) != expected or len(set(selected.values())) != len(selected):
            raise ValueError(plugin + ' does not stage every required shared routing source exactly once.')
        result[plugin] = selected
    return result


def member_bytes(package, install, verifier):
    members = verifier.archive_members(package)
    if install not in members:
        raise ValueError(package.name + ' does not contain ' + install + '.')
    return subprocess.check_output(
        ['tar', '-xOf', str(package), '-P', '--', members[install]],
        stderr=subprocess.DEVNULL)


def committed_source_bytes(source, source_commit, relative):
    """Read one shared source exactly as recorded by the named Git commit."""
    try:
        return subprocess.check_output(
            ['git', '-C', str(source), 'show', source_commit + ':' + relative],
            stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as error:
        raise ValueError('The shared routing source is absent from the source commit.') from error


def bind_packages(source, packages, source_commit):
    """Verify source/package identity and return a hash report for the three candidates."""
    source = Path(source).resolve()
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('A complete source commit is required for package binding.')
    verifier = load_verifier(source)
    mappings = shared_destinations(source, verifier)
    selected = {}
    for package in map(Path, packages):
        manifest = verifier.manifest_of(package)
        name = manifest.get('name')
        if name not in REQUIRED or name in selected:
            raise ValueError('Expected one candidate for each shared-route package.')
        selected[name] = (package.resolve(), manifest)
    if set(selected) != set(REQUIRED):
        raise ValueError('Expected one candidate for each shared-route package.')

    source_hashes = {}
    for names in mappings.values():
        for relative in names:
            path = verifier.source_path(source, relative)
            committed = committed_source_bytes(source, source_commit, relative)
            if path.read_bytes() != committed:
                raise ValueError('The shared routing source differs from the source commit.')
            source_hashes[relative] = hashlib.sha256(committed).hexdigest()

    package_reports = []
    route_hashes = set()
    tun_hashes = set()
    package_abis = set()
    for name in REQUIRED:
        package, manifest = selected[name]
        verifier.verify_source_package(package, source, plugin=name)
        package_abis.add(manifest.get('abi'))
        embedded = {}
        for relative, install in mappings[name].items():
            payload = member_bytes(package, install, verifier)
            digest = hashlib.sha256(payload).hexdigest()
            if digest != source_hashes[relative]:
                raise ValueError(name + ' embeds routing code from a different source revision.')
            if not verifier.file_checksum_matches(manifest.get('files', {}).get(install), payload):
                raise ValueError(name + ' manifest does not bind the shared routing payload.')
            embedded[relative] = {'install': install, 'sha256': digest}
            (route_hashes if relative.endswith('/route_control.py') else tun_hashes).add(digest)
        try:
            package_path = str(package.relative_to(source))
        except ValueError:
            package_path = str(package)
        package_reports.append({
            'name': name,
            'version': manifest.get('version'),
            'abi': manifest.get('abi'),
            'path': package_path,
            'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
            'shared': embedded,
        })
    if len(package_abis) != 1 or not re.fullmatch(r'FreeBSD:[0-9]+:amd64', str(next(iter(package_abis), ''))):
        raise ValueError('The three shared-route candidates do not have one native FreeBSD ABI.')
    if len(route_hashes) != 1 or len(tun_hashes) != 1:
        raise ValueError('Shared routing payload hashes differ between package candidates.')
    return {
        'schema_version': 1,
        'source_commit': source_commit,
        'source': dict(sorted(source_hashes.items())),
        'packages': package_reports,
    }


def current_commit(source):
    value = subprocess.check_output(
        ['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('The checkout has no complete source commit.')
    return value


def write_report(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', prefix='.shared-route-', dir=path.parent,
                                     delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    temporary.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('packages', nargs='+', type=Path)
    args = parser.parse_args(argv)
    if current_commit(args.source.resolve()) != args.source_commit:
        raise ValueError('Package binding source commit differs from the checkout.')
    write_report(args.output, bind_packages(args.source, args.packages, args.source_commit))


if __name__ == '__main__':
    main()
