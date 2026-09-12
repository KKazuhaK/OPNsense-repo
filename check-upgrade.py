#!/usr/bin/env python3
"""Check signed package availability before choosing a target firmware upgrade."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen

spec = importlib.util.spec_from_file_location('verify_repo', Path(__file__).with_name('verify-repo.py'))
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


def select_target(report, abi, series):
    if not re.fullmatch(verification.ABI_PATTERN, abi) or not re.fullmatch(r'[0-9]{2}\.[17]', series):
        raise ValueError('Provide the official target ABI and OPNsense series.')
    matches = [p for p in report.get('packages', []) if p.get('abi') == abi and p.get('product_abi') == series]
    if report.get('schema_version') != 2 or len(matches) != 1:
        raise ValueError('The target has no signed native-tested package; defer the firmware upgrade.')
    return matches[0]


def check(url, abi, series):
    if not url.startswith('https://'):
        raise ValueError('The repository URL must use HTTPS.')
    with tempfile.TemporaryDirectory() as directory:
        site = Path(directory)

        def download(relative):
            path = site / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with urlopen(url.rstrip('/') + '/' + relative, timeout=30) as response:
                path.write_bytes(response.read())
            return path

        key = download('kazuha.pub')
        if hashlib.sha256(key.read_bytes()).hexdigest() != verification.FINGERPRINT:
            raise ValueError('Incorrect repository trust anchor.')
        payload = download('release.json').read_bytes()
        signature = download('release.sig').read_bytes()
        verification.signature_check(payload, signature, key)
        entry = select_target(json.loads(payload), abi, series)
        package_path = verification.release_path(site, entry['path'])
        repository = package_path.parent.parent.relative_to(site).as_posix()
        download(repository + '/meta.conf')
        download(repository + '/data.pkg')
        catalog = download(repository + '/packagesite.pkg')
        verification.verify_catalog(site / repository / 'data.pkg', 'data', key)
        manifests = [json.loads(line) for line in verification.verify_catalog(catalog, 'packagesite.yaml', key).splitlines() if line.strip()]
        match = [m for m in manifests if m.get('path') == 'All/' + package_path.name and m.get('name') == 'os-mihomo' and m.get('abi') == abi and m.get('sum') == entry['sha256']]
        if len(match) != 1:
            raise ValueError('The tested target package is missing from its signed catalog.')
        package = download(entry['path'])
        if hashlib.sha256(package.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('The target package digest differs from the signed report.')
        verification.validate_attestation(entry, verification.manifest_of(package))
        return entry


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--abi', required=True)
    parser.add_argument('--product-abi', required=True)
    parser.add_argument('--site-url', default='https://kkazuhak.github.io/OPNsense-repo')
    args = parser.parse_args()
    try:
        result = check(args.site_url, args.abi, args.product_abi)
        print('Ready: ' + args.product_abi + ' / ' + args.abi + ' / Python ' + result['python'] + '. Native package tests passed; verify target dependencies and the complete firmware flow before rollout.')
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, str(error) + '\n')
