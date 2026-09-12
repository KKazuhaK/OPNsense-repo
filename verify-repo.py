#!/usr/bin/env python3
"""Verify signed pkg catalogs and package digests before Pages publication."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

FINGERPRINT = '92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b'


def verify_catalog(archive, member, public_key):
    payload = subprocess.check_output(['tar', '-xOf', str(archive), member])
    signature = subprocess.check_output(['tar', '-xOf', str(archive), 'signature'])
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(signature)
        stream.flush()
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key), '-signature', stream.name],
                                input=hashlib.sha256(payload).hexdigest().encode(), capture_output=True)
    if result.returncode:
        raise ValueError('Catalog signature verification failed: ' + archive.name)
    return payload


def verify(site):
    public_key = site / 'kazuha.pub'
    if hashlib.sha256(public_key.read_bytes()).hexdigest() != FINGERPRINT:
        raise ValueError('The public key does not match the fleet trust anchor.')
    repo = site / 'repo/FreeBSD:15:amd64'
    verify_catalog(repo / 'data.pkg', 'data', public_key)
    payload = verify_catalog(repo / 'packagesite.pkg', 'packagesite.yaml', public_key)
    manifests = [json.loads(line) for line in payload.splitlines() if line.strip()]
    if len(manifests) != 1 or manifests[0]['name'] != 'os-mihomo' or manifests[0]['abi'] != 'FreeBSD:15:amd64':
        raise ValueError('The catalog must contain only the FreeBSD 15 Mihomo plugin.')
    for item in manifests:
        package = (repo / item['path']).resolve()
        if not package.is_relative_to((repo / 'All').resolve()) or package.suffix != '.pkg':
            raise ValueError('Unsafe package path in the catalog.')
        if hashlib.sha256(package.read_bytes()).hexdigest() != item['sum']:
            raise ValueError('Package digest verification failed.')
    print('Catalog signatures and package digest verified: os-mihomo ' + manifests[0]['version'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', type=Path)
    args = parser.parse_args()
    verify(args.site.resolve())
