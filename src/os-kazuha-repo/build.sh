#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="$SCRIPT_DIR/work/freebsd-pkg"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
DISTDIR="${DISTDIR:-$SCRIPT_DIR/dist}"
VERSION="${VERSION:-1.0.0}"
TARGET_PRODUCT_ABI="${TARGET_PRODUCT_ABI:-26.7}"
BUILD_PYTHON="${BUILD_PYTHON:-python${TARGET_PYTHON:-3.13}}"
export PYTHONDONTWRITEBYTECODE=1
die() { echo "error: $*" >&2; exit 1; }
for tool in pkg tar sha256 "$BUILD_PYTHON"; do command -v "$tool" >/dev/null 2>&1 || die "missing $tool"; done
[ "$("$BUILD_PYTHON" -B -c 'import sys; print(sys.version_info.major)')" = '3' ] || die 'the package builder requires Python 3'
case "$TARGET_PRODUCT_ABI" in [0-9][0-9].[17]) ;; *) die 'invalid target OPNsense series' ;; esac
case "$(pkg config ABI)" in FreeBSD:*:amd64) ;; *) die 'build on FreeBSD amd64' ;; esac
[ "$(sha256 -q "$SCRIPT_DIR/src/usr/local/share/kazuha-repo/kazuha.pub")" = '92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b' ] || die 'incorrect repository trust anchor'

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$DISTDIR"
(cd "$SCRIPT_DIR/src" && tar --exclude '.DS_Store' --exclude '._*' --exclude '__pycache__' --exclude '*.pyc' --exclude '*.pyo' -cf - .) | (cd "$STAGEDIR" && tar -xf -)
chmod 0755 "$STAGEDIR/usr/local/opnsense/scripts/firmware/repos/kazuha.sh"
chmod 0644 "$STAGEDIR/usr/local/share/kazuha-repo/kazuha.pub"

SCRIPT_DIR="$SCRIPT_DIR" STAGEDIR="$STAGEDIR" METADIR="$METADIR" VERSION="$VERSION" TARGET_PRODUCT_ABI="$TARGET_PRODUCT_ABI" "$BUILD_PYTHON" -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path

stage = Path(os.environ['STAGEDIR'])
source = Path(os.environ['SCRIPT_DIR'])
if any(p.name == '__pycache__' or p.suffix in {'.pyc', '.pyo'} for p in stage.rglob('*')):
    raise SystemExit('Python bytecode must not be packaged')
metadata_file = stage / 'usr/local/opnsense/version/kazuha-repo'
metadata = json.loads(metadata_file.read_text())
metadata.update(product_abi=os.environ['TARGET_PRODUCT_ABI'], product_version=os.environ['VERSION'])
metadata_file.write_text(json.dumps(metadata, separators=(',', ':')) + '\n')
files = {'/' + str(p.relative_to(stage)): '1$' + hashlib.sha256(p.read_bytes()).hexdigest()
         for p in sorted(stage.rglob('*')) if p.is_file()}
allowed = {
    '/usr/local/opnsense/scripts/firmware/repos/kazuha.sh',
    '/usr/local/opnsense/version/kazuha-repo',
    '/usr/local/share/kazuha-repo/kazuha.pub',
}
if set(files) != allowed:
    raise SystemExit('The repository plugin must contain only its hook, public key and metadata')
manifest = {
    'name': 'os-kazuha-repo', 'origin': 'opnsense/os-kazuha-repo', 'version': os.environ['VERSION'],
    'comment': 'Signed Kazuha repository with firmware series selection',
    'maintainer': 'https://github.com/KKazuhaK/', 'www': 'https://github.com/KKazuhaK/OPNsense-repo',
    'abi': 'FreeBSD:*:amd64', 'arch': 'freebsd:*:x86:64', 'prefix': '/usr/local', 'deps': {},
    'annotations': metadata, 'flatsize': sum(p.stat().st_size for p in stage.rglob('*') if p.is_file()),
    'desc': (source / 'packaging/freebsd/pkg-descr').read_text(), 'files': files,
    'scripts': {phase: (source / 'packaging/freebsd' / ('+' + phase.upper().replace('-', '_'))).read_text()
                for phase in ['post-install', 'post-deinstall']},
}
(Path(os.environ['METADIR']) / '+MANIFEST').write_text(json.dumps(manifest))
PY
pkg create -M "$METADIR/+MANIFEST" -r "$STAGEDIR" -o "$DISTDIR"
PACKAGE="$DISTDIR/os-kazuha-repo-$VERSION.pkg"
pkg info -F "$PACKAGE" >/dev/null
"$BUILD_PYTHON" -B - "$PACKAGE" <<'PY'
import json
from pathlib import PurePosixPath
import subprocess
import sys

manifest = json.loads(subprocess.check_output(['tar', '-xOf', sys.argv[1], '+MANIFEST']))
members = subprocess.check_output(['tar', '-tf', sys.argv[1]], text=True).splitlines()
paths = [name.removeprefix('./').lstrip('/') for name in members]
expected = {name.lstrip('/') for name in manifest['files']} | {'+MANIFEST', '+COMPACT_MANIFEST'}
if len(paths) != len(set(paths)) or set(paths) != expected:
    raise SystemExit('Package archive inventory differs from its manifest')
if any('__pycache__' in PurePosixPath(name).parts or PurePosixPath(name).suffix in {'.pyc', '.pyo'} for name in members):
    raise SystemExit('Python bytecode must not be packaged')
PY
sha256 "$PACKAGE"
echo "==> Package: $PACKAGE"
