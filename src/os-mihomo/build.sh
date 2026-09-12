#!/bin/sh
set -eu

PKG_NAME=os-mihomo
VERSION="${VERSION:-1.1.1}"
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="$SCRIPT_DIR/work/freebsd-pkg"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
DISTDIR="${DISTDIR:-$SCRIPT_DIR/dist}"
ASSET="$SCRIPT_DIR/src/usr/local/bin/clash-meta-freebsd-amd64.xz"
MIHOMO_PYTHON="${MIHOMO_PYTHON:-python3.13}"
export PYTHONDONTWRITEBYTECODE=1

die() { echo "error: $*" >&2; exit 1; }
for tool in pkg tar xz sha256 "$MIHOMO_PYTHON"; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool; build on FreeBSD 15 / OPNsense"
done
[ "$("$MIHOMO_PYTHON" -B -c 'import sys; print("%s.%s" % sys.version_info[:2])')" = '3.13' ] || die 'the build interpreter must be Python 3.13, matching python313'
[ "$(pkg config ABI)" = 'FreeBSD:15:amd64' ] || die 'only FreeBSD:15:amd64 is supported'
[ "${ABI:-FreeBSD:15:amd64}" = 'FreeBSD:15:amd64' ] || die 'only FreeBSD:15:amd64 is supported'
"$MIHOMO_PYTHON" -B -c 'import yaml' || die 'PyYAML for Python 3.13 is required'
[ -f "$ASSET" ] || die 'the bundled FreeBSD binary archive is missing'

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$DISTDIR"
(cd "$SCRIPT_DIR/src" && tar --exclude '.DS_Store' --exclude '._*' --exclude '*.xz' --exclude '__pycache__' --exclude '*.pyc' --exclude '*.pyo' -cf - .) |
    (cd "$STAGEDIR" && tar -xf -)
xz -t "$ASSET"
xz -dc "$ASSET" > "$STAGEDIR/usr/local/bin/mihomo"
chmod 0755 "$STAGEDIR/usr/local/bin/mihomo" "$STAGEDIR/usr/bin/mihomo_sub" \
    "$STAGEDIR/usr/local/etc/rc.d/mihomo" \
    "$STAGEDIR/usr/local/opnsense/scripts/mihomo/mihomo.py" \
    "$STAGEDIR/usr/local/opnsense/scripts/mihomo/setup_unbound.php"

# User state and runtime configuration are deliberately absent from the package.
[ ! -e "$STAGEDIR/usr/local/etc/mihomo/config.yaml" ] || die 'runtime config must not be packaged'
[ ! -e "$STAGEDIR/usr/local/etc/mihomo/sub/env" ] || die 'subscription credentials must not be packaged'
[ ! -e "$STAGEDIR/etc/rc.conf.d/mihomo" ] || die 'rc state must not be packaged'
[ ! -e "$STAGEDIR/usr/local/etc/mihomo" ] || die 'the legacy deletion target must not be packaged'

STAGEDIR="$STAGEDIR" METADIR="$METADIR" SCRIPT_DIR="$SCRIPT_DIR" VERSION="$VERSION" "$MIHOMO_PYTHON" -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
stage = Path(os.environ['STAGEDIR'])
source = Path(os.environ['SCRIPT_DIR'])
if any(p.name == '__pycache__' or p.suffix in {'.pyc', '.pyo'} for p in stage.rglob('*')):
    raise SystemExit('Python bytecode must not be staged')
files = { '/' + str(p.relative_to(stage)): '1$' + hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(stage.rglob('*')) if p.is_file() }
deps = {}
for name in ['curl', 'python313', 'py313-pyyaml']:
    value = subprocess.check_output(['pkg', 'query', '%o %v', name], text=True).strip().split()
    if len(value) != 2:
        raise SystemExit('missing build dependency: ' + name)
    deps[name] = {'origin': value[0], 'version': value[1]}
python_version = deps['python313']['version'].split('_', 1)[0].split(',', 1)[0]
if python_version != '.'.join(map(str, sys.version_info[:3])):
    raise SystemExit('The build interpreter version differs from the python313 package dependency')
manifest = {
    'name': 'os-mihomo', 'origin': 'opnsense/os-mihomo', 'version': os.environ['VERSION'],
    'comment': 'Mihomo proxy integration with explicit transparent routing',
    'maintainer': 'https://github.com/KKazuhaK/', 'www': 'https://github.com/KKazuhaK/OPNsense-repo',
    'abi': 'FreeBSD:15:amd64', 'arch': 'freebsd:15:x86:64', 'prefix': '/usr/local',
    'flatsize': sum(p.stat().st_size for p in stage.rglob('*') if p.is_file()),
    'deps': deps, 'desc': (source / 'packaging/freebsd/pkg-descr').read_text(), 'files': files,
    'scripts': {phase.lower().replace('_', '-').removeprefix('+'): (source / 'packaging/freebsd' / phase).read_text()
                for phase in ['+PRE_INSTALL', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL']},
}
(Path(os.environ['METADIR']) / '+MANIFEST').write_text(json.dumps(manifest))
PY
pkg create -M "$METADIR/+MANIFEST" -r "$STAGEDIR" -o "$DISTDIR"
PACKAGE="$DISTDIR/$PKG_NAME-$VERSION.pkg"
[ -f "$PACKAGE" ] || die 'pkg did not create the expected package'
pkg info -F "$PACKAGE" >/dev/null
"$MIHOMO_PYTHON" -B - "$PACKAGE" <<'PY'
from pathlib import PurePosixPath
import subprocess
import sys
members = subprocess.check_output(['tar', '-tf', sys.argv[1]], text=True).splitlines()
if any('__pycache__' in PurePosixPath(name).parts or PurePosixPath(name).suffix in {'.pyc', '.pyo'} for name in members):
    raise SystemExit('Python bytecode must not be packaged')
PY
sha256 "$PACKAGE"
echo "==> Package: $PACKAGE"
