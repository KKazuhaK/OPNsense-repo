#!/bin/sh
set -eu

PKG_NAME=os-mihomo
VERSION="${VERSION:-1.1.2}"
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
DISTDIR="${DISTDIR:-$SCRIPT_DIR/dist}"
ASSET="$SCRIPT_DIR/src/usr/local/bin/clash-meta-freebsd-amd64.xz"
MIHOMO_PYTHON="${MIHOMO_PYTHON:-python${TARGET_PYTHON:-3.13}}"
export PYTHONDONTWRITEBYTECODE=1

die() { echo "error: $*" >&2; exit 1; }
for tool in pkg tar xz sha256 uname freebsd-version "$MIHOMO_PYTHON"; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool; build on native FreeBSD / OPNsense"
done
TARGET_CONFIG="$("$MIHOMO_PYTHON" -B "$SCRIPT_DIR/packaging/target.py" --check-build "$SCRIPT_DIR")"
export TARGET_CONFIG
TARGET_ABI="$("$MIHOMO_PYTHON" -B -c 'import json,os; print(json.loads(os.environ["TARGET_CONFIG"])["target"]["abi"])')"
TARGET_SERIES="$("$MIHOMO_PYTHON" -B -c 'import json,os; print(json.loads(os.environ["TARGET_CONFIG"])["target"]["product_abi"])')"
TARGET_REPOSITORY="$("$MIHOMO_PYTHON" -B -c 'import json,os; print(json.loads(os.environ["TARGET_CONFIG"])["target"]["repository"])')"
WORKDIR="$SCRIPT_DIR/work/freebsd-pkg/$TARGET_ABI/$TARGET_SERIES"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
DISTDIR="$DISTDIR/$TARGET_ABI"
case "$TARGET_REPOSITORY" in */"$TARGET_SERIES") DISTDIR="$DISTDIR/$TARGET_SERIES" ;; esac
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
import importlib.util
stage = Path(os.environ['STAGEDIR'])
source = Path(os.environ['SCRIPT_DIR'])
spec = importlib.util.spec_from_file_location('build_target', source / 'packaging/target.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
build = json.loads(os.environ['TARGET_CONFIG'])
target = build['target']
version = os.environ['VERSION']
if any(p.name == '__pycache__' or p.suffix in {'.pyc', '.pyo'} for p in stage.rglob('*')):
    raise SystemExit('Python bytecode must not be staged')
for path, content in helper.staged_files(source, target, version).items():
    destination = stage / path.lstrip('/')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
files = { '/' + str(p.relative_to(stage)): '1$' + hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(stage.rglob('*')) if p.is_file() }
manifest = {
    'name': 'os-mihomo', 'origin': 'opnsense/os-mihomo', 'version': version,
    'comment': 'Mihomo proxy integration with explicit transparent routing',
    'maintainer': 'https://github.com/KKazuhaK/', 'www': 'https://github.com/KKazuhaK/OPNsense-repo',
    'abi': target['abi'], 'arch': target['arch'], 'prefix': '/usr/local',
    'flatsize': sum(p.stat().st_size for p in stage.rglob('*') if p.is_file()),
    'deps': build['deps'], 'desc': (source / 'packaging/freebsd/pkg-descr').read_text(), 'files': files,
    'annotations': helper.product_metadata(source, target, version),
    'scripts': {phase.lower().replace('_', '-').removeprefix('+'): helper.transform_hook(source, phase, target)
                for phase in ['+PRE_INSTALL', '+POST_INSTALL', '+PRE_DEINSTALL', '+POST_DEINSTALL']},
}
(Path(os.environ['METADIR']) / '+MANIFEST').write_text(json.dumps(manifest))
(Path(os.environ['METADIR']) / 'build-target.json').write_text(json.dumps(build, sort_keys=True) + '\n')
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
