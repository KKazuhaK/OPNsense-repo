#!/bin/sh
set -eu

PKG_NAME="${PKG_NAME:-os-sing-box}"
VERSION="${VERSION:-1.1.4}"
ORIGIN="${ORIGIN:-opnsense/os-sing-box}"
COMMENT="${COMMENT:-sing-box proxy integration for OPNsense}"
MAINTAINER="${MAINTAINER:-https://github.com/Opnwall/}"
WWW="${WWW:-https://sing-box.sagernet.org/}"
PREFIX="${PREFIX:-/usr/local}"
FORMAT="${FORMAT:-tgz}"
ABI="${ABI:-native}"
OUTPUT_NAME="${OUTPUT_NAME:-${PKG_NAME}-${VERSION}.pkg}"
SING_BOX_ASSET="${SING_BOX_ASSET:-bsd-box-reF1nd-freebsd-amd64.xz}"
SING_BOX_DOWNLOAD_URL="${SING_BOX_DOWNLOAD_URL:-https://github.com/Vincent-Loeng/bsd-box/releases/latest/download/$SING_BOX_ASSET}"
DOWNLOAD_TIMEOUT="${DOWNLOAD_TIMEOUT:-300}"
SING_BOX_PYTHON="${SING_BOX_PYTHON:-python${TARGET_PYTHON:-3.13}}"

SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${WORKDIR:-"$SCRIPT_DIR/work/freebsd-pkg"}"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
PLIST="$WORKDIR/pkg-plist"
DISTDIR="${DISTDIR:-"$SCRIPT_DIR/dist"}"
DOWNLOADDIR="$WORKDIR/downloads"

die() {
    echo "error: $*" >&2
    exit 1
}

need_file() {
    [ -e "$SCRIPT_DIR/$1" ] || die "missing required file: $1"
}

command -v pkg >/dev/null 2>&1 || die "pkg command not found. Run this script on FreeBSD/OPNsense."
command -v tar >/dev/null 2>&1 || die "tar command not found."
command -v xz >/dev/null 2>&1 || die "xz command not found."
command -v sha256 >/dev/null 2>&1 || die "sha256 command not found."
command -v "$SING_BOX_PYTHON" >/dev/null 2>&1 || die "$SING_BOX_PYTHON command not found."
if ! command -v fetch >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    die "fetch or curl command not found."
fi

need_file "src/usr/local/etc/sing-box/config.json.sample"
need_file "src/usr/local/etc/sing-box/sub/env.sample"
need_file "src/usr/local/etc/sing-box/sub/sub.sh"
need_file "src/usr/local/etc/sing-box/sub/template.json.sample"
need_file "src/usr/local/etc/rc.d/sing-box"
need_file "src/etc/rc.conf.d/sing_box.sample"
need_file "src/usr/local/opnsense/service/conf/actions.d/actions_sing-box.conf"
need_file "src/usr/local/etc/inc/plugins.inc.d/sing_box.inc"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/SingBox/Menu/Menu.xml"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/SingBox/ACL/ACL.xml"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/SingBox/IndexController.php"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/SingBox/Api/ServiceController.php"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/SingBox/Api/SettingsController.php"
need_file "src/usr/local/opnsense/mvc/app/views/OPNsense/SingBox/index.volt"
need_file "src/usr/local/opnsense/scripts/singbox/singbox.php"
need_file "src/usr/local/opnsense/scripts/singbox/config_mirror.py"
need_file "src/usr/local/opnsense/scripts/singbox/config_setup.php"
need_file "src/usr/local/opnsense/scripts/singbox/integration.py"
need_file "src/usr/local/opnsense/scripts/singbox/routing.py"
need_file "src/usr/local/opnsense/scripts/singbox/native_route.py"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/SingBox/Backup.php"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/SingBox/Backup.xml"
need_file "src/usr/local/etc/rc.d/sing-box-backup"
need_file "src/usr/local/etc/rc.syshook.d/start/15-singbox-backup"
need_file "../common/config_backup.py"
need_file "../common/config_backup.php"
need_file "../common/process_identity.py"
need_file "../common/route_control.py"
need_file "../common/tun_policy_routing.py"
need_file "src/usr/bin/sing_box_sub"
need_file "src/usr/local/bin/$SING_BOX_ASSET"
need_file "packaging/freebsd/+MANIFEST.in"
need_file "packaging/freebsd/+PRE_INSTALL"
need_file "packaging/freebsd/+POST_INSTALL"
need_file "packaging/freebsd/+PRE_DEINSTALL"
need_file "packaging/freebsd/+POST_DEINSTALL"
need_file "packaging/freebsd/pkg-descr"

case "$ABI" in
    universal)
        PKG_ABI="FreeBSD:*:amd64"
        PKG_ARCH="freebsd:*:x86:64"
        ;;
    native)
        PKG_ABI="$(env -u ABI pkg config ABI)"
        case "$PKG_ABI" in
            FreeBSD:*:amd64) ;;
            *) die "unsupported native ABI: $PKG_ABI" ;;
        esac
        ABI_MAJOR="$(printf '%s\n' "$PKG_ABI" | awk -F: '{print $2}')"
        PKG_ARCH="freebsd:${ABI_MAJOR}:x86:64"
        ;;
    FreeBSD:*:amd64)
        PKG_ABI="$ABI"
        ABI_MAJOR="$(printf '%s\n' "$PKG_ABI" | awk -F: '{print $2}')"
        PKG_ARCH="freebsd:${ABI_MAJOR}:x86:64"
        ;;
    *)
        die "unsupported ABI: $ABI"
        ;;
esac
unset ABI || true

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$DISTDIR" "$DOWNLOADDIR"

copy_tree() {
    src="$1"
    dst="$2"
    mkdir -p "$dst"
    (cd "$src" && tar --exclude '.DS_Store' --exclude '._*' --exclude '*.xz' --exclude '__pycache__' --exclude '*.pyc' -cf - .) | (cd "$dst" && tar -xf -)
}

download_file() {
    download_url="$1"
    download_dst="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --retry-all-errors --retry-delay 2 --connect-timeout 30 --max-time "$DOWNLOAD_TIMEOUT" -o "$download_dst" "$download_url"
    else
        fetch -T "$DOWNLOAD_TIMEOUT" -q -o "$download_dst" "$download_url"
    fi
}

unpack_binary() {
    archive="$1"
    binary_dst="$2"
    tmp="$binary_dst.tmp"

    rm -f "$tmp" "$binary_dst"
    if xz -t "$archive" >/dev/null 2>&1; then
        xz -dc "$archive" > "$tmp"
    else
        cp "$archive" "$tmp"
    fi
    mv -f "$tmp" "$binary_dst"
    chmod 0755 "$binary_dst"
    [ -s "$binary_dst" ] || die "binary is empty: $archive"
}

prepare_binary() {
    asset="$1"
    binary_url="$2"
    binary_dst="$3"
    local_asset="$SCRIPT_DIR/src/usr/local/bin/$asset"
    archive="$binary_dst.download"

    mkdir -p "$DOWNLOADDIR"
    if [ -f "$local_asset" ]; then
        echo "==> Using local asset $local_asset"
        unpack_binary "$local_asset" "$binary_dst"
    else
        echo "==> Downloading $binary_url"
        rm -f "$archive"
        download_file "$binary_url" "$archive"
        unpack_binary "$archive" "$binary_dst"
    fi
}

echo "==> Staging files"
copy_tree "$SCRIPT_DIR/src" "$STAGEDIR"
install -m 0644 "$SCRIPT_DIR/../common/config_backup.py" "$STAGEDIR/usr/local/opnsense/scripts/singbox/config_backup.py"
install -m 0644 "$SCRIPT_DIR/../common/config_backup.php" "$STAGEDIR/usr/local/opnsense/scripts/singbox/config_backup.php"
install -m 0644 "$SCRIPT_DIR/../common/process_identity.py" "$STAGEDIR/usr/local/opnsense/scripts/singbox/process_identity.py"
install -m 0644 "$SCRIPT_DIR/../common/route_control.py" "$STAGEDIR/usr/local/opnsense/scripts/singbox/route_control.py"
install -m 0644 "$SCRIPT_DIR/../common/tun_policy_routing.py" "$STAGEDIR/usr/local/opnsense/scripts/singbox/tun_policy_routing.py"
PRODUCT_VERSION="$(sed -n 's/.*"product_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$STAGEDIR/usr/local/opnsense/version/sing-box")"
[ "$PRODUCT_VERSION" = "$VERSION" ] || die "VERSION does not match the committed sing-box product metadata"
prepare_binary "$SING_BOX_ASSET" "$SING_BOX_DOWNLOAD_URL" "$DOWNLOADDIR/sing-box"
mkdir -p "$STAGEDIR/usr/local/bin"
install -m 0755 "$DOWNLOADDIR/sing-box" "$STAGEDIR/usr/local/bin/sing-box"
chmod 0700 "$STAGEDIR/usr/local/etc/sing-box" "$STAGEDIR/usr/local/etc/sing-box/sub"
chmod 0600 \
    "$STAGEDIR/usr/local/etc/sing-box/config.json.sample" \
    "$STAGEDIR/usr/local/etc/sing-box/sub/env.sample" \
    "$STAGEDIR/usr/local/etc/sing-box/sub/template.json.sample"
chmod 0755 "$STAGEDIR/usr/local/etc/sing-box/sub/sub.sh"
chmod 0755 "$STAGEDIR/usr/bin/sing_box_sub"
chmod 0755 "$STAGEDIR/usr/local/etc/rc.d/sing-box"
chmod 0755 "$STAGEDIR/usr/local/etc/rc.d/sing-box-backup" "$STAGEDIR/usr/local/etc/rc.syshook.d/start/15-singbox-backup"

echo "==> Generating plist"
find "$STAGEDIR" -type f | sed "s#^$STAGEDIR##" | sort > "$PLIST"

FLATSIZE=0
while IFS= read -r file; do
    size="$(wc -c < "$STAGEDIR$file" | tr -d ' ')"
    FLATSIZE=$((FLATSIZE + size))
done < "$PLIST"

echo "==> Generating metadata"
# Pkg URL-decodes manifest scripts, so escape percent signs before serialization.
"$SING_BOX_PYTHON" -B - "$SCRIPT_DIR" "$STAGEDIR" "$METADIR" "$PLIST" "$PKG_NAME" "$ORIGIN" "$VERSION" "$COMMENT" "$MAINTAINER" "$WWW" "$PKG_ABI" "$PKG_ARCH" "$PREFIX" "$FLATSIZE" <<'PYTHON'
from pathlib import Path
import hashlib
import json
import sys

source, stage, metadata, plist = map(Path, sys.argv[1:5])
name, origin, version, comment, maintainer, www, abi, arch, prefix, flatsize = sys.argv[5:]
manifest = {
    'name': name, 'origin': origin, 'version': version, 'comment': comment,
    'maintainer': maintainer, 'www': www, 'abi': abi, 'arch': arch,
    'prefix': prefix, 'flatsize': int(flatsize),
    'deps': {'python313': {'origin': 'lang/python313', 'version': '>=0'},
             'jq': {'origin': 'textproc/jq', 'version': '>=0'},
             'curl': {'origin': 'ftp/curl', 'version': '>=0'}},
    'desc': (source / 'packaging/freebsd/pkg-descr').read_text(),
    'files': {file: '1$' + hashlib.sha256((stage / file.lstrip('/')).read_bytes()).hexdigest()
              for file in plist.read_text().splitlines()},
    'scripts': {phase: (source / 'packaging/freebsd' / filename).read_text().replace('%', '%25')
                for phase, filename in [('pre-install', '+PRE_INSTALL'),
                                        ('post-install', '+POST_INSTALL'),
                                        ('pre-deinstall', '+PRE_DEINSTALL'),
                                        ('post-deinstall', '+POST_DEINSTALL')]},
}
serialized = json.dumps(manifest, indent=2) + '\n'
(metadata / '+MANIFEST').write_text(serialized)
(metadata / '+COMPACT_MANIFEST').write_text(serialized)
PYTHON

echo "==> Creating package for $PKG_ABI"
pkg create -M "$METADIR/+MANIFEST" -r "$STAGEDIR" -o "$DISTDIR"
created_package="$DISTDIR/$PKG_NAME-$VERSION.pkg"
[ "$created_package" = "$DISTDIR/$OUTPUT_NAME" ] || mv "$created_package" "$DISTDIR/$OUTPUT_NAME"

echo "==> Package: $DISTDIR/$OUTPUT_NAME"
pkg info -F "$DISTDIR/$OUTPUT_NAME" >/dev/null
echo "==> Verified package metadata"
if command -v sha256 >/dev/null 2>&1; then
    sha256 "$DISTDIR/$OUTPUT_NAME"
fi
