#!/bin/sh
set -eu

PKG_NAME="${PKG_NAME:-os-speedtest}"
VERSION="${VERSION:-1.1.1}"
ORIGIN="${ORIGIN:-opnsense/os-speedtest}"
COMMENT="${COMMENT:-Internet speed test integration for OPNsense}"
MAINTAINER="${MAINTAINER:-https://github.com/Opnwall/}"
WWW="${WWW:-https://github.com/showwin/speedtest-go}"
PREFIX="${PREFIX:-/usr/local}"
FORMAT="${FORMAT:-tgz}"
TARGET_ABI="${TARGET_ABI:-${ABI:-native}}"
OUTPUT_NAME="${OUTPUT_NAME:-${PKG_NAME}.pkg}"
ASSET="speedtest-go_1.7.10_Freebsd_x86_64.tar.gz"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${WORKDIR:-$SCRIPT_DIR/work/freebsd-pkg}"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
PLIST="$WORKDIR/pkg-plist"
DISTDIR="${DISTDIR:-$SCRIPT_DIR/dist}"

die() { echo "error: $*" >&2; exit 1; }
need_file() { [ -e "$SCRIPT_DIR/$1" ] || die "missing required file: $1"; }

command -v pkg >/dev/null 2>&1 || die "pkg command not found; build on FreeBSD or OPNsense"
command -v tar >/dev/null 2>&1 || die "tar command not found"
need_file "src/usr/local/bin/$ASSET"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/Speedtest/IndexController.php"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/Speedtest/Api/SettingsController.php"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/Speedtest/Api/ServiceController.php"
need_file "src/usr/local/opnsense/mvc/app/views/OPNsense/Speedtest/index.volt"
need_file "src/usr/local/opnsense/scripts/speedtest/api.php"
need_file "src/usr/local/opnsense/scripts/speedtest/config_mirror.php"
need_file "src/usr/local/opnsense/scripts/speedtest/config_mirror.py"
need_file "src/usr/local/opnsense/scripts/speedtest/speedtest.py"
need_file "src/usr/local/opnsense/service/conf/actions.d/actions_speedtest.conf"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Menu/Menu.xml"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/ACL/ACL.xml"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.xml"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.php"
need_file "src/usr/local/etc/rc.syshook.d/start/98-speedtest"
need_file "packaging/freebsd/+MANIFEST.in"
need_file "packaging/freebsd/+POST_INSTALL"
need_file "packaging/freebsd/+PRE_DEINSTALL"
need_file "packaging/freebsd/+POST_DEINSTALL"
need_file "packaging/freebsd/pkg-descr"
grep -q "\"product_version\":\"$VERSION\"" "$SCRIPT_DIR/src/usr/local/opnsense/version/speedtest" ||
	die "src/usr/local/opnsense/version/speedtest does not declare product_version $VERSION"

case "$TARGET_ABI" in
	native) PKG_ABI="$(env -u ABI pkg config ABI 2>/dev/null || env -u ABI pkg -vv | awk -F'"' '/ABI =/ {print $2; exit}')" ;;
	FreeBSD:*:amd64) PKG_ABI="$TARGET_ABI" ;;
	*) die "unsupported ABI: $TARGET_ABI" ;;
esac
case "$PKG_ABI" in
	FreeBSD:*:amd64) ABI_MAJOR="$(printf '%s\n' "$PKG_ABI" | awk -F: '{print $2}')"; PKG_ARCH="freebsd:${ABI_MAJOR}:x86:64" ;;
	*) die "unsupported ABI: $PKG_ABI" ;;
esac

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$DISTDIR"

echo "==> Staging files"
(cd "$SCRIPT_DIR/src" && tar --exclude '.DS_Store' --exclude '__pycache__' --exclude '*.pyc' --exclude '*.pyo' --exclude "$ASSET" -cf - .) | (cd "$STAGEDIR" && tar -xf -)
mkdir -p "$STAGEDIR/usr/local/bin"
tar -xzf "$SCRIPT_DIR/src/usr/local/bin/$ASSET" -C "$WORKDIR"
ENGINE="$(find "$WORKDIR" -type f -name speedtest-go | head -1)"
[ -n "$ENGINE" ] || die "speedtest-go was not found in $ASSET"
install -m 0755 "$ENGINE" "$STAGEDIR/usr/local/bin/opnsense-speedtest"
chmod 0644 \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Menu/Menu.xml" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/ACL/ACL.xml" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.xml" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/Speedtest/Backup.php" \
	"$STAGEDIR/usr/local/opnsense/version/speedtest"
# The boot hook is executed, not sourced, so a checkout that lost the bit has
# to get it back here rather than fail silently once per boot.
chmod 0755 "$STAGEDIR/usr/local/etc/rc.syshook.d/start/98-speedtest"

find "$STAGEDIR" \( -type f -o -type l \) | sed "s#^$STAGEDIR##" | sort > "$PLIST"
FLATSIZE=0
while IFS= read -r file; do
	[ -L "$STAGEDIR$file" ] && size=0 || size="$(wc -c < "$STAGEDIR$file" | tr -d ' ')"
	FLATSIZE=$((FLATSIZE + size))
done < "$PLIST"

sed \
	-e "s#@PKG_NAME@#$PKG_NAME#g" -e "s#@ORIGIN@#$ORIGIN#g" \
	-e "s#@VERSION@#$VERSION#g" -e "s#@COMMENT@#$COMMENT#g" \
	-e "s#@MAINTAINER@#$MAINTAINER#g" -e "s#@WWW@#$WWW#g" \
	-e "s#@ABI@#$PKG_ABI#g" -e "s#@ARCH@#$PKG_ARCH#g" \
	-e "s#@PREFIX@#$PREFIX#g" -e "s#@FLATSIZE@#$FLATSIZE#g" \
	-e "/@DESC@/r $SCRIPT_DIR/packaging/freebsd/pkg-descr" -e "/@DESC@/d" \
	"$SCRIPT_DIR/packaging/freebsd/+MANIFEST.in" > "$METADIR/+MANIFEST"
install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+POST_INSTALL" "$METADIR/+POST_INSTALL"
install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+PRE_DEINSTALL" "$METADIR/+PRE_DEINSTALL"
install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+POST_DEINSTALL" "$METADIR/+POST_DEINSTALL"

echo "==> Creating package for $PKG_ABI"
env -u ABI pkg create -f "$FORMAT" -r "$STAGEDIR" -m "$METADIR" -p "$PLIST" -o "$DISTDIR"
CREATED="$DISTDIR/$PKG_NAME-$VERSION.pkg"
[ ! -f "$CREATED" ] || [ "$(basename "$CREATED")" = "$OUTPUT_NAME" ] || mv -f "$CREATED" "$DISTDIR/$OUTPUT_NAME"
env -u ABI pkg info -F "$DISTDIR/$OUTPUT_NAME" >/dev/null
echo "==> Package: $DISTDIR/$OUTPUT_NAME"
sha256 "$DISTDIR/$OUTPUT_NAME" 2>/dev/null || true
