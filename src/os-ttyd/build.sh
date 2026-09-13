#!/bin/sh
set -eu

PKG_NAME="${PKG_NAME:-os-ttyd}"
VERSION="${VERSION:-1.1.1}"
ORIGIN="${ORIGIN:-opnsense/os-ttyd}"
COMMENT="${COMMENT:-ttyd terminal for OPNsense}"
MAINTAINER="${MAINTAINER:-https://github.com/Opnwall/}"
WWW="${WWW:-https://github.com/tsl0922/ttyd}"
PREFIX="${PREFIX:-/usr/local}"
FORMAT="${FORMAT:-txz}"
TARGET_ABI="${TARGET_ABI:-${ABI:-native}}"
OUTPUT_NAME="${OUTPUT_NAME:-os-ttyd.pkg}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${WORKDIR:-"$SCRIPT_DIR/work/freebsd-pkg"}"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
RUNTIMEDIR="$WORKDIR/runtime"
PLIST="$WORKDIR/pkg-plist"
DISTDIR="${DISTDIR:-"$SCRIPT_DIR/dist"}"

die() {
	echo "error: $*" >&2
	exit 1
}

need_file() {
	[ -e "$SCRIPT_DIR/$1" ] || die "missing required file: $1"
}

command -v pkg >/dev/null 2>&1 || die "pkg command not found. Run this script on FreeBSD/OPNsense."
command -v tar >/dev/null 2>&1 || die "tar command not found."
command -v sha256 >/dev/null 2>&1 || die "sha256 command not found."

need_file "src/etc/rc.conf.d/ttyd.sample"
need_file "src/usr/local/etc/rc.d/os-ttyd"
need_file "src/usr/local/etc/lighttpd_webgui/conf.d/ttyd.conf"
need_file "src/usr/local/opnsense/mvc/app/views/OPNsense/Ttyd/index.volt"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/Ttyd/Menu/Menu.xml"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/Ttyd/ACL/ACL.xml"
need_file "src/usr/local/opnsense/service/conf/actions.d/actions_ttyd.conf"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/Ttyd/IndexController.php"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/Ttyd/Api/ServiceController.php"
need_file "src/usr/local/opnsense/scripts/ttyd/manage.py"
need_file "src/usr/local/opnsense/version/ttyd"
grep -q "\"product_version\":\"$VERSION\"" "$SCRIPT_DIR/src/usr/local/opnsense/version/ttyd" ||
	die "src/usr/local/opnsense/version/ttyd does not declare product_version $VERSION"
need_file "packaging/freebsd/+MANIFEST.in"
need_file "packaging/freebsd/+PRE_INSTALL"
need_file "packaging/freebsd/+POST_INSTALL"
need_file "packaging/freebsd/+PRE_DEINSTALL"
need_file "packaging/freebsd/+POST_DEINSTALL"
need_file "packaging/freebsd/pkg-descr"

case "$TARGET_ABI" in
	native)
		PKG_ABI="$(env -u ABI pkg config ABI)"
		;;
	FreeBSD:*:amd64)
		PKG_ABI="$TARGET_ABI"
		;;
	*)
		die "unsupported ABI: $TARGET_ABI"
		;;
esac

case "$PKG_ABI" in
	FreeBSD:15:amd64)
		ABI_MAJOR="$(printf '%s\n' "$PKG_ABI" | awk -F: '{print $2}')"
		PKG_ARCH="freebsd:${ABI_MAJOR}:x86:64"
		;;
	*)
		die "unsupported ABI: $PKG_ABI; this version has a pinned FreeBSD 15 runtime only"
		;;
esac

VENDOR_DIR="$SCRIPT_DIR/vendor/freebsd${ABI_MAJOR}-amd64"
for package in libuv libwebsockets ttyd; do
	[ -f "$VENDOR_DIR/${package}.pkg" ] || die "missing runtime package: $VENDOR_DIR/${package}.pkg"
	pin="$(awk -v name="${package}.pkg" '$2 == name {print $1}' "$VENDOR_DIR/checksums.sha256")"
	[ "$(sha256 -q "$VENDOR_DIR/${package}.pkg")" = "$pin" ] || die "runtime package differs from its committed digest: ${package}.pkg"
done

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$RUNTIMEDIR" "$DISTDIR"

copy_tree() {
	src="$1"
	dst="$2"
	mkdir -p "$dst"
	(cd "$src" && tar --exclude '.DS_Store' --exclude '._*' --exclude '__pycache__' --exclude '*.pyc' --exclude '*.pyo' --no-xattrs -cf - .) | (cd "$dst" && tar -xf -)
}

copy_from_runtime() {
	path="$1"
	dst="${2:-$path}"
	[ -f "$RUNTIMEDIR$path" ] && [ ! -L "$RUNTIMEDIR$path" ] || die "missing regular runtime file: $path"
	mkdir -p "$STAGEDIR$(dirname "$dst")"
	cp -p "$RUNTIMEDIR$path" "$STAGEDIR$dst"
}

echo "==> Extracting bundled ttyd runtime for FreeBSD ${ABI_MAJOR}"
for package in libuv libwebsockets ttyd; do
	tar -xf "$VENDOR_DIR/${package}.pkg" -C "$RUNTIMEDIR"
done

copy_from_runtime /usr/local/bin/ttyd /usr/local/os-ttyd/bin/ttyd
copy_from_runtime /usr/local/lib/libuv.so.1.0.0 /usr/local/os-ttyd/lib/libuv.so
copy_from_runtime /usr/local/lib/libuv.so.1.0.0 /usr/local/os-ttyd/lib/libuv.so.1
copy_from_runtime /usr/local/lib/libuv.so.1.0.0 /usr/local/os-ttyd/lib/libuv.so.1.0.0
copy_from_runtime /usr/local/lib/libwebsockets-evlib_uv.so /usr/local/os-ttyd/lib/libwebsockets-evlib_uv.so
copy_from_runtime /usr/local/lib/libwebsockets.so.21 /usr/local/os-ttyd/lib/libwebsockets.so
copy_from_runtime /usr/local/lib/libwebsockets.so.21 /usr/local/os-ttyd/lib/libwebsockets.so.21
for license_name in libuv-1.52.1 libwebsockets-4.5.8 ttyd-1.7.7_2; do
	for license_file in LICENSE MIT catalog.mk; do
		copy_from_runtime "/usr/local/share/licenses/$license_name/$license_file" \
		    "/usr/local/os-ttyd/share/licenses/$license_name/$license_file"
	done
done

echo "==> Staging OPNsense integration files"
copy_tree "$SCRIPT_DIR/src/etc" "$STAGEDIR/etc"
copy_tree "$SCRIPT_DIR/src/usr" "$STAGEDIR/usr"
for shared in config_backup.py config_backup.php; do
	install -m 0644 "$SCRIPT_DIR/../common/$shared" "$STAGEDIR/usr/local/opnsense/scripts/ttyd/$shared"
done

chmod 0644 "$STAGEDIR/etc/rc.conf.d/ttyd.sample"
chmod 0755 "$STAGEDIR/usr/local/etc/rc.d/os-ttyd"
chmod 0755 "$STAGEDIR/usr/local/etc/rc.d/os-ttyd-backup"
chmod 0755 "$STAGEDIR/usr/local/os-ttyd/bin/ttyd"
chmod 0644 \
	"$STAGEDIR/usr/local/etc/lighttpd_webgui/conf.d/ttyd.conf" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/views/OPNsense/Ttyd/index.volt" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/Ttyd/Menu/Menu.xml" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/Ttyd/ACL/ACL.xml" \
	"$STAGEDIR/usr/local/opnsense/service/conf/actions.d/actions_ttyd.conf"

echo "==> Generating plist"
[ -z "$(find "$STAGEDIR" -type l -print)" ] || die "staged runtime must contain only regular files"
find "$STAGEDIR" -type f | sed "s#^$STAGEDIR##" | sort > "$PLIST"

FLATSIZE=0
while IFS= read -r file; do
	if [ -L "$STAGEDIR$file" ]; then
		size=0
	else
		size="$(wc -c < "$STAGEDIR$file" | tr -d ' ')"
	fi
	FLATSIZE=$((FLATSIZE + size))
done < "$PLIST"

echo "==> Generating metadata"
sed \
	-e "s#@PKG_NAME@#$PKG_NAME#g" \
	-e "s#@ORIGIN@#$ORIGIN#g" \
	-e "s#@VERSION@#$VERSION#g" \
	-e "s#@COMMENT@#$COMMENT#g" \
	-e "s#@MAINTAINER@#$MAINTAINER#g" \
	-e "s#@WWW@#$WWW#g" \
	-e "s#@ABI@#$PKG_ABI#g" \
	-e "s#@ARCH@#$PKG_ARCH#g" \
	-e "s#@PREFIX@#$PREFIX#g" \
	-e "s#@FLATSIZE@#$FLATSIZE#g" \
	-e "/@DESC@/r $SCRIPT_DIR/packaging/freebsd/pkg-descr" \
	-e "/@DESC@/d" \
	"$SCRIPT_DIR/packaging/freebsd/+MANIFEST.in" > "$METADIR/+MANIFEST"

install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+PRE_INSTALL" "$METADIR/+PRE_INSTALL"
install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+POST_INSTALL" "$METADIR/+POST_INSTALL"
install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+PRE_DEINSTALL" "$METADIR/+PRE_DEINSTALL"
install -m 0644 "$SCRIPT_DIR/packaging/freebsd/+POST_DEINSTALL" "$METADIR/+POST_DEINSTALL"

echo "==> Creating package for $PKG_ABI"
env -u ABI pkg create -f "$FORMAT" -r "$STAGEDIR" -m "$METADIR" -p "$PLIST" -o "$DISTDIR"

CREATED="$DISTDIR/$PKG_NAME-$VERSION.pkg"
if [ -f "$CREATED" ] && [ "$(basename "$CREATED")" != "$OUTPUT_NAME" ]; then
	mv -f "$CREATED" "$DISTDIR/$OUTPUT_NAME"
fi

echo "==> Package: $DISTDIR/$OUTPUT_NAME"
env -u ABI pkg info -F "$DISTDIR/$OUTPUT_NAME" >/dev/null
echo "==> Verified package metadata"
