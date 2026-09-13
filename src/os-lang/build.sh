#!/bin/sh
set -eu

PKG_NAME="${PKG_NAME:-os-lang}"
VERSION="${VERSION:-1.1.1}"
ORIGIN="${ORIGIN:-opnsense/os-lang}"
COMMENT="${COMMENT:-Chinese localization updater for OPNsense}"
MAINTAINER="${MAINTAINER:-https://github.com/Opnwall/}"
WWW="${WWW:-https://github.com/Opnwall}"
PREFIX="${PREFIX:-/usr/local}"
FORMAT="${FORMAT:-txz}"
TARGET_ABI="${TARGET_ABI:-${ABI:-FreeBSD:*:amd64}}"
OUTPUT_NAME="${OUTPUT_NAME:-os-lang.pkg}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${WORKDIR:-"$SCRIPT_DIR/work/freebsd-pkg"}"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
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

need_file "src/usr/local/opnsense/mvc/app/views/OPNsense/LangTool/index.volt"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/LangTool/Menu/Menu.xml"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/LangTool/IndexController.php"
need_file "src/usr/local/opnsense/mvc/app/controllers/OPNsense/LangTool/Api/ServiceController.php"
need_file "src/usr/local/opnsense/scripts/langtool/manage.php"
need_file "src/usr/local/opnsense/scripts/langtool/validate_archive.py"
need_file "src/usr/local/opnsense/service/conf/actions.d/actions_langtool.conf"
need_file "src/usr/local/opnsense/mvc/app/models/OPNsense/LangTool/ACL/ACL.xml"
need_file "packaging/freebsd/+MANIFEST.in"
need_file "packaging/freebsd/+POST_INSTALL"
need_file "packaging/freebsd/+PRE_DEINSTALL"
need_file "packaging/freebsd/+POST_DEINSTALL"
need_file "packaging/freebsd/pkg-descr"

case "$TARGET_ABI" in
	native)
		PKG_ABI="$(env -u ABI pkg config ABI 2>/dev/null || env -u ABI pkg -vv | awk -F'"' '/ABI =/ {print $2; exit}')"
		;;
	FreeBSD:*:amd64)
		PKG_ABI="$TARGET_ABI"
		;;
	*)
		die "unsupported ABI: $TARGET_ABI"
		;;
esac

case "$PKG_ABI" in
	FreeBSD:*:amd64)
		ABI_MAJOR="$(printf '%s\n' "$PKG_ABI" | awk -F: '{print $2}')"
		PKG_ARCH="freebsd:${ABI_MAJOR}:x86:64"
		;;
	*)
		die "unsupported ABI: $PKG_ABI"
		;;
esac

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$DISTDIR"

copy_tree() {
	src="$1"
	dst="$2"
	mkdir -p "$dst"
	(cd "$src" && tar --exclude '.DS_Store' --exclude '._*' --exclude '__pycache__' --no-xattrs -cf - .) | (cd "$dst" && tar -xf -)
}

echo "==> Staging OPNsense integration files"
copy_tree "$SCRIPT_DIR/src" "$STAGEDIR"

chmod 0644 \
	"$STAGEDIR/usr/local/opnsense/mvc/app/views/OPNsense/LangTool/index.volt" \
	"$STAGEDIR/usr/local/opnsense/mvc/app/models/OPNsense/LangTool/Menu/Menu.xml"

echo "==> Generating plist"
find "$STAGEDIR" \( -type f -o -type l \) | sed "s#^$STAGEDIR##" | sort > "$PLIST"

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
if command -v sha256 >/dev/null 2>&1; then
	sha256 "$DISTDIR/$OUTPUT_NAME"
else
	sha256sum "$DISTDIR/$OUTPUT_NAME"
fi
