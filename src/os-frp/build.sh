#!/bin/sh
set -eu

PKG_NAME="${PKG_NAME:-os-frp}"
VERSION="${VERSION:-1.0.1}"
ORIGIN="${ORIGIN:-opnsense/os-frp}"
COMMENT="${COMMENT:-frp reverse proxy server and client integration for OPNsense}"
MAINTAINER="${MAINTAINER:-https://github.com/KKazuhaK/}"
WWW="${WWW:-https://github.com/fatedier/frp}"
PREFIX="${PREFIX:-/usr/local}"
FORMAT="${FORMAT:-txz}"
ABI="${ABI:-native}"
FRP_VERSION="${FRP_VERSION:-0.71.0}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DISTFILE="$SCRIPT_DIR/vendor/frp_${FRP_VERSION}_freebsd_amd64.tar.gz"
DISTSUM="$DISTFILE.sha256"
UPSTREAM_SUMS="${UPSTREAM_SUMS:-$SCRIPT_DIR/vendor/frp_sha256_checksums.txt}"
WORKDIR="${WORKDIR:-$SCRIPT_DIR/work/freebsd-pkg}"
STAGEDIR="$WORKDIR/stage"
METADIR="$WORKDIR/meta"
VENDORDIR="$WORKDIR/vendor"
PLIST="$WORKDIR/pkg-plist"
DISTDIR="${DISTDIR:-$SCRIPT_DIR/dist}"
OUTPUT_NAME="${OUTPUT_NAME:-$PKG_NAME-$VERSION.pkg}"

die() { echo "error: $*" >&2; exit 1; }

for tool in pkg tar sha256 install find od awk sed; do
    command -v "$tool" >/dev/null 2>&1 || die "missing $tool; build on native FreeBSD / OPNsense"
done

# Every file the plugin is contracted to ship.  A missing sibling must fail the
# build rather than produce a package that installs a half-wired plugin.
while IFS= read -r required; do
    [ -n "$required" ] || continue
    [ -e "$SCRIPT_DIR/$required" ] || die "missing required file: $required"
done <<'FILES'
src/etc/rc.conf.d/frps.sample
src/etc/rc.conf.d/frpc.sample
src/usr/local/etc/frp/frps.toml.sample
src/usr/local/etc/frp/frpc.toml.sample
src/usr/local/etc/rc.d/frps
src/usr/local/etc/rc.d/frpc
src/usr/local/etc/rc.syshook.d/start/15-frp
src/usr/local/etc/inc/plugins.inc.d/frp.inc
src/usr/local/opnsense/service/conf/actions.d/actions_frps.conf
src/usr/local/opnsense/service/conf/actions.d/actions_frpc.conf
src/usr/local/opnsense/scripts/frp/manage.py
src/usr/local/opnsense/scripts/frp/config_mirror.php
src/usr/local/opnsense/version/frp
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp/IndexController.php
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp/ServerController.php
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp/ClientController.php
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp/Api/ServiceController.php
src/usr/local/opnsense/mvc/app/controllers/OPNsense/Frp/Api/SettingsController.php
src/usr/local/opnsense/mvc/app/views/OPNsense/Frp/server.volt
src/usr/local/opnsense/mvc/app/views/OPNsense/Frp/client.volt
src/usr/local/opnsense/mvc/app/views/OPNsense/Frp/common.volt
src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Menu/Menu.xml
src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/ACL/ACL.xml
src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Backup.xml
src/usr/local/opnsense/mvc/app/models/OPNsense/Frp/Backup.php
packaging/freebsd/+MANIFEST.in
packaging/freebsd/+PRE_INSTALL
packaging/freebsd/+POST_INSTALL
packaging/freebsd/+PRE_DEINSTALL
packaging/freebsd/+POST_DEINSTALL
packaging/freebsd/pkg-descr
FILES

# The package version and the version file the GUI reads must never drift.
grep -q "\"product_version\":\"$VERSION\"" "$SCRIPT_DIR/src/usr/local/opnsense/version/frp" ||
    die "src/usr/local/opnsense/version/frp does not declare product_version $VERSION"

[ -f "$DISTFILE" ] || die "missing vendored upstream archive: vendor/$(basename "$DISTFILE")"

# The upstream archive is pinned by digest, so a swapped or re-fetched artifact
# fails the build instead of shipping unreviewed binaries.  Pin it once, after
# checking the digest against the checksum upstream publishes for the release.
ACTUAL_SUM="$(sha256 -q "$DISTFILE")"
if [ -n "${FRP_PIN_CHECKSUM:-}" ]; then
    printf '%s\n' "$ACTUAL_SUM" > "$DISTSUM"
    echo "==> Pinned $(basename "$DISTFILE") to $ACTUAL_SUM"
    exit 0
fi
EXPECTED_SUM="${FRP_DIST_SHA256:-}"
if [ -z "$EXPECTED_SUM" ] && [ -f "$DISTSUM" ]; then
    EXPECTED_SUM="$(cat "$DISTSUM")"
fi
# The checksum file upstream publishes beside the release covers every artifact
# of that release; the line for this one is the same statement as a pin file.
if [ -z "$EXPECTED_SUM" ] && [ -f "$UPSTREAM_SUMS" ]; then
    EXPECTED_SUM="$(awk -v name="$(basename "$DISTFILE")" '$2 == name { print $1; exit }' "$UPSTREAM_SUMS")"
fi
[ -n "$EXPECTED_SUM" ] ||
    die "no recorded digest for $(basename "$DISTFILE"); verify it against the upstream release checksum, then run: FRP_PIN_CHECKSUM=1 sh build.sh"
# Accept a bare digest as well as a "digest  filename" checksum line.
EXPECTED_SUM="$(printf '%s\n' "$EXPECTED_SUM" | awk 'NR == 1 { print $1 }')"
[ "$ACTUAL_SUM" = "$EXPECTED_SUM" ] ||
    die "upstream archive digest mismatch: expected $EXPECTED_SUM, got $ACTUAL_SUM"

case "$ABI" in
    native) PKG_ABI="$(env -u ABI pkg config ABI)" ;;
    FreeBSD:*:amd64) PKG_ABI="$ABI" ;;
    *) die "unsupported ABI: $ABI" ;;
esac
ABI_MAJOR="$(printf '%s\n' "$PKG_ABI" | awk -F: '{print $2}')"
[ "$ABI_MAJOR" = 15 ] || die "only FreeBSD 15 amd64 is supported, got $PKG_ABI"
PKG_ARCH="freebsd:${ABI_MAJOR}:x86:64"

rm -rf "$WORKDIR"
mkdir -p "$STAGEDIR" "$METADIR" "$VENDORDIR" "$DISTDIR"

echo "==> Staging OPNsense integration files"
(cd "$SCRIPT_DIR/src" && tar --exclude '.DS_Store' --exclude '._*' --exclude '__pycache__' \
    --exclude '*.pyc' --exclude '*.pyo' --no-xattrs -cf - .) | (cd "$STAGEDIR" && tar -xf -)

echo "==> Extracting frp $FRP_VERSION binaries from the vendored archive"
tar -xf "$DISTFILE" -C "$VENDORDIR"
install -d -m 0755 "$STAGEDIR/usr/local/sbin"
for side in frps frpc; do
    found="$(find "$VENDORDIR" -type f -name "$side" | sort)"
    [ -n "$found" ] || die "the vendored archive does not contain $side"
    [ "$(printf '%s\n' "$found" | wc -l | tr -d ' ')" = 1 ] || die "the vendored archive contains more than one $side"
    [ "$(od -An -N4 -tx1 "$found" | tr -d ' \n')" = 7f454c46 ] || die "$side is not an ELF executable"
    install -m 0755 "$found" "$STAGEDIR/usr/local/sbin/$side"
done

# Normalise modes, then mark the executables.  Source checkouts carry whatever
# umask produced them; the package must not.
find "$STAGEDIR" -type d -exec chmod 0755 {} +
find "$STAGEDIR" -type f -exec chmod 0644 {} +
chmod 0755 \
    "$STAGEDIR/usr/local/sbin/frps" \
    "$STAGEDIR/usr/local/sbin/frpc" \
    "$STAGEDIR/usr/local/etc/rc.d/frps" \
    "$STAGEDIR/usr/local/etc/rc.d/frpc" \
    "$STAGEDIR/usr/local/etc/rc.syshook.d/start/15-frp" \
    "$STAGEDIR/usr/local/opnsense/scripts/frp/manage.py" \
    "$STAGEDIR/usr/local/opnsense/scripts/frp/config_mirror.php"
# The samples occupy the place of files that hold the authentication token and
# the dashboard password; keep them root-only so a copy never widens them.
chmod 0600 \
    "$STAGEDIR/usr/local/etc/frp/frps.toml.sample" \
    "$STAGEDIR/usr/local/etc/frp/frpc.toml.sample"

echo "==> Checking the stage"
# Live runtime state is never packaged.  frps.toml holds the authentication
# token and the dashboard password, so a packaged copy would publish somebody's
# secret to every installation.  Only the .sample files may appear.
for live in /usr/local/etc/frp/frps.toml /usr/local/etc/frp/frpc.toml \
    /etc/rc.conf.d/frps /etc/rc.conf.d/frpc \
    /var/run/frps.pid /var/run/frpc.pid \
    /var/log/frps.log /var/log/frpc.log /var/db/os-frp; do
    [ ! -e "$STAGEDIR$live" ] || die "live runtime path must not be packaged: $live"
done
! find "$STAGEDIR" \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.txz' \) -print | grep -q . ||
    die 'the vendored archive must not be packaged'
! find "$STAGEDIR" \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' \) -print | grep -q . ||
    die 'Python bytecode must not be packaged'
for binary in frps frpc; do
    [ -s "$STAGEDIR/usr/local/sbin/$binary" ] || die "missing staged binary: /usr/local/sbin/$binary"
done

echo "==> Generating plist"
find "$STAGEDIR" \( -type f -o -type l \) | sed "s#^$STAGEDIR##" | sort > "$PLIST"
FLATSIZE=0
while IFS= read -r file; do
    size="$(wc -c < "$STAGEDIR$file" | tr -d ' ')"
    FLATSIZE=$((FLATSIZE + size))
done < "$PLIST"

echo "==> Generating metadata"
sed -e "s#@PKG_NAME@#$PKG_NAME#g" -e "s#@ORIGIN@#$ORIGIN#g" -e "s#@VERSION@#$VERSION#g" \
    -e "s#@COMMENT@#$COMMENT#g" -e "s#@MAINTAINER@#$MAINTAINER#g" -e "s#@WWW@#$WWW#g" \
    -e "s#@ABI@#$PKG_ABI#g" -e "s#@ARCH@#$PKG_ARCH#g" -e "s#@PREFIX@#$PREFIX#g" \
    -e "s#@FLATSIZE@#$FLATSIZE#g" \
    -e "/@DESC@/r $SCRIPT_DIR/packaging/freebsd/pkg-descr" -e "/@DESC@/d" \
    "$SCRIPT_DIR/packaging/freebsd/+MANIFEST.in" > "$METADIR/+MANIFEST"
for hook in +PRE_INSTALL +POST_INSTALL +PRE_DEINSTALL +POST_DEINSTALL; do
    install -m 0644 "$SCRIPT_DIR/packaging/freebsd/$hook" "$METADIR/$hook"
done

echo "==> Creating package for $PKG_ABI"
env -u ABI pkg create -f "$FORMAT" -r "$STAGEDIR" -m "$METADIR" -p "$PLIST" -o "$DISTDIR"
CREATED="$DISTDIR/$PKG_NAME-$VERSION.pkg"
[ -f "$CREATED" ] || die 'pkg did not create the expected package'
PACKAGE="$DISTDIR/$OUTPUT_NAME"
[ "$CREATED" = "$PACKAGE" ] || mv -f "$CREATED" "$PACKAGE"
env -u ABI pkg info -F "$PACKAGE" >/dev/null

# The stage checks above run against a directory; repeat them against the
# archive that is actually shipped.
if tar -tf "$PACKAGE" | grep -Eq '__pycache__|\.py[co]$|\.tar\.gz$'; then
    die 'unexpected member in the package archive'
fi
if tar -tf "$PACKAGE" | grep -Eq '^\.?/?(usr/local/etc/frp/frp[sc]\.toml|etc/rc\.conf\.d/frp[sc])$'; then
    die 'live runtime state must not be packaged'
fi

echo "==> Package: $PACKAGE"
sha256 "$PACKAGE"
