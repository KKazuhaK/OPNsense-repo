#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$SCRIPT_DIR/.site/repo}"
SIGNING_KEY="${SIGNING_KEY:-/root/pkgsign/kazuha-repo.key}"
die() { echo "error: $*" >&2; exit 1; }
command -v pkg >/dev/null 2>&1 || die 'build on FreeBSD 15 / OPNsense'
[ "$(pkg config ABI)" = 'FreeBSD:15:amd64' ] || die 'only FreeBSD:15:amd64 is supported'
[ "$#" -eq 1 ] || die "usage: $0 os-mihomo-version.pkg"
[ -f "$1" ] || die 'package not found'
[ -f "$SIGNING_KEY" ] || die 'the local repository signing key is missing'
[ "$(stat -f '%Lp' "$SIGNING_KEY")" = '600' ] || die 'the signing key must have mode 0600'
[ "$(pkg query -F "$1" '%n')" = 'os-mihomo' ] || die 'only os-mihomo is published by this fork'
[ "$(pkg query -F "$1" '%q')" = 'FreeBSD:15:amd64' ] || die 'the package ABI must be FreeBSD:15:amd64'
version="$(pkg query -F "$1" '%v')"
case "$version" in *[!0-9A-Za-z._,+-]*|'') die 'invalid package version' ;; esac
abi_dir="$REPO_ROOT/FreeBSD:15:amd64"
mkdir -p "$abi_dir/All"
find "$abi_dir/All" -type f -name 'os-mihomo-*.pkg' -delete
cp "$1" "$abi_dir/All/os-mihomo-$version.pkg"
pkg repo "$abi_dir" "rsa:$SIGNING_KEY"
site_dir="$(dirname "$REPO_ROOT")"
openssl pkey -in "$SIGNING_KEY" -pubout -out "$site_dir/kazuha.pub" 2>/dev/null
[ "$(sha256 -q "$site_dir/kazuha.pub")" = '92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b' ] || die 'the signing key does not match the fleet trust anchor'
cp "$SCRIPT_DIR/index.html" "$site_dir/index.html"
cp "$SCRIPT_DIR/kazuha.conf" "$site_dir/kazuha.conf"
cp "$SCRIPT_DIR/opnwall.conf" "$site_dir/opnwall.conf"
touch "$site_dir/.nojekyll"
(cd "$site_dir" && find repo -type f | sort | xargs sha256) > "$site_dir/SHA256SUMS.txt"
echo "==> Signed repository ready: $site_dir"
