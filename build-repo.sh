#!/bin/sh
set -eu
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$SCRIPT_DIR/.site/repo}"
LEGACY_REPO="${LEGACY_REPO:-$SCRIPT_DIR/repo}"
SIGNING_KEY="${SIGNING_KEY:-/root/pkgsign/kazuha-repo.key}"
SOURCE_COMMIT="${SOURCE_COMMIT:-}"
die() { echo "error: $*" >&2; exit 1; }
[ "$#" -ge 1 ] || die 'usage: build-repo.sh mihomo.pkg [additional.pkg ...]'
command -v pkg >/dev/null 2>&1 || die 'sign catalogs on a FreeBSD host with pkg'
[ -f "$SIGNING_KEY" ] || die 'a local signing key is required'
[ "$(stat -f '%Lp' "$SIGNING_KEY")" = 600 ] || die 'a local 0600 signing key is required'
[ -n "$SOURCE_COMMIT" ] || die 'SOURCE_COMMIT must identify the tested source revision'
mkdir -p "$REPO_ROOT"
# Preserve legacy downloads and ABI trees, then re-sign their catalogs locally.
if [ -d "$LEGACY_REPO" ]; then
    (cd "$LEGACY_REPO" && tar -cf - .) | (cd "$REPO_ROOT" && tar -xf -)
fi
site_dir="$(dirname "$REPO_ROOT")"
python3 "$SCRIPT_DIR/verify-repo.py" "$site_dir" --prepare --source "$SCRIPT_DIR" --source-commit "$SOURCE_COMMIT" "$@"
# Withdraw the unsafe 1.1.0 upgrade candidate while retaining 1.0.2 for rollback.
find "$REPO_ROOT" -type f -name 'os-mihomo-1.1.0.pkg' -delete
# Each catalog belongs to one ABI and, when dependencies differ, one series.
find "$REPO_ROOT" -type d -name All | while IFS= read -r all_dir; do
    catalog_input="$(mktemp -d "${TMPDIR:-/tmp}/kazuha-catalog.XXXXXX")"
    trap 'rm -rf "$catalog_input"' EXIT HUP INT TERM
    mkdir "$catalog_input/All"
    (cd "$all_dir" && tar -cf - .) | (cd "$catalog_input/All" && tar -xf -)
    # pkg repo recurses, so never scan adjacent series through an ABI root.
    pkg repo -o "$(dirname "$all_dir")" "$catalog_input" "rsa:$SIGNING_KEY"
    rm -rf "$catalog_input"
    trap - EXIT HUP INT TERM
done
openssl pkey -in "$SIGNING_KEY" -pubout -out "$site_dir/kazuha.pub" 2>/dev/null
[ "$(sha256 -q "$site_dir/kazuha.pub")" = 92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b ] || die 'incorrect trust anchor'
cp "$SCRIPT_DIR/index.html" "$site_dir/index.html"
cp "$SCRIPT_DIR/kazuha.conf" "$site_dir/kazuha.conf"
cp "$SCRIPT_DIR/client.sh" "$site_dir/client.sh"
cp "$SCRIPT_DIR/check-upgrade.py" "$site_dir/check-upgrade.py"
cp "$SCRIPT_DIR/verify-repo.py" "$site_dir/verify-repo.py"
rm -f "$site_dir/opnwall.conf"
openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$site_dir/release.sig" "$site_dir/release.json"
touch "$site_dir/.nojekyll"
(cd "$site_dir" && find repo -type f | sort | xargs sha256) > "$site_dir/SHA256SUMS.txt"
python3 "$SCRIPT_DIR/verify-repo.py" "$site_dir" --source "$SCRIPT_DIR"
echo "==> Signed repository with tested Mihomo and legacy packages: $site_dir"
