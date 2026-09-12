#!/bin/sh
set -eu
SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$SCRIPT_DIR/.site/repo}"
LEGACY_REPO="${LEGACY_REPO:-$SCRIPT_DIR/repo}"
SIGNING_KEY="${SIGNING_KEY:-/root/pkgsign/kazuha-repo.key}"
TEST_REPORT="${TEST_REPORT:-$(dirname "${1:-.}")/test-report.json}"
SOURCE_COMMIT="${SOURCE_COMMIT:-}"
die() { echo "error: $*" >&2; exit 1; }
[ "$#" -ge 1 ] || die 'usage: build-repo.sh mihomo.pkg [additional.pkg ...]'
[ "$(pkg config ABI)" = 'FreeBSD:15:amd64' ] || die 'sign on FreeBSD 15 amd64'
[ -f "$SIGNING_KEY" ] || die 'a local signing key is required'
[ "$(stat -f '%Lp' "$SIGNING_KEY")" = 600 ] || die 'a local 0600 signing key is required'
[ -f "$TEST_REPORT" ] || die 'actual FreeBSD jail test report is required'
[ -n "$SOURCE_COMMIT" ] || die 'SOURCE_COMMIT must identify the tested source revision'
python3 - "$TEST_REPORT" "$1" <<'PY'
import hashlib,json,sys
from pathlib import Path
report=json.loads(Path(sys.argv[1]).read_text())
assert report.get('ok') is True and len(report.get('checks',[])) >= 10, 'Jail checks did not pass'
assert report['package_sha256']==hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest(), 'Package changed after jail testing'
PY
[ "$(pkg query -F "$1" '%n')" = os-mihomo ] || die 'first package must be Mihomo'
[ "$(pkg query -F "$1" '%q')" = FreeBSD:15:amd64 ] || die 'Mihomo ABI must be FreeBSD 15 amd64'
mkdir -p "$REPO_ROOT"
# Preserve legacy downloads and ABI trees, then re-sign their catalogs locally.
if [ -d "$LEGACY_REPO" ]; then
    (cd "$LEGACY_REPO" && tar -cf - .) | (cd "$REPO_ROOT" && tar -xf -)
fi
for package in "$@"; do
    name="$(pkg query -F "$package" '%n')"
    version="$(pkg query -F "$package" '%v')"
    abi="$(pkg query -F "$package" '%q')"
    case "$name:$version:$abi" in *[!0-9A-Za-z._,:+*-]*) die 'invalid package metadata' ;; esac
    case "$abi" in FreeBSD:14:amd64|FreeBSD:15:amd64) ;; *) die 'unsupported package ABI' ;; esac
    mkdir -p "$REPO_ROOT/$abi/All"
    cp "$package" "$REPO_ROOT/$abi/All/$name-$version.pkg"
done
# Withdraw the unsafe 1.1.0 upgrade candidate while retaining 1.0.2 for rollback.
find "$REPO_ROOT" -type f -name 'os-mihomo-1.1.0.pkg' -delete
for abi_dir in "$REPO_ROOT"/FreeBSD:*:amd64; do pkg repo "$abi_dir" "rsa:$SIGNING_KEY"; done
site_dir="$(dirname "$REPO_ROOT")"
openssl pkey -in "$SIGNING_KEY" -pubout -out "$site_dir/kazuha.pub" 2>/dev/null
[ "$(sha256 -q "$site_dir/kazuha.pub")" = 92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b ] || die 'incorrect trust anchor'
cp "$SCRIPT_DIR/index.html" "$site_dir/index.html"
cp "$SCRIPT_DIR/kazuha.conf" "$site_dir/kazuha.conf"
rm -f "$site_dir/opnwall.conf"
python3 - "$TEST_REPORT" "$SOURCE_COMMIT" "$site_dir/release.json" "$@" <<'PY'
import hashlib,json,sys
from pathlib import Path
value=json.loads(Path(sys.argv[1]).read_text())
value['source_commit']=sys.argv[2]
value['package_path']='repo/FreeBSD:15:amd64/All/'+Path(sys.argv[4]).name
value['additional_packages']=[{'path':'repo/FreeBSD:15:amd64/All/'+Path(p).name,'sha256':hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in sys.argv[5:]]
Path(sys.argv[3]).write_text(json.dumps(value,sort_keys=True)+'\n')
PY
openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$site_dir/release.sig" "$site_dir/release.json"
touch "$site_dir/.nojekyll"
(cd "$site_dir" && find repo -type f | sort | xargs sha256) > "$site_dir/SHA256SUMS.txt"
echo "==> Signed repository with tested Mihomo and legacy packages: $site_dir"
