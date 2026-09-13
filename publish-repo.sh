#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
SITE_DIR="${SITE_DIR:-$SCRIPT_DIR/.site}"
REMOTE="${PUBLISH_REMOTE:-https://github.com/KKazuhaK/OPNsense-repo.git}"
command -v git >/dev/null 2>&1 || { echo 'git is required on the publishing host' >&2; exit 1; }
for entry in index.html kazuha.pub kazuha.conf release.json release.sig; do
    [ -f "$SITE_DIR/$entry" ] || { echo "missing signed site asset: $entry" >&2; exit 1; }
done
# Publishing never receives a private key or copies the source checkout.
if find "$SITE_DIR" -type f | LC_ALL=C grep -Eq '\.(key|pem)$|/(AGENTS|CLAUDE|HANDOFF|MEMORY)\.md$'; then
    echo 'refusing to publish local instructions or key files' >&2
    exit 1
fi
if grep -R -l -E -- '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----' "$SITE_DIR" >/dev/null 2>&1; then
    echo 'refusing to publish private key material' >&2
    exit 1
fi
python3 "$SCRIPT_DIR/verify-repo.py" "$SITE_DIR" --source "$SCRIPT_DIR"
python3 -B "$SCRIPT_DIR/tests/run.py"
source_commit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' "$SITE_DIR/release.json")"
[ "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" = "$source_commit" ] || { echo 'release source revision does not match the checkout' >&2; exit 1; }
[ -z "$(git -C "$SCRIPT_DIR" status --porcelain)" ] || { echo 'commit tested source before publishing' >&2; exit 1; }
work="$(mktemp -d "${TMPDIR:-/tmp}/mihomo-pages.XXXXXX")"
trap 'rm -rf "$work"' EXIT HUP INT TERM
git init -q --initial-branch=gh-pages "$work"
# Use the existing user identity without adding author or co-author overrides.
git -C "$work" config user.name "$(git -C "$SCRIPT_DIR" config user.name)"
git -C "$work" config user.email "$(git -C "$SCRIPT_DIR" config user.email)"
(cd "$SITE_DIR" && tar -cf - .) | (cd "$work" && tar -xf -)
mkdir -p "$work/.github/workflows"
cp "$SCRIPT_DIR/.github/workflows/pages.yml" "$work/.github/workflows/pages.yml"
cp "$SCRIPT_DIR/verify-repo.py" "$work/verify-repo.py"
git -C "$work" add .
git -C "$work" commit -qm 'Publish signed Mihomo repository'
previous="$(git ls-remote "$REMOTE" refs/heads/gh-pages | awk '{print $1}')"
# Replace the generated branch using a lease so binaries do not accumulate there.
git -C "$work" push "--force-with-lease=refs/heads/gh-pages:$previous" "$REMOTE" HEAD:refs/heads/gh-pages
echo '==> Signed repository published to gh-pages'
