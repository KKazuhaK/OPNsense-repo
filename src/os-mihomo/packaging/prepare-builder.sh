#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
die() { echo "error: $*" >&2; exit 1; }
: "${TARGET_ABI:?TARGET_ABI is required}"
: "${TARGET_PRODUCT_ABI:?TARGET_PRODUCT_ABI is required}"
: "${TARGET_PYTHON:?TARGET_PYTHON is required}"
: "${TARGET_PHP:?TARGET_PHP is required}"
: "${TARGET_DEPENDENCY_REPOSITORY:?TARGET_DEPENDENCY_REPOSITORY is required}"
: "${TARGET_DEPENDENCY_FINGERPRINT:?TARGET_DEPENDENCY_FINGERPRINT is required}"
case "$TARGET_ABI" in FreeBSD:*:amd64) ;; *) die 'invalid native builder ABI' ;; esac
major="${TARGET_ABI#FreeBSD:}"
major="${major%:amd64}"
case "$major" in ''|0*|*[!0-9]*) die 'invalid native builder ABI' ;; esac
case "$TARGET_PRODUCT_ABI" in [0-9][0-9].[17]) ;; *) die 'invalid OPNsense CE series' ;; esac
case "$TARGET_PYTHON" in 3.*) ;; *) die 'invalid target Python' ;; esac
python_minor="${TARGET_PYTHON#3.}"
case "$python_minor" in ''|0*|*[!0-9]*) die 'invalid target Python' ;; esac
case "$TARGET_PHP" in 8.*) ;; *) die 'invalid target PHP' ;; esac
php_minor="${TARGET_PHP#8.}"
case "$php_minor" in ''|*[!0-9]*) die 'invalid target PHP' ;; esac
[ "$TARGET_DEPENDENCY_REPOSITORY" = "https://pkg.opnsense.org/$TARGET_ABI/$TARGET_PRODUCT_ABI/latest" ] || die 'dependency repository differs from the target series'
case "$TARGET_DEPENDENCY_FINGERPRINT" in
    packaging/OPNsense/trusted/pkg.opnsense.org.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) die 'invalid committed dependency fingerprint path' ;;
esac
fingerprint="$SCRIPT_DIR/../$TARGET_DEPENDENCY_FINGERPRINT"
if [ ! -f "$fingerprint" ] || [ -L "$fingerprint" ]; then
    die 'the committed OPNsense fingerprint is missing'
fi
if ! grep -Eq '^function: "sha256"$' "$fingerprint" ||
    ! grep -Eq '^fingerprint: "[0-9a-f]{64}"$' "$fingerprint"; then
    die 'invalid OPNsense fingerprint contents'
fi
if [ "$(uname -s)" != FreeBSD ] || [ "$(uname -m)" != amd64 ]; then
    die 'prepare a native FreeBSD amd64 builder'
fi
[ "$(pkg -4 config ABI)" = "$TARGET_ABI" ] || die 'builder ABI differs from the target'

tmp_base="${TMPDIR:-/tmp}"
work="$(mktemp -d "${tmp_base%/}/mihomo-builder.XXXXXX")"
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$work/repos" "$work/fingerprints/trusted" "$work/fingerprints/revoked"
cp "$fingerprint" "$work/fingerprints/trusted/$(basename "$fingerprint")"
chmod 0644 "$work/fingerprints/trusted/$(basename "$fingerprint")"
cat > "$work/repos/OPNsense.conf" <<EOF
OPNsense: {
  fingerprints: "$work/fingerprints",
  url: "$TARGET_DEPENDENCY_REPOSITORY",
  signature_type: "fingerprints",
  priority: 11,
  enabled: yes
}
EOF
# Select the target firmware repository for every dependency and its transitive packages.
pkg -4 -R "$work/repos" update -f -r OPNsense
pkg -4 -R "$work/repos" install -y -r OPNsense curl git "python3$python_minor" \
    "py3$python_minor-pyyaml" "php8$php_minor" "php8$php_minor-dom" \
    "php8$php_minor-filter" "php8$php_minor-gettext" "php8$php_minor-simplexml" unbound
