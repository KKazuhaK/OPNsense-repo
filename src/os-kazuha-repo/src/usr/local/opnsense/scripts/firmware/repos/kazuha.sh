#!/bin/sh
set -eu

root="${KAZUHA_REPO_ROOT:-}"
case "$root" in ''|/*) ;; *) echo 'error: repository root must be absolute' >&2; exit 1 ;; esac
root="${root%/}"
fingerprint=92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b
source_key="$root/usr/local/share/kazuha-repo/kazuha.pub"
if [ ! -f "$source_key" ] || [ "$(sha256 -q "$source_key")" != "$fingerprint" ]; then
    echo 'error: repository public key does not match the trust anchor' >&2
    exit 1
fi
series="$(opnsense-version -x)"
case "$series" in [0-9][0-9].[17]) ;; *) echo 'error: invalid OPNsense release series' >&2; exit 1 ;; esac
suffix="/$series"
[ "$series" != '26.7' ] || suffix=''

keys="$root/usr/local/etc/pkg/keys"
repos="$root/usr/local/etc/pkg/repos"
install -d -m 0755 "$keys" "$repos"
key_tmp="$(mktemp "$keys/.kazuha.pub.XXXXXX")"
config_tmp="$(mktemp "$repos/.kazuha.conf.XXXXXX")"
trap 'rm -f "$key_tmp" "$config_tmp"' EXIT
trap 'exit 1' HUP INT TERM
install -m 0644 "$source_key" "$key_tmp"
# pkg expands the ABI placeholder after the hook selects the firmware series.
# shellcheck disable=SC2016
printf 'kazuha: {\n  url: "https://kkazuhak.github.io/OPNsense-repo/repo/${ABI}%s",\n  signature_type: "pubkey",\n  pubkey: "/usr/local/etc/pkg/keys/kazuha.pub",\n  priority: 10,\n  enabled: yes\n}\n' "$suffix" > "$config_tmp"
chmod 0644 "$config_tmp"
mv -f "$key_tmp" "$keys/kazuha.pub"
mv -f "$config_tmp" "$repos/kazuha.conf"
