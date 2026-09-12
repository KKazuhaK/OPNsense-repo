#!/bin/sh
set -eu

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'run this bootstrap as root on OPNsense'
root="${KAZUHA_REPO_ROOT:-}"
case "$root" in ''|/*) ;; *) die 'repository root must be absolute' ;; esac
root="${root%/}"
for tool in fetch pkg sha256 opnsense-version; do command -v "$tool" >/dev/null 2>&1 || die "missing $tool"; done
series="$(opnsense-version -x)"
case "$series" in [0-9][0-9].[17]) ;; *) die 'invalid OPNsense release series' ;; esac
suffix="/$series"
[ "$series" != '26.7' ] || suffix=''
tmp_base="${TMPDIR:-/tmp}"
work="$(mktemp -d "${tmp_base%/}/kazuha-bootstrap.XXXXXX")"
changed=no
committed=no
keys="$root/usr/local/etc/pkg/keys"
repos="$root/usr/local/etc/pkg/repos"

cleanup() {
    if [ "$changed" = yes ] && [ "$committed" != yes ]; then
        for item in key config old_repo; do
            case "$item" in key) target="$keys/kazuha.pub" ;; config) target="$repos/kazuha.conf" ;; old_repo) target="$repos/opnwall.conf" ;; esac
            if [ -f "$work/backup_$item" ]; then
                cp -p "$work/backup_$item" "$target.restore"
                mv -f "$target.restore" "$target"
            elif [ "$item" != old_repo ]; then
                rm -f "$target"
            fi
        done
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$work/repos" "$work/db" "$work/cache"
fetch -q -o "$work/kazuha.pub" https://kkazuhak.github.io/OPNsense-repo/kazuha.pub
[ "$(sha256 -q "$work/kazuha.pub")" = '92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b' ] || die 'public key fingerprint verification failed'

configuration() {
    # pkg expands the ABI placeholder when reading this configuration.
    # shellcheck disable=SC2016
    printf 'kazuha: {\n  url: "https://kkazuhak.github.io/OPNsense-repo/repo/${ABI}%s",\n  signature_type: "pubkey",\n  pubkey: "%s",\n  priority: 10,\n  enabled: yes\n}\n' "$suffix" "$1"
}
configuration "$work/kazuha.pub" > "$work/repos/kazuha.conf"
candidate_pkg() {
    pkg -4 -o "REPOS_DIR=$work/repos" -o "PKG_DBDIR=$work/db" -o "PKG_CACHEDIR=$work/cache" "$@"
}
# Check the signed repository and download its plugin before changing router files.
candidate_pkg update -f -r kazuha
[ "$(candidate_pkg rquery -r kazuha '%n' os-kazuha-repo)" = os-kazuha-repo ] || die 'the repository plugin is unavailable for this series'
version="$(candidate_pkg rquery -r kazuha '%v' os-kazuha-repo)"
case "$version" in ''|*[!0-9A-Za-z._,+~-]*) die 'invalid repository plugin version' ;; esac
candidate_pkg fetch -y -r kazuha os-kazuha-repo

for item in key config old_repo; do
    case "$item" in key) target="$keys/kazuha.pub" ;; config) target="$repos/kazuha.conf" ;; old_repo) target="$repos/opnwall.conf" ;; esac
    [ ! -L "$target" ] || die 'repository files must not be symbolic links'
    [ ! -e "$target" ] || [ -f "$target" ] || die 'repository files must be regular files'
    [ ! -f "$target" ] || cp -p "$target" "$work/backup_$item"
done
install -d -m 0755 "$keys" "$repos"
changed=yes
install -m 0644 "$work/kazuha.pub" "$keys/.kazuha.pub.bootstrap"
mv -f "$keys/.kazuha.pub.bootstrap" "$keys/kazuha.pub"
configuration /usr/local/etc/pkg/keys/kazuha.pub > "$work/kazuha.conf"
install -m 0644 "$work/kazuha.conf" "$repos/.kazuha.conf.bootstrap"
mv -f "$repos/.kazuha.conf.bootstrap" "$repos/kazuha.conf"
pkg -4 update -f -r kazuha
pkg -4 -o "PKG_CACHEDIR=$work/cache" install -U -y -r kazuha "os-kazuha-repo-$version"

# Retire only the original unsigned upstream configuration, never a custom repository.
if [ -f "$repos/opnwall.conf" ]; then
    old="$(tr -d '[:space:]' < "$repos/opnwall.conf")"
    # Match the original literal pkg placeholder and configuration exactly.
    # shellcheck disable=SC2016
    case "$old" in
        'opnwall:{url:"https://opnwall.github.io/OPNsense-repo/repo/${ABI}",priority:10,enabled:yes}'|'opnwall:{url:"https://opnwall.github.io/OPNsense-repo/repo/${ABI}",signature_type:"none",priority:10,enabled:yes}')
            rm -f "$repos/opnwall.conf"
            ;;
    esac
fi
committed=yes
echo 'Signed Kazuha repository installed and registered for firmware updates.'
