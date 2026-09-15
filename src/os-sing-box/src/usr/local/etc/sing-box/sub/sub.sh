#!/bin/sh
# Fetch a complete Sing-box JSON subscription without disclosing it to a converter.
set -eu
Server_Dir="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
provided_url="${SING_BOX_URL:-${CLASH_URL:-}}"
# shellcheck disable=SC1091
[ ! -f "$Server_Dir/env" ] || . "$Server_Dir/env"
subscription_url="${provided_url:-${SING_BOX_URL:-${CLASH_URL:-}}}"
case "$subscription_url" in http://*|https://*) ;; *) echo 'Set a direct Sing-box JSON subscription URL.' >&2; exit 1 ;; esac
# A newline would inject another curl configuration directive.
carriage_return="$(printf '\r')"
case "$subscription_url" in *'
'*|*"$carriage_return"*) echo 'Invalid subscription URL.' >&2; exit 1 ;; esac
private_dir="$(mktemp -d /tmp/singbox-sub.XXXXXX)"
trap 'rm -rf "$private_dir"' EXIT HUP INT TERM
chmod 0700 "$private_dir"
umask 077
escaped_url="$(printf '%s' "$subscription_url" | sed 's/\\/\\\\/g; s/"/\\"/g')"
printf 'url = "%s"\n' "$escaped_url" > "$private_dir/curl.conf"
status="$(curl --disable --config "$private_dir/curl.conf" --silent --location --max-redirs 3 --proto '=http,https' --proto-redir '=https' --connect-timeout 10 --max-time 30 --max-filesize 16777216 --user-agent 'sing-box/1 (OPNsense)' --output "$private_dir/sub.json" --write-out '%{http_code}' 2>/dev/null)" || { echo 'Subscription download failed.' >&2; exit 1; }
[ "$status" = 200 ] || { echo 'Subscription HTTP request failed; no retry was attempted.' >&2; exit 1; }
jq -e 'type == "object" and (.outbounds | type == "array" and length > 0)' "$private_dir/sub.json" >/dev/null 2>&1 || { echo 'A complete Sing-box JSON subscription is required.' >&2; exit 1; }
core="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
"$core" check -c "$private_dir/sub.json" >/dev/null 2>&1 || { echo 'Sing-box rejected the subscription.' >&2; exit 1; }
config="${SING_BOX_FORMAL_CONFIG:-/usr/local/etc/sing-box/config.json}"
# Stage in the destination filesystem and preserve the active file on restart failure.
staged="$(mktemp "${config}.XXXXXX")"
cp "$private_dir/sub.json" "$staged"
chmod 0600 "$staged"
[ ! -f "$config" ] || cp "$config" "$private_dir/previous.json"
was_running="no"
if service sing-box onestatus >/dev/null 2>&1; then was_running="yes"; fi
mv "$staged" "$config"
if [ "$was_running" = "yes" ] && ! service sing-box onerestart >/dev/null 2>&1; then
    if [ -f "$private_dir/previous.json" ]; then
        cp "$private_dir/previous.json" "$config"
        chmod 0600 "$config"
        service sing-box onerestart >/dev/null 2>&1 || true
    fi
    echo 'Service restart failed; the previous configuration was restored.' >&2
    exit 1
fi
echo 'Subscription validated and applied.'
