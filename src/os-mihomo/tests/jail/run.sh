#!/bin/sh
set -eu
[ "$#" -eq 2 ] || { echo 'usage: run.sh new.pkg legacy-1.0.2.pkg' >&2; exit 1; }
TEST_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
JAIL_ROOT="${JAIL_ROOT:-/root/mihomo-refactor-build/jail}"
export JAIL_ROOT
sh "$TEST_DIR/prepare.sh"
cp "$1" "$JAIL_ROOT/root/new.pkg"
cp "$2" "$JAIL_ROOT/root/old.pkg"
cp "$TEST_DIR/case.py" "$JAIL_ROOT/root/case.py"
cp "$TEST_DIR/config.inc" "$JAIL_ROOT/usr/local/etc/inc/config.inc"
cp "$TEST_DIR/configctl" "$JAIL_ROOT/usr/local/sbin/configctl"
cp "$TEST_DIR/service" "$JAIL_ROOT/usr/sbin/service"
chmod 0755 "$JAIL_ROOT/usr/local/sbin/configctl" "$JAIL_ROOT/usr/sbin/service"
jail_name=mihomo-refactor-test
ruleset=33422
[ -z "$(jls -j "$jail_name" jid 2>/dev/null || true)" ] || { echo 'test jail already exists' >&2; exit 1; }
trap 'jail -r "$jail_name" 2>/dev/null || true; devfs rule -s "$ruleset" delset 2>/dev/null || true' EXIT HUP INT TERM
# All routes and devices under test belong to a private VNET.
devfs rule -s "$ruleset" add hide
for device in null zero random urandom fd stdin stdout stderr; do devfs rule -s "$ruleset" add path "$device" unhide; done
devfs rule -s "$ruleset" add path "fd/*" unhide
devfs rule -s "$ruleset" add path 'tun*' unhide
devfs rule -s "$ruleset" add path 'bpf*' unhide
jail -c name="$jail_name" path="$JAIL_ROOT" host.hostname=mihomo-test vnet persist mount.devfs devfs_ruleset="$ruleset" allow.raw_sockets=1
jexec "$jail_name" /sbin/sysctl net.fibs=2023
jexec "$jail_name" /sbin/ifconfig lo0 inet 127.0.0.1/8 up
jexec "$jail_name" /sbin/ifconfig lo0 inet6 ::1/128
jexec "$jail_name" /sbin/ifconfig lo1 create inet 192.0.2.10/24 up
# The core's dedicated FIB needs a connected gateway route too.
jexec "$jail_name" /usr/sbin/setfib 2022 /sbin/route add -net 192.0.2.0/24 -iface lo1
jexec "$jail_name" /sbin/route add default 192.0.2.1
jexec "$jail_name" /usr/local/bin/python3 /root/case.py
cp "$JAIL_ROOT/root/test-report.json" "$(dirname "$1")/test-report.json"
echo 'Actual package upgrade and VNET lifecycle checks passed'
