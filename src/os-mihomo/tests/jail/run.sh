#!/bin/sh
set -eu
export LC_ALL=C
[ "$#" -eq 2 ] || { echo 'usage: run.sh new.pkg legacy-1.0.2.pkg' >&2; exit 1; }
TEST_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
JAIL_ROOT="${JAIL_ROOT:-/root/mihomo-refactor-build/jail}"
export JAIL_ROOT
native_product_abi="$(opnsense-version -x)"
target_python="$(tar -xOf "$1" +MANIFEST | python3 -c 'import json,sys; p=next(n for n in json.load(sys.stdin)["deps"] if n.startswith("python3")); print("python3." + p[7:])')"
export TARGET_PYTHON="$target_python"
sh "$TEST_DIR/prepare.sh"
cp "$1" "$JAIL_ROOT/root/new.pkg"
cp "$2" "$JAIL_ROOT/root/old.pkg"
cp "$TEST_DIR/case.py" "$JAIL_ROOT/root/case.py"
cp "$TEST_DIR/config.inc" "$JAIL_ROOT/usr/local/etc/inc/config.inc"
cp "$TEST_DIR/util.inc" "$JAIL_ROOT/usr/local/etc/inc/util.inc"
cp "$TEST_DIR/configctl" "$JAIL_ROOT/usr/local/sbin/configctl"
cp "$TEST_DIR/service" "$JAIL_ROOT/usr/sbin/service"
chmod 0755 "$JAIL_ROOT/usr/local/sbin/configctl" "$JAIL_ROOT/usr/sbin/service"
jail_name="mihomo-lifecycle-$$"
ruleset=48000
while devfs rule showsets | awk -v number="$ruleset" '$1 == number {found=1} END {exit !found}'; do ruleset=$((ruleset + 1)); done
[ "$ruleset" -lt 60000 ] || { echo 'No unused private devfs ruleset' >&2; exit 1; }
ownership="mihomo-lifecycle-owned-$$"
jail_id=''
[ -z "$(jls -j "$jail_name" jid 2>/dev/null || true)" ] || { echo 'test jail already exists' >&2; exit 1; }
snapshot_host()
{
    python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
commands = [['/sbin/pfctl', '-sr'], ['/sbin/pfctl', '-sn'],
            ['/usr/bin/netstat', '-rn', '-F', '0', '-f', 'inet'],
            ['/usr/bin/netstat', '-rn', '-F', '0', '-f', 'inet6'],
            ['/sbin/ifconfig', '-l'], ['/usr/bin/pgrep', '-x', 'mihomo'],
            ['/sbin/sysctl', '-n', 'net.inet.ip.forwarding', 'net.inet6.ip6.forwarding', 'net.pf.share_forward'],
            ['/sbin/devfs', 'rule', 'showsets']]
value = { ' '.join(cmd): hashlib.sha256(subprocess.run(cmd, capture_output=True).stdout).hexdigest()
          for cmd in commands }
status = subprocess.run(['/sbin/pfctl', '-s', 'info'], capture_output=True, text=True).stdout
value['host_pf_status'] = next(line.split()[1] for line in status.splitlines() if line.startswith('Status:'))
for name in ['/conf/config.xml', '/var/db/os-mihomo/settings.json',
             '/var/db/os-mihomo/subscription.yaml', '/var/db/os-mihomo/merge.yaml',
             '/var/db/os-mihomo/config.yaml', '/etc/resolv.conf']:
    path = Path(name)
    value[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
print(json.dumps(value, sort_keys=True))
PY
}
snapshot_host > "$JAIL_ROOT/root/host-before.json"
cleanup()
{
    result=$?
    trap - EXIT HUP INT TERM
    current_id="$(jls -j "$jail_name" jid 2>/dev/null || true)"
    if [ -n "$current_id" ]; then
        current_path="$(jls -j "$jail_name" path)"
        if [ "$current_path" = "$JAIL_ROOT" ] && { [ -z "$jail_id" ] || [ "$current_id" = "$jail_id" ]; }; then
            if [ "$result" -ne 0 ]; then
                jexec "$jail_name" /usr/bin/netstat -rn -F 0 > "$JAIL_ROOT/root/failure-native-routes.txt" 2>&1 || true
                jexec "$jail_name" /usr/bin/netstat -rn -F 1 > "$JAIL_ROOT/root/failure-private-routes.txt" 2>&1 || true
            fi
            # jail removal terminates only this owned VNET's remaining processes.
            jail -r "$jail_name" || result=1
        else
            echo 'Refusing cleanup of a jail with different ownership' >&2
            result=1
        fi
    fi
    if mount -p | awk -v target="$JAIL_ROOT/dev" '$2 == target && $3 == "devfs" {found=1} END {exit !found}'; then
        umount "$JAIL_ROOT/dev" || result=1
    fi
    if devfs rule -s "$ruleset" show | awk -v token="$ownership" 'index($0, token) {found=1} END {exit !found}'; then
        devfs rule -s "$ruleset" delset || result=1
    fi
    snapshot_host > "$JAIL_ROOT/root/host-after.json" || result=1
    if ! cmp -s "$JAIL_ROOT/root/host-before.json" "$JAIL_ROOT/root/host-after.json"; then
        echo 'Host configuration, Core PIDs, PF, routes or resources changed during the private jail test' >&2
        result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
# All routes and devices under test belong to a private VNET.
devfs rule -s "$ruleset" add hide
devfs rule -s "$ruleset" add path "$ownership" hide
for device in null zero random urandom fd stdin stdout stderr; do devfs rule -s "$ruleset" add path "$device" unhide; done
devfs rule -s "$ruleset" add path "fd/*" unhide
devfs rule -s "$ruleset" add path 'tun*' unhide
devfs rule -s "$ruleset" add path 'bpf*' unhide
devfs rule -s "$ruleset" add path 'pf' unhide
jail -c name="$jail_name" path="$JAIL_ROOT" host.hostname=mihomo-test vnet persist mount.devfs devfs_ruleset="$ruleset" allow.raw_sockets=1
jail_id="$(jls -j "$jail_name" jid)"
# PF and forwarding are VNET-private, independently verified before enabling.
jexec "$jail_name" /sbin/pfctl -s info | awk '/^Status:/ {if ($2 != "Disabled") exit 1; found=1} END {if (!found) exit 1}'
jexec "$jail_name" /sbin/pfctl -e
jexec "$jail_name" /sbin/sysctl net.pf.share_forward=1
[ "$(jexec "$jail_name" /sbin/sysctl -n net.pf.share_forward)" = 1 ]
jexec "$jail_name" /sbin/ifconfig lo0 inet 127.0.0.1/8 up
jexec "$jail_name" /sbin/ifconfig lo0 inet6 ::1/128
jexec "$jail_name" /sbin/ifconfig lo1 create inet 192.0.2.10/24 up
# The unchanged routing module allocates its own FIB and copies these routes.
# A loopback address creates only a host route; supply the fixture's actual
# connected network in FIB0 so its gateway remains reachable in copied FIBs.
jexec "$jail_name" /sbin/route -n add -net 192.0.2.0/24 -iface lo1
jexec "$jail_name" /sbin/route -n get 192.0.2.1 | awk '/interface:/ {if ($2 != "lo1") exit 1; found=1} END {if (!found) exit 1}'
jexec "$jail_name" /sbin/route add default 192.0.2.1
jexec "$jail_name" "/usr/local/bin/$target_python" /root/case.py
jexec "$jail_name" "/usr/local/bin/$target_python" -B - <<'PY'
import json
from pathlib import Path
import subprocess
import sys
report = json.loads(Path('/root/test-report.json').read_text())
manifest = json.loads(subprocess.check_output(['tar', '-xOf', '/root/new.pkg', '+MANIFEST']))
release = subprocess.check_output(['freebsd-version', '-u'], text=True).strip()
report.update(native_release=release, native_abi='FreeBSD:' + release.split('.')[0] + ':amd64',
              native_kernel_version=subprocess.check_output(['uname', '-K'], text=True).strip(),
              python='.'.join(map(str, sys.version_info[:2])), product_abi=manifest['annotations']['product_abi'],
              package_version=manifest['version'], state_policy='floating', pf_share_forward=1)
Path('/root/test-report.json').write_text(json.dumps(report, indent=2) + '\n')
PY
cp "$JAIL_ROOT/root/test-report.json" "$(dirname "$1")/test-report.json"
python3 - "$(dirname "$1")/test-report.json" "$native_product_abi" <<'PY'
import json
from pathlib import Path
import sys
path = Path(sys.argv[1])
value = json.loads(path.read_text())
value['native_product_abi'] = sys.argv[2]
path.write_text(json.dumps(value, indent=2) + '\n')
PY
echo 'Actual package upgrade and VNET lifecycle checks passed'
