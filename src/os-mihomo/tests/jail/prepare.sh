#!/bin/sh
set -eu
jail_root="${JAIL_ROOT:-/root/mihomo-refactor-build/jail}"
prepare_digest="$(sha256 -q "$0")"
[ ! -f "$jail_root/.prepared" ] || [ "$(cat "$jail_root/.prepared")" != "$prepare_digest" ] || exit 0
mkdir -p "$jail_root" "$jail_root/usr/local/bin" "$jail_root/usr/local/sbin" "$jail_root/usr/local/lib" "$jail_root/usr/local/etc" "$jail_root/usr/local/etc/inc" "$jail_root/conf" "$jail_root/tmp" "$jail_root/var/run" "$jail_root/var/log" "$jail_root/var/db/pkg" "$jail_root/var/unbound/etc" "$jail_root/dev" "$jail_root/root" "$jail_root/etc"
chmod 1777 "$jail_root/tmp"
for source in /bin /sbin /lib /libexec; do [ -d "$jail_root$source" ] || cp -a "$source" "$jail_root/"; done
mkdir -p "$jail_root/usr/bin" "$jail_root/usr/lib"
target_python="${TARGET_PYTHON:-python3.13}"
python_version="${target_python#python}"
for name in awk sed date pkill pgrep env install tar touch find basename id setfib freebsd-version uname; do source="$(command -v "$name")"; mkdir -p "$jail_root$(dirname "$source")"; cp -L "$source" "$jail_root$source"; done
cp -L "/usr/local/bin/$target_python" "$jail_root/usr/local/bin/$target_python"
cp -L "/usr/local/bin/$target_python" "$jail_root/usr/local/bin/python3"
for name in php curl; do cp -L "/usr/local/bin/$name" "$jail_root/usr/local/bin/$name"; done
mkdir -p "$jail_root/usr/sbin"
cp -L /usr/sbin/daemon "$jail_root/usr/sbin/"
cp -a /etc/rc.subr "$jail_root/etc/"
cp -L /usr/local/sbin/pkg-static "$jail_root/usr/local/sbin/pkg"
cp -L /usr/local/sbin/unbound "$jail_root/usr/local/sbin/"
cp -L /usr/local/sbin/unbound-checkconf "$jail_root/usr/local/sbin/"
cp -a "/usr/local/lib/python$python_version" "$jail_root/usr/local/lib/"
cp -a /usr/local/lib/php "$jail_root/usr/local/lib/"
cp -a /usr/local/etc/php.ini "$jail_root/usr/local/etc/"
cp -a /usr/local/etc/php "$jail_root/usr/local/etc/"
for binary in "/usr/local/bin/$target_python" /usr/local/bin/php /usr/local/bin/curl /usr/local/sbin/unbound /usr/local/sbin/unbound-checkconf /usr/bin/awk /usr/bin/sed /usr/bin/date /usr/bin/pkill /usr/bin/pgrep /usr/bin/install /usr/bin/tar /usr/local/lib/php/*/*.so /usr/local/lib/python"$python_version"/lib-dynload/*.so; do
  [ -f "$binary" ] || continue
  ldd -f '%p\n' "$binary" 2>/dev/null | while read -r library; do
    case "$library" in /*) mkdir -p "$jail_root$(dirname "$library")"; [ -f "$jail_root$library" ] || cp -L "$library" "$jail_root$library" ;; esac
  done
done
# The test resolver and OS configuration are synthetic; no production secrets are copied.
printf 'nameserver 127.0.0.1\n' > "$jail_root/etc/resolv.conf"
printf 'root:*:0:0::0:0:root:/root:/bin/sh\nnobody:*:65534:65534::0:0:Nobody:/:/usr/sbin/nologin\n' > "$jail_root/etc/master.passwd"
printf 'wheel:*:0:root\nnobody:*:65534:\n' > "$jail_root/etc/group"
pwd_mkdb -d "$jail_root/etc" "$jail_root/etc/master.passwd"
printf "%s\n" "$prepare_digest" > "$jail_root/.prepared"
echo 'Throwaway jail filesystem prepared'
