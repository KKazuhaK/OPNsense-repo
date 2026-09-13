#!/bin/sh
set -eu
jail_root="${JAIL_ROOT:-/root/mihomo-refactor-build/jail}"
jail_root="${jail_root%/}"
case "$jail_root" in /*) ;; *) echo 'JAIL_ROOT must be an absolute throwaway directory' >&2; exit 1 ;; esac
case "$jail_root" in /|/root|/usr|/usr/local|/etc|/var|/tmp|*//*|*/./*|*/.|*/../*|*/..) echo 'Unsafe JAIL_ROOT' >&2; exit 1 ;; esac
[ ! -L "$jail_root" ] || { echo 'JAIL_ROOT must not be a symbolic link' >&2; exit 1; }
target_python="${TARGET_PYTHON:-python3.13}"
python_version="${target_python#python}"
runtime_versions="$(pkg query -a '%n-%v' | awk '/^opnsense-[0-9]/ || /^php[0-9]+-/ || /^python[0-9]+-/ || /^py[0-9]+-/ {print}' | LC_ALL=C sort)"
prepare_digest="$(printf '%s\n%s\n%s\n' "$(sha256 -q "$0")" "$target_python" "$runtime_versions" | sha256 -q)"
[ ! -f "$jail_root/.prepared" ] || [ "$(cat "$jail_root/.prepared")" != "$prepare_digest" ] || exit 0
mkdir -p "$jail_root" "$jail_root/usr/local/bin" "$jail_root/usr/local/sbin" "$jail_root/usr/local/lib" "$jail_root/usr/local/etc" "$jail_root/usr/local/etc/inc" "$jail_root/conf" "$jail_root/tmp" "$jail_root/var/run" "$jail_root/var/log" "$jail_root/var/db/pkg" "$jail_root/var/unbound/etc" "$jail_root/dev" "$jail_root/root" "$jail_root/etc"
chmod 1777 "$jail_root/tmp"
for source in /bin /sbin /lib /libexec; do [ -d "$jail_root$source" ] || cp -a "$source" "$jail_root/"; done
mkdir -p "$jail_root/usr/bin" "$jail_root/usr/lib"
for name in awk sed date pkill pgrep env install tar touch find basename id whoami setfib freebsd-version uname; do source="$(command -v "$name")"; mkdir -p "$jail_root$(dirname "$source")"; cp -L "$source" "$jail_root$source"; done
# Keep the compatibility paths the plugin and resolver adapter execute directly.
for source in /usr/bin/pgrep /usr/bin/pkill; do cp -L "$source" "$jail_root$source"; done
cp -L "/usr/local/bin/$target_python" "$jail_root/usr/local/bin/$target_python"
cp -L "/usr/local/bin/$target_python" "$jail_root/usr/local/bin/python3"
for name in php curl; do cp -L "/usr/local/bin/$name" "$jail_root/usr/local/bin/$name"; done
mkdir -p "$jail_root/usr/sbin"
cp -L /usr/sbin/daemon "$jail_root/usr/sbin/"
cp -a /etc/rc.subr "$jail_root/etc/"
cp -L /usr/local/sbin/pkg-static "$jail_root/usr/local/sbin/pkg"
cp -L /usr/local/sbin/unbound "$jail_root/usr/local/sbin/"
cp -L /usr/local/sbin/unbound-checkconf "$jail_root/usr/local/sbin/"
# Copy framework code and interpreter modules from the package inventory only.
# Live config.xml, generated PHP configuration, credentials and caches never enter it.
mkdir -p "$jail_root/usr/local/etc/php" "$jail_root/var/lib/php/tmp" "$jail_root/var/lib/php/cache"
if [ -d "$jail_root/usr/local/lib/python$python_version" ]; then
    find "$jail_root/usr/local/lib/python$python_version" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
fi
pkg query -a '%Fp' | awk -v python_base="/usr/local/lib/python$python_version/" '
    index($0, python_base) == 1 && $0 !~ /\/__pycache__\// && $0 !~ /\.(pyc|pyo)$/ {print; next}
    /^\/usr\/local\/lib\/php\/[0-9]+\/[A-Za-z0-9_]+\.so$/ {print; next}
    /^\/usr\/local\/opnsense\/mvc\/script\/load_phalcon\.php$/ {print; next}
    /^\/usr\/local\/opnsense\/mvc\/app\/config\/(AppConfig|config|loader)\.php$/ {print; next}
    /^\/usr\/local\/opnsense\/mvc\/app\/library\/OPNsense\/(Autoload|Core|Base)\/.+\.php$/ {print; next}
    /^\/usr\/local\/opnsense\/mvc\/app\/models\/OPNsense\/Base\/.+\.(php|xml)$/ {print}
' | LC_ALL=C sort -u > "$jail_root/root/pkg-owned-runtime.list"
find "$jail_root/usr/local/etc/php" -type f -name '*.ini' -delete
copy_runtime_file()
{
    runtime_source="$1"
    copy_source="$runtime_source"
    if [ -L "$runtime_source" ]; then
        case "$runtime_source" in
            /usr/local/lib/python"$python_version"/*) ;;
            *) echo "Unsupported package-owned runtime link: $runtime_source" >&2; return 1 ;;
        esac
        copy_source="$(realpath "$runtime_source")"
        LC_ALL=C grep -Fqx -- "$copy_source" "$jail_root/root/pkg-owned-runtime.list" || {
            echo "Runtime link target is outside the package-owned inventory: $runtime_source" >&2
            return 1
        }
    fi
    [ -f "$copy_source" ] && [ ! -L "$copy_source" ] || { echo "Missing package-owned runtime file: $runtime_source" >&2; return 1; }
    mkdir -p "$jail_root$(dirname "$runtime_source")"
    cp -p -P "$runtime_source" "$jail_root$runtime_source"
}
while IFS= read -r source; do
    copy_runtime_file "$source"
    case "$source" in
        /usr/local/lib/php/*/*.so)
            module="$(basename "$source" .so)"
            order=20
            case "$module" in session) order=18 ;; phalcon) order=30 ;; esac
            printf 'extension="%s"\n' "$source" > "$jail_root/usr/local/etc/php/ext-$order-$module.ini"
            ;;
    esac
done < "$jail_root/root/pkg-owned-runtime.list"
for required in script/load_phalcon.php app/config/AppConfig.php app/config/config.php app/library/OPNsense/Core/Config.php app/models/OPNsense/Base/BaseModel.php; do
    [ -f "$jail_root/usr/local/opnsense/mvc/$required" ] || { echo "Missing native framework: $required" >&2; exit 1; }
done
printf '%s\n' 'include_path="/usr/local/etc/inc:/usr/local/opnsense/mvc"' 'memory_limit=1G' 'date.timezone=UTC' 'display_errors=stderr' 'html_errors=Off' > "$jail_root/usr/local/etc/php.ini"
for binary in "/usr/local/bin/$target_python" /usr/local/bin/php /usr/local/bin/curl /usr/local/sbin/unbound /usr/local/sbin/unbound-checkconf /usr/bin/awk /usr/bin/sed /usr/bin/date /usr/bin/pkill /usr/bin/pgrep /usr/bin/install /usr/bin/tar /usr/local/lib/php/*/*.so /usr/local/lib/python"$python_version"/lib-dynload/*.so; do
  [ -f "$binary" ] || continue
  ldd -f '%p\n' "$binary" 2>/dev/null | while read -r library; do
    case "$library" in /*) mkdir -p "$jail_root$(dirname "$library")"; [ -f "$jail_root$library" ] || cp -L "$library" "$jail_root$library" ;; esac
  done
done
# Load genuine classes without constructing Config or reading any XML yet.
# shellcheck disable=SC2016
chroot "$jail_root" /usr/local/bin/php -r '
    require_once("/usr/local/opnsense/mvc/script/load_phalcon.php");
    $core = new ReflectionClass("OPNsense\\Core\\Config");
    if ($core->getFileName() !== "/usr/local/opnsense/mvc/app/library/OPNsense/Core/Config.php" ||
        !class_exists("OPNsense\\Base\\BaseModel")) {
        exit(1);
    }
'
# The test resolver and OS configuration are synthetic; no production secrets are copied.
printf 'nameserver 127.0.0.1\n' > "$jail_root/etc/resolv.conf"
printf 'root:*:0:0::0:0:root:/root:/bin/sh\nnobody:*:65534:65534::0:0:Nobody:/:/usr/sbin/nologin\n' > "$jail_root/etc/master.passwd"
printf 'wheel:*:0:root\nnobody:*:65534:\n' > "$jail_root/etc/group"
pwd_mkdb -d "$jail_root/etc" "$jail_root/etc/master.passwd"
printf "%s\n" "$prepare_digest" > "$jail_root/.prepared"
echo 'Throwaway jail filesystem prepared'
