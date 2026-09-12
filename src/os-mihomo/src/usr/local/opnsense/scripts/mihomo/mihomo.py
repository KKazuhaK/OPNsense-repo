#!/usr/local/bin/python3
"""Manage Mihomo configuration, service state, and transparent DNS as one unit."""
import argparse
import contextlib
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time

import yaml

MAX_CONFIG = 16 * 1024 * 1024
SCRIPT = "/usr/local/opnsense/scripts/mihomo/mihomo.py"
HELPER = "/usr/local/opnsense/scripts/mihomo/setup_unbound.php"
STATE = "/var/db/os-mihomo"
HOME = STATE + "/home"
SHARE = "/usr/local/share/mihomo"
PID = "/var/run/mihomo-child.pid"
DAEMON_PID = "/var/run/mihomo.pid"
WATCH_PID = "/var/run/mihomo-watch.pid"
WATCH_CHILD_PID = "/var/run/mihomo-watch-child.pid"
DEFAULT_UI_URL = "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip"


class Error(Exception):
    pass


class Loader(yaml.SafeLoader):
    """Use YAML 1.2 booleans and reject ambiguous duplicate explicit keys."""
    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values
              if tag not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp"}]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key, _ in node.value:
            if key.tag == "tag:yaml.org,2002:merge":
                continue
            value = self.construct_object(key, deep=deep)
            try:
                if value in seen:
                    raise Error("The YAML contains duplicate mapping keys.")
                seen.add(value)
            except TypeError:
                raise Error("YAML mapping keys must be scalars.") from None
        self.flatten_mapping(node)
        return super().construct_mapping(node, deep=deep)


Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))


def parse_yaml(content):
    if len(content) > MAX_CONFIG:
        raise Error("The subscription exceeds the configuration size limit.")
    try:
        data = yaml.load(content, Loader=Loader)
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError):
        raise Error("The subscription is not valid YAML.") from None
    if not isinstance(data, dict):
        raise Error("A complete YAML configuration mapping is required.")

    def inspect(value, parents=(), depth=0):
        if depth > 80 or id(value) in parents:
            raise Error("Recursive or excessively nested YAML is not supported.")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise Error("Configuration mapping keys must be strings.")
            for child in value.values():
                inspect(child, parents + (id(value),), depth + 1)
        elif isinstance(value, list):
            for child in value:
                inspect(child, parents + (id(value),), depth + 1)
    inspect(data)
    return data


def check_subscription(data):
    proxies = data.get("proxies")
    providers = data.get("proxy-providers")
    if not ((isinstance(proxies, list) and proxies) or (isinstance(providers, dict) and providers)):
        raise Error("The subscription must contain top-level proxies or proxy-providers.")
    if not isinstance(data.get("proxy-groups"), list) or not isinstance(data.get("rules"), list) or not data["rules"]:
        raise Error("The subscription must include proxy-groups and a nonempty rules list.")


def merge_yaml(base, overlay):
    """Deep-merge mappings and apply the six explicit list extensions."""
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key.startswith(('prepend-', 'append-')):
            target = key.split('-', 1)[1]
            if target not in {'rules', 'proxy-groups', 'proxies'} or not isinstance(value, list):
                raise Error("Unsupported list extension in merge YAML.")
            continue
        if isinstance(value, dict) and value and isinstance(result.get(key), dict):
            result[key] = merge_yaml(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    for target in ('rules', 'proxy-groups', 'proxies'):
        if any(prefix + target in overlay for prefix in ('prepend-', 'append-')):
            current = result.get(target, [])
            if not isinstance(current, list):
                raise Error("List extensions require a list value.")
            result[target] = copy.deepcopy(overlay.get('prepend-' + target, [])) + current + copy.deepcopy(overlay.get('append-' + target, []))
    return result


def dns_transport_rules(content):
    """Read literal upstream IPs without resolving their verification names."""
    addresses = set()
    for value in re.findall(r'^\s*forward-addr:\s*([^\s#]+)', content, re.MULTILINE):
        address = value.strip('"').split('@', 1)[0].strip('[]')
        try:
            addresses.add(ipaddress.ip_address(address))
        except ValueError:
            raise Error("The router DNS upstream must use literal IP addresses.") from None
    if not addresses:
        raise Error("No router DNS upstream addresses were found. Configure explicit forwarding upstreams first.")
    return [('IP-CIDR' if ip.version == 4 else 'IP-CIDR6') + ',' + str(ip) + ('/32' if ip.version == 4 else '/128') + ',DIRECT,no-resolve'
            for ip in sorted(addresses, key=lambda ip: (ip.version, int(ip)))] + ['DST-PORT,853,DIRECT']


def advertises_ipv6(content):
    """Detect enabled router-advertisement or DHCPv6 server configuration."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise Error("Unable to inspect the router IPv6 configuration.") from None
    for group in ('radvd', 'dhcpdv6'):
        for entry in root.findall('./' + group + '/*'):
            enabled = entry.find('enable')
            if enabled is not None and (enabled.text or '').strip().lower() not in {'0', 'false', 'no'}:
                return True
            if group == 'radvd' and entry.findtext('mode', '').lower() not in {'', 'disabled'}:
                return True
    for service in ('Kea/dhcp6', 'Dhcprelay/dhcp6', 'RouterAdvertisements'):
        for entry in root.findall('./OPNsense/' + service + '//enabled'):
            if (entry.text or '').strip() == '1':
                return True
    return False


def render(data, settings, transparent=None, overlay=None, upstreams='', ipv6_advertised=False):
    result = copy.deepcopy(data)
    router_dns = settings.get('router_dns', False)
    if router_dns:
        result = merge_yaml(result, {'dns': {
            'nameserver': ['127.0.0.1'], 'proxy-server-nameserver': ['127.0.0.1'],
            'default-nameserver': ['127.0.0.1'], 'nameserver-policy': {}}})
        # An empty policy replaces the provider policy rather than deep-merging it.
        result['dns']['nameserver-policy'] = {}
    if overlay is None:
        overlay = parse_yaml((Path(__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml').read_bytes())
        if settings.get('controller'):
            overlay['external-controller'] = settings['controller']
    result = merge_yaml(result, overlay)
    enabled = settings["transparent"] if transparent is None else transparent
    dns = result.get("dns", {})
    if not isinstance(dns, dict):
        raise Error("The dns section must be a mapping.")
    tun = result.get('tun', {})
    if not isinstance(tun, dict):
        raise Error("The tun section must be a mapping.")
    for section in (tun, dns):
        if 'enable' in section and not isinstance(section['enable'], bool):
            raise Error("TUN and DNS enablement must be boolean values.")
    if not enabled:
        tun.update(enable=False, **{'auto-route': False, 'strict-route': False, 'dns-hijack': []})
        dns.update(enable=False, listen='')
    tun['device'] = 'tun_mihomo'
    if enabled and tun.get('enable') and dns.get('enable') and dns.get("enhanced-mode") == "fake-ip":
        try:
            network = ipaddress.ip_network(dns.get("fake-ip-range", "198.18.0.1/16"), strict=False)
        except ValueError:
            raise Error("The fake-IP range is invalid.") from None
        if network.version != 4 or not network.subnet_of(ipaddress.ip_network("198.18.0.0/15")):
            raise Error("The fake-IP range must stay within 198.18.0.0/15.")
    result["dns"] = dns
    result['tun'] = tun
    result.update({
        "external-ui": result.get('external-ui', HOME + "/ui"),
        "external-ui-url": result.get('external-ui-url', DEFAULT_UI_URL), "secret": settings["secret"],
    })
    for key in ('port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port'):
        value = result.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535 or value == 53:
            raise Error("Proxy listener ports must be valid and cannot use port 53.")
    for value in (dns.get('listen', ''), result.get('external-controller', ''), result.get('external-controller-tls', '')):
        if value:
            if not isinstance(value, str) or ':' not in value:
                raise Error('Listeners require a numeric port other than 53.')
            port = value.rsplit(':', 1)[-1]
            if not re.fullmatch('[0-9]{1,5}', port) or not 0 <= int(port) <= 65535 or int(port) == 53:
                raise Error('Listeners require a numeric port other than 53.')
    for listener in result.get('listeners', []):
        if not isinstance(listener, dict):
            raise Error('Additional listeners must be mappings.')
        port = listener.get('port', 0)
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535 or port == 53:
            raise Error("Additional listeners cannot bind port 53.")
    if router_dns:
        if ipv6_advertised and not (result.get('ipv6') is True and dns.get('ipv6') is True):
            raise Error("Clients are being offered IPv6 while Mihomo IPv6 is disabled. Validate IPv6 before enabling router DNS.")
        if dns.get('fallback'):
            raise Error("Remove DNS fallback upstreams from merge YAML before enabling router DNS.")
        result['rules'] = dns_transport_rules(upstreams) + result.get('rules', [])
    return yaml.safe_dump(result, allow_unicode=True, sort_keys=False).encode()


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class System:
    def run(self, args, timeout=45, check=True):
        try:
            result = subprocess.run(args, capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            raise Error("A system operation failed or timed out.") from None
        output = result.stdout + result.stderr
        failed_action = args[0] == "/usr/local/sbin/configctl" and (b"Execute error" in output or b"Error (" in output)
        if check and (result.returncode or failed_action):
            raise Error("A system operation failed; the previous configuration was retained.")
        return result

    def valid_pid(self, path, expected):
        try:
            pid = int(Path(path).read_text().strip())
            if pid <= 1:
                return None
            result = self.run(["/bin/ps", "-p", str(pid), "-o", "command="], check=False)
            command = shlex.split(result.stdout.decode(errors='replace'))
            matches = expected in command if expected == SCRIPT else bool(command and (command[0] == expected or (expected == 'daemon' and Path(command[0]).name in {'daemon', 'daemon:'})))
            if result.returncode == 0 and matches:
                return pid
        except (OSError, ValueError):
            pass
        return None

    def running(self):
        return self.valid_pid(PID, "/usr/local/bin/mihomo") is not None

    def validate(self, candidate):
        result = self.run(["/usr/local/bin/mihomo", "-t", "-d", HOME, "-f", str(candidate)], timeout=90, check=False)
        if result.returncode:
            raise Error("Mihomo rejected the configuration. No configuration was applied.")

    def start(self, config, transparent):
        data = parse_yaml(Path(config).read_bytes())
        needs_dns = data.get('dns', {}).get('enable') and data.get('dns', {}).get('listen') == '127.0.0.1:1053'
        if transparent and self.run(["/usr/sbin/service", "sing-box", "onestatus"], check=False).returncode == 0:
            raise Error("Sing-box already owns transparent routing.")
        if self.running() or self.run(["/usr/bin/pgrep", "-x", "mihomo"], check=False).returncode == 0:
            raise Error("Mihomo is already running; an existing process must be stopped before starting another.")
        self.destroy_tun()
        self.run(["/usr/sbin/daemon", "-P", DAEMON_PID, "-p", PID, "-f", "-o", "/var/log/mihomo.log",
                  "-t", "mihomo", "/usr/local/bin/mihomo", "-d", HOME, "-f", str(config)])
        for _ in range(30):
            if self.running():
                port = data.get('mixed-port') or data.get('socks-port') or data.get('port')
                if port:
                    bind = data.get('bind-address', '127.0.0.1')
                    bind = '127.0.0.1' if bind in {'*', '0.0.0.0', '::'} else bind.strip('[]')
                    try:
                        with socket.create_connection((bind, port), timeout=0.5):
                            pass
                    except OSError:
                        time.sleep(0.5)
                        continue
                if transparent:
                    present = self.run(['/sbin/ifconfig', 'tun_mihomo'], check=False).returncode == 0
                    routed = not data.get('tun', {}).get('auto-route') or b'tun_mihomo' in self.run(['/sbin/route', '-n', 'get', '8.8.8.8'], check=False).stdout
                    if not (present and routed):
                        time.sleep(0.5)
                        continue
                if not needs_dns:
                    return
                try:
                    with socket.create_connection(("127.0.0.1", 1053), timeout=0.5):
                        return
                except OSError:
                    pass
            time.sleep(0.5)
        self.stop()
        raise Error("Mihomo did not become ready.")

    def stop(self):
        pids = [self.valid_pid(PID, "/usr/local/bin/mihomo"), self.valid_pid(DAEMON_PID, "daemon")]
        for pid in pids:
            if pid:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            remaining = []
            for pid in pids:
                if pid:
                    try:
                        os.kill(pid, 0)
                        remaining.append(pid)
                    except ProcessLookupError:
                        pass
            if not remaining:
                break
            time.sleep(0.1)
        for pid in remaining if pids else []:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        time.sleep(0.1)
        if self.running():
            raise Error("Mihomo could not be stopped.")
        for path in (PID, DAEMON_PID):
            Path(path).unlink(missing_ok=True)
        self.destroy_tun()

    def destroy_tun(self):
        if self.run(["/sbin/ifconfig", "tun_mihomo"], check=False).returncode == 0:
            self.run(["/sbin/ifconfig", "tun_mihomo", "destroy"])

    def dns(self, enabled, settings):
        pending = Path(STATE) / "dns-reload-pending"
        was_pending = pending.exists()
        atomic_write(pending, b"pending\n")
        result = self.run(["/usr/local/bin/php", HELPER, "enable" if enabled else "disable",
                  "1" if settings["dns_fallback"] else "0"], timeout=90)
        if b"unchanged" in result.stdout and not was_pending:
            pending.unlink(missing_ok=True)
            return
        self.run(["/usr/local/sbin/configctl", "template", "reload", "OPNsense/Unbound"], timeout=90)
        self.run(["/usr/local/sbin/unbound-checkconf", "/var/unbound/unbound.conf"], timeout=30)
        for args in (["unbound", "restart"], ["unbound", "cache", "flush"], ["filter", "reload"]):
            self.run(["/usr/local/sbin/configctl", *args], timeout=90)
        pending.unlink(missing_ok=True)

    def remove(self):
        self.run(["/usr/local/bin/php", HELPER, "remove"], timeout=90)
        self.run(["/usr/local/sbin/configctl", "filter", "reload"], timeout=90)
        self.run(["/usr/local/sbin/configctl", "cron", "restart"], timeout=90)

    def tun(self):
        self.run(['/usr/local/bin/php', HELPER, 'enable-tun'], timeout=90)
        self.run(['/usr/local/sbin/configctl', 'filter', 'reload'], timeout=90)

    def check_router_dns(self):
        import struct
        query = struct.pack('!HHHHHH', 0x4d48, 0x100, 1, 0, 0, 0) + b'\x09localhost\x00\x00\x01\x00\x01'
        try:
            with socket.create_connection(('127.0.0.1', 53), timeout=3) as client:
                client.sendall(struct.pack('!H', len(query)) + query)
                length = client.recv(2)
                if len(length) != 2:
                    raise ValueError
                response = b''
                size = struct.unpack('!H', length)[0]
                while len(response) < size:
                    part = client.recv(size - len(response))
                    if not part:
                        raise ValueError
                    response += part
                if len(response) < 12 or response[:2] != query[:2] or response[3] & 15:
                    raise ValueError
        except (OSError, ValueError):
            raise Error('The router DNS resolver did not answer successfully. No provider DNS fallback is used.') from None

    def watch(self):
        if not self.valid_pid(WATCH_CHILD_PID, SCRIPT):
            self.run(["/usr/sbin/daemon", "-P", WATCH_PID, "-p", WATCH_CHILD_PID, "-f", "-o", "/var/log/mihomo.log",
                      "-t", "mihomo-watch", "/usr/local/bin/python3", SCRIPT, "watch"])

    def stop_watch(self):
        for path, expected in ((WATCH_CHILD_PID, SCRIPT), (WATCH_PID, "daemon")):
            pid = self.valid_pid(path, expected)
            if pid:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGTERM)
            Path(path).unlink(missing_ok=True)


def fetch_subscription(url, user_agent, proxy="127.0.0.1:7891", run=subprocess.run, sleep=time.sleep):
    try:
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
    except ValueError:
        raise Error("A valid HTTP or HTTPS subscription URL is required.") from None
    if any(char in url + user_agent for char in "\r\n\x00"):
        raise Error("The URL and User-Agent must not contain control characters.")
    with tempfile.TemporaryDirectory(prefix="mihomo-fetch-") as directory:
        output = Path(directory) / "subscription.yaml"
        curl_config = Path(directory) / "curl.conf"
        escaped = url.replace("\\", "\\\\").replace('"', '\\"')
        atomic_write(curl_config, ('url = "' + escaped + '"\n').encode())
        routes = [None] + ([proxy] if proxy else [])
        for route in routes:
            for attempt in range(2):
                args = ["/usr/local/bin/curl", "--disable", "--config", str(curl_config), "--silent",
                        "--location", "--max-redirs", "3", "--proto", "=http,https", "--proto-redir", "=https",
                        "--connect-timeout", "10", "--max-time", "30", "--max-filesize", str(MAX_CONFIG),
                        "--user-agent", user_agent, "--output", str(output), "--write-out", "%{http_code}"]
                if route:
                    args += ["--socks5-hostname", route]
                else:
                    args += ["--noproxy", "*"]
                try:
                    response = run(args, capture_output=True, timeout=35)
                except subprocess.TimeoutExpired:
                    response = subprocess.CompletedProcess(args, 28, b"000", b"")
                except OSError:
                    raise Error("Curl is unavailable.") from None
                status = response.stdout.decode(errors="replace").strip()
                if status.isdigit() and 400 <= int(status) < 500:
                    raise Error("The subscription returned HTTP " + status + ". No retry or proxy fallback was attempted.")
                if response.returncode == 0 and status == "200":
                    content = output.read_bytes()
                    if not content:
                        raise Error("The subscription response is empty.")
                    return content
                retryable = response.returncode == 28 or (status.isdigit() and 500 <= int(status) <= 599)
                if not retryable:
                    raise Error("The subscription request failed. Check its URL, TLS certificate, and network.")
                if attempt == 0:
                    sleep(1)
    raise Error("The subscription could not be fetched after bounded timeout/server-error retries.")


class Manager:
    def __init__(self, root=Path("/"), system=None):
        self.root = Path(root)
        self.system = system or System()
        self.state = self.path(STATE)
        self.settings_file = self.state / "settings.json"
        self.source_file = self.state / "subscription.yaml"
        self.config_file = self.state / "config.yaml"
        self.merge_file = self.state / 'merge.yaml'
        self.status_file = self.path("/var/run/mihomo-status.json")

    def path(self, path):
        return self.root / path.lstrip("/")

    @contextlib.contextmanager
    def lock(self, blocking=True):
        path = self.path("/var/run/os-mihomo.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                raise Error("Another Mihomo operation is in progress.") from None
            yield

    def settings(self):
        try:
            value = json.loads(self.settings_file.read_bytes())
            value.setdefault('router_dns', False)
            self.check_settings(value)
            return value
        except (OSError, ValueError, TypeError, KeyError):
            raise Error("Mihomo settings are missing or invalid; run initialization first.") from None

    def check_settings(self, settings):
        for key in ("transparent", "dns_fallback", "service_enabled", 'router_dns'):
            if key == 'router_dns' and key not in settings:
                continue
            if not isinstance(settings.get(key), bool):
                raise Error("Service policies must be boolean values.")
        if not isinstance(settings.get("secret"), str) or not settings["secret"]:
            raise Error("A nonempty dashboard secret is required.")
        controller = settings.get("controller", "127.0.0.1:9090")
        try:
            host, port = controller.rsplit(":", 1)
            address = ipaddress.IPv4Address(host)
            if address.is_unspecified or not 1 <= int(port) <= 65535:
                raise ValueError
        except (AttributeError, ValueError):
            raise Error("The controller must bind to a specific IPv4 address and port.") from None
        for key in ("subscription_url", "device"):
            if not isinstance(settings.get(key), str) or any(char in settings[key] for char in "\r\n\x00"):
                raise Error("Invalid subscription settings.")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", settings["device"]):
            raise Error("The device label must contain only letters, digits, dots, underscores, or hyphens.")

    def write_settings(self, settings):
        self.check_settings(settings)
        atomic_write(self.settings_file, (json.dumps(settings, indent=2) + "\n").encode())

    def publish_status(self, settings=None, dns_active=False, error=""):
        settings = settings or self.settings()
        status = {"running": self.system.running(), "transparent": settings["transparent"],
                  "dns_active": dns_active, "dns_fallback": settings["dns_fallback"],
                  "service_enabled": settings["service_enabled"], "error": error, "updated": time.time()}
        atomic_write(self.status_file, json.dumps(status).encode(), 0o644)
        return status

    def log(self, message):
        message = time.strftime("[%Y-%m-%d %H:%M:%S] ") + message + "\n"
        path = self.path("/var/log/mihomo_sub.log")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            with os.fdopen(fd, "a") as stream:
                os.chmod(path, 0o640)
                stream.write(message)
        except OSError:
            pass

    def initialize(self, upgrade=False):
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        if self.settings_file.exists():
            settings = self.settings()
        else:
            legacy = self.state / "migrate"
            source = legacy / "config.yaml"
            existing = parse_yaml(source.read_bytes()) if source.exists() else {}
            env = {}
            if (legacy / "env").exists():
                for line in (legacy / "env").read_text().splitlines():
                    try:
                        tokens = shlex.split(line)
                        if tokens and "=" in tokens[-1]:
                            key, value = tokens[-1].split("=", 1)
                            env[key] = value
                    except ValueError:
                        raise Error("The legacy subscription settings could not be read.") from None
            settings = {"subscription_url": env.get("mihomo_URL", ""),
                        "secret": env.get("mihomo_secret") or existing.get("secret") or secrets.token_hex(32),
                        "device": re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname())[:64] or "router",
                        "transparent": False, 'router_dns': False,
                        "dns_fallback": True, "service_enabled": True}
            if existing:
                atomic_write(self.source_file, source.read_bytes())
            self.write_settings(settings)
        # Every installation or upgrade requires an explicit new TUN activation.
        settings.update(transparent=False, service_enabled=True)
        self.write_settings(settings)
        if not self.merge_file.exists():
            preset = self.path(SHARE + '/presets/full.yaml')
            if not preset.exists():
                preset = Path(__file__).resolve().parents[3] / 'share/mihomo/presets/full.yaml'
            overlay = parse_yaml(preset.read_bytes())
            if settings.get('controller'):
                overlay['external-controller'] = settings['controller']
            atomic_write(self.merge_file, yaml.safe_dump(overlay, sort_keys=False).encode())
        runtime_home = self.path(HOME)
        runtime_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ('GeoIP.dat', 'GeoSite.dat'):
            target = runtime_home / name
            if not target.exists() and not target.is_symlink():
                target.symlink_to(SHARE + '/' + name)
        data = parse_yaml(self.source_file.read_bytes()) if self.source_file.exists() else {
            "proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"], "log-level": "info"}
        candidate = self.candidate(data, settings)
        try:
            self.system.validate(candidate)
            atomic_write(self.config_file, candidate.read_bytes())
        finally:
            candidate.unlink(missing_ok=True)
        self.publish_status(settings)
        return {"initialized": True, "transparent": settings["transparent"]}

    def router_context(self, settings):
        if not settings.get('router_dns'):
            return '', False
        config = self.path('/conf/config.xml').read_bytes()
        upstreams = self.path('/var/unbound/etc/dot.conf').read_text()
        if (self.state / 'dns-state.json').exists():
            import xml.etree.ElementTree as ET
            snapshot = json.loads((self.state / 'dns-state.json').read_bytes())
            entries = ET.fromstring(config).findall('./OPNsense/unboundplus/dots/dot')
            upstreams = '\n'.join('forward-addr: ' + node.findtext('server', '') + '@' + node.findtext('port', '853')
                for node in entries if node.get('uuid') != 'b126bf65-a985-49ca-a9d2-16f156aac198'
                and (node.findtext('enabled') == '1' or snapshot.get('roots', {}).get(node.get('uuid')) == '1'))
        return upstreams, advertises_ipv6(config)

    def candidate(self, data, settings, overlay=None):
        upstreams, ipv6 = self.router_context(settings)
        content = render(data, settings, overlay=overlay if overlay is not None else parse_yaml(self.merge_file.read_bytes()), upstreams=upstreams, ipv6_advertised=ipv6)
        fd, name = tempfile.mkstemp(prefix=".candidate-", suffix=".yaml", dir=self.state)
        os.close(fd)
        path = Path(name)
        atomic_write(path, content)
        return path

    def stop(self, settings=None):
        settings = settings or self.settings()
        # Restore direct DNS before stopping the listener, even for fail-closed policy.
        failed = None
        try:
            self.system.dns(False, settings)
        except (Error, OSError) as error:
            failed = error
        try:
            self.system.stop()
        finally:
            self.publish_status(settings, dns_active=failed is not None,
                error='DNS restoration failed; the core and TUN were stopped. Recovery will be retried.' if failed else '')
        if failed:
            raise Error('DNS restoration failed; the core and TUN were stopped. Recovery will be retried.') from None

    def start(self, settings=None):
        settings = settings or self.settings()
        if not settings["service_enabled"]:
            self.publish_status(settings)
            return {"running": False, "message": "The service is administratively stopped."}
        data = parse_yaml(self.source_file.read_bytes()) if self.source_file.exists() else {'proxies': [], 'proxy-groups': [], 'rules': ['MATCH,DIRECT']}
        candidate = self.candidate(data, settings)
        try:
            self.system.validate(candidate)
            generated = parse_yaml(candidate.read_bytes())
            atomic_write(self.config_file, candidate.read_bytes())
        finally:
            candidate.unlink(missing_ok=True)
        tun = bool(generated.get('tun', {}).get('enable'))
        dns_active = bool(tun and generated.get('dns', {}).get('enable') and generated['dns'].get('listen') == '127.0.0.1:1053' and not settings.get('router_dns'))
        self.system.dns(False, settings)
        if settings.get('router_dns'):
            self.system.check_router_dns()
        self.system.start(self.config_file, tun)
        try:
            if tun:
                self.system.tun()
            if dns_active:
                self.system.dns(True, settings)
            self.system.watch()
        except Error:
            self.stop(settings)
            raise
        return self.publish_status(settings, dns_active)

    def apply(self, content, settings=None, subscription=True, overlay=None):
        settings = settings or self.settings()
        self.check_settings(settings)
        data = parse_yaml(content)
        if subscription:
            check_subscription(data)
        candidate = self.candidate(data, settings, overlay)
        backup_dir = Path(tempfile.mkdtemp(prefix=".rollback-", dir=self.state))
        try:
            self.system.validate(candidate)
            before = {}
            for path in (self.config_file, self.source_file, self.settings_file, self.merge_file):
                backup = backup_dir / path.name
                if path.exists():
                    os.link(path, backup)
                    before[path] = backup
                else:
                    before[path] = None
            running = self.system.running()
            previous = self.settings()
            if running:
                self.stop(previous)
            try:
                atomic_write(self.config_file, candidate.read_bytes())
                if subscription:
                    atomic_write(self.source_file, content)
                self.write_settings(settings)
                if overlay is not None:
                    atomic_write(self.merge_file, yaml.safe_dump(overlay, sort_keys=False, allow_unicode=True).encode())
                if running:
                    self.start(settings)
                else:
                    self.publish_status(settings)
            except (Error, OSError):
                # Recovery files must be restored even if a DNS cleanup fails.
                try:
                    self.stop(settings)
                except (Error, OSError):
                    with contextlib.suppress(Error, OSError):
                        self.system.stop()
                for path, original in before.items():
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        os.replace(original, path)
                if running:
                    try:
                        self.system.dns(False, previous)
                        self.start(previous)
                    except (Error, OSError):
                        direct = False
                        try:
                            self.system.dns(False, previous)
                            direct = True
                        except (Error, OSError):
                            pass
                        message = "Rollback restored the files; the service could not restart. " + (
                            "Direct DNS is active." if direct else "DNS restoration also failed; integration state is retained for recovery.")
                        self.publish_status(previous, error=message)
                        raise Error(message) from None
                raise Error("The change failed. The previous configuration and secret were restored.") from None
        finally:
            candidate.unlink(missing_ok=True)
            for path in backup_dir.iterdir():
                path.unlink(missing_ok=True)
            backup_dir.rmdir()
        return {"applied": True, "proxies": len(data.get("proxies", [])), "rules": len(data["rules"])}

    def set_policy(self, enabled):
        settings = self.settings()
        settings["transparent"] = enabled
        if enabled and not self.source_file.exists():
            raise Error("Fetch and validate a subscription before enabling transparent routing.")
        if enabled and not self.system.running():
            raise Error("Start the proxy service before enabling transparent routing.")
        if enabled and not parse_yaml(self.merge_file.read_bytes()).get('tun', {}).get('enable'):
            raise Error('Choose a TUN preset or enable TUN in merge YAML before activation.')
        if self.source_file.exists():
            result = self.apply(self.source_file.read_bytes(), settings)
        else:
            data = {"proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
            result = self.apply(yaml.safe_dump(data).encode(), settings, subscription=False)
        return result

    def update_status(self, status, error=""):
        atomic_write(self.path("/var/run/mihomo-update.json"),
                     json.dumps({"status": status, "error": error, "updated": time.time()}).encode(), 0o644)

    def update(self):
        # Network waits must not prevent the watchdog from restoring DNS.
        path = self.path("/var/run/os-mihomo-sub.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("A subscription update is already running.") from None
            with self.lock():
                settings = self.settings()
                proxy = ''
                if self.system.running():
                    current = parse_yaml(self.config_file.read_bytes())
                    port = current.get('socks-port') or current.get('mixed-port')
                    bind = current.get('bind-address', '127.0.0.1')
                    bind = '127.0.0.1' if bind in {'*', '0.0.0.0', '::'} else bind
                    if port:
                        proxy = ('[' + bind + ']' if ':' in bind else bind) + ':' + str(port)
            self.update_status("running")
            self.log("Fetching the subscription directly.")
            try:
                content = fetch_subscription(settings["subscription_url"], "OPNsense-Mihomo/1 (" + settings["device"] + ")", proxy)
                with self.lock():
                    latest = self.settings()
                    if (latest["subscription_url"], latest["device"]) != (settings["subscription_url"], settings["device"]):
                        raise Error("Subscription settings changed during download. The response was discarded.")
                    result = self.apply(content, latest)
                self.log("Subscription validated and applied.")
                self.update_status("completed")
                return result
            except (Error, OSError) as error:
                message = str(error) if isinstance(error, Error) else "Unable to read or persist the subscription configuration."
                self.log(message)
                self.update_status("failed", message)
                raise

    def queue_update(self):
        self.settings()
        path = self.path("/var/run/mihomo-update.pid")
        if self.system.valid_pid(str(path), SCRIPT):
            raise Error("A subscription update is already queued or running.")
        process = subprocess.Popen(["/usr/local/bin/python3", SCRIPT, "sub-update"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        atomic_write(path, str(process.pid).encode())
        return {"queued": True}

    def watchdog_tick(self):
        settings = self.settings()
        try:
            status = json.loads(self.status_file.read_bytes())
        except (OSError, ValueError):
            status = {}
        active = bool(status.get("dns_active"))
        if not self.system.running():
            self.system.destroy_tun()
            if active and (settings['dns_fallback'] or not settings['service_enabled'] or (self.state / 'dns-reload-pending').exists()):
                self.system.dns(False, settings)
                return self.publish_status(settings, error="Mihomo exited. Direct DNS and routing were restored automatically.")
        if settings.get('router_dns'):
            upstreams, ipv6 = self.router_context(settings)
            data = parse_yaml(self.config_file.read_bytes())
            if ipv6 and not (data.get('ipv6') is True and data.get('dns', {}).get('ipv6') is True):
                return self.publish_status(settings, active, error='IPv6 is now being advertised to clients while Mihomo IPv6 is disabled. Disable router DNS or validate IPv6 support.')
            pins = dns_transport_rules(upstreams)
            if self.system.running() and data.get('rules', [])[:len(pins)] != pins:
                self.apply(self.source_file.read_bytes(), settings)
                return self.publish_status(settings, active)
        return self.publish_status(settings, active)

    def dispatch(self, action, argument=None):
        if action in {"clear-log", "clear-sub-log"}:
            path = self.path("/var/log/mihomo.log" if action == "clear-log" else "/var/log/mihomo_sub.log")
            with path.open("w"):
                pass
            return {"cleared": True}
        if action == "init":
            return self.initialize(argument == "upgrade")
        if action == "queue-update":
            return self.queue_update()
        if action == "sub-update":
            return self.update()
        if action == "save-config":
            return self.apply(Path(argument).read_bytes())
        if action in {'save-merge', 'load-preset'}:
            path = Path(argument)
            if action == 'load-preset':
                name = argument if re.fullmatch(r'[a-z0-9-]+\.yaml', argument or '') else path.read_text().strip()
                if not re.fullmatch(r'[a-z0-9-]+\.yaml', name):
                    raise Error('Invalid preset name.')
                path = self.path(SHARE + '/presets/' + name)
            overlay = parse_yaml(path.read_bytes())
            content = self.source_file.read_bytes() if self.source_file.exists() else b'proxies: []\nproxy-groups: []\nrules: ["MATCH,DIRECT"]\n'
            return self.apply(content, subscription=self.source_file.exists(), overlay=overlay)
        if action == "set-settings":
            value = json.loads(Path(argument).read_bytes())
            settings = self.settings()
            for key in ("subscription_url", "secret", "device", "dns_fallback", 'router_dns'):
                if key in value:
                    settings[key] = value[key]
            if self.source_file.exists():
                return self.apply(self.source_file.read_bytes(), settings)
            base = {"proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
            return self.apply(yaml.safe_dump(base).encode(), settings, subscription=False)
        if action in {"enable-transparent", "disable-transparent"}:
            return self.set_policy(action == "enable-transparent")
        settings = self.settings()
        if action in {"suspend", "stop", "remove"}:
            if action != 'suspend':
                settings['service_enabled'] = False
                self.write_settings(settings)
            self.stop(settings)
            self.system.stop_watch()
            if action != "suspend":
                settings["service_enabled"] = False
                if action == "remove":
                    settings["transparent"] = False
                    self.system.remove()
                self.write_settings(settings)
                self.publish_status(settings)
            return {"running": False}
        if action in {"start", "restart", "boot", "wan-restart"}:
            if action in {"start", "restart"}:
                settings["service_enabled"] = True
                self.write_settings(settings)
            if action == "wan-restart" and not self.system.running():
                return {"running": False}
            if action in {"restart", "wan-restart"} and self.system.running():
                self.stop(settings)
            if self.system.running():
                return self.publish_status(settings, settings["transparent"])
            return self.start(settings)
        if action == "status":
            try:
                status = json.loads(self.status_file.read_bytes())
            except (OSError, ValueError):
                status = {}
            return self.publish_status(settings, bool(status.get("dns_active")), error=status.get('error', ''))
        raise Error("Unknown action.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Return structured action results for configd.")
    parser.add_argument("action")
    parser.add_argument("argument", nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Mihomo state changes require root privileges.", file=sys.stderr)
        return 1
    manager = Manager()
    if args.action == "watch":
        while True:
            try:
                with manager.lock(blocking=False):
                    manager.watchdog_tick()
            except (Error, OSError):
                pass
            time.sleep(5)
    try:
        if args.action == "sub-update":
            result = manager.update()
        else:
            with manager.lock():
                result = manager.dispatch(args.action, args.argument)
        if args.json:
            print(json.dumps({"ok": True, "result": result}))
        else:
            print("Mihomo operation completed.")
        return 0
    except (Error, OSError, ValueError, TypeError, KeyError) as error:
        message = str(error) if isinstance(error, Error) else "Unable to read or persist Mihomo configuration."
        if args.json:
            print(json.dumps({"ok": False, "error": message}))
            return 0
        print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
