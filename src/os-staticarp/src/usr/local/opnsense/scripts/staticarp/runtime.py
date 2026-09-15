#!/usr/local/bin/python3
"""Apply only journalled ARP bindings and interface modes under the settings lock."""
import copy
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

CONFIG_DIR = Path('/usr/local/etc/staticarp')
STATE_FILE = Path('/var/db/os-staticarp/runtime.json')
MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
DEVICE = re.compile(r'^[A-Za-z][A-Za-z0-9_.:-]{0,63}$')


class RuntimeErrorWithRecovery(RuntimeError):
    pass


class System:
    def run(self, *args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=10,
                                env={**os.environ, 'LC_ALL': 'C'})
        if result.returncode:
            raise RuntimeErrorWithRecovery('A kernel command failed: ' + ' '.join(args[:2]))
        return result.stdout

    def boot_id(self):
        output = self.run('/sbin/sysctl', '-n', 'kern.boottime')
        match = re.search(r'sec\s*=\s*([0-9]+),\s*usec\s*=\s*([0-9]+)', output)
        if not match:
            raise RuntimeErrorWithRecovery('The kernel boot identity is unavailable.')
        return match[1] + ':' + match[2]

    def interface_index(self, device):
        try:
            return socket.if_nametoindex(device)
        except OSError:
            return None

    def interfaces(self):
        rows = {}
        current = None
        for line in self.run('/sbin/ifconfig', '-a').splitlines():
            match = re.match(r'^([^\s:]+): flags=[^<]*<([^>]*)>', line)
            if match:
                current = match[1]
                flags = set(match[2].split(','))
                rows[current] = {'noarp': 'NOARP' in flags, 'staticarp': 'STATICARP' in flags,
                                 'addresses': []}
            match = re.match(r'\s+inet\s+([0-9.]+)\s', line)
            if current and match:
                rows[current]['addresses'].append(str(ipaddress.IPv4Address(match[1])))
        if not rows:
            raise RuntimeErrorWithRecovery('Could not read interface modes.')
        return rows

    def mode(self, device):
        row = self.interfaces().get(device)
        return None if row is None else {key: row[key] for key in ('noarp', 'staticarp')}

    def neighbors(self):
        rows = {}
        for line in self.run('/usr/sbin/arp', '-an').splitlines():
            match = re.match(r'^\S+ \(([0-9.]+)\) at (\S+) on (\S+)(.*)$', line)
            if not match:
                continue
            ip, mac, device, tail = match.groups()
            ip = str(ipaddress.IPv4Address(ip))
            mac = mac.lower()
            # Dynamic entries are identified without their changing expiration timer.
            row = {'mac': mac, 'permanent': ' permanent' in tail, 'published': ' published' in tail}
            if not MAC.fullmatch(mac):
                row['mac'] = '(incomplete)'
            key = device + '|' + ip
            if key in rows:
                raise RuntimeErrorWithRecovery('Ambiguous ARP binding: ' + ip)
            rows[key] = row
        return rows

    def binding(self, key):
        return self.neighbors().get(key)

    def target_interface(self, ip):
        output = self.run('/sbin/route', '-n', 'get', ip)
        match = re.search(r'^\s*interface:\s*(\S+)\s*$', output, re.M)
        flags = re.search(r'^\s*flags:\s*<([^>]*)>', output, re.M)
        if not match or not flags or 'GATEWAY' in flags[1].split(','):
            raise RuntimeErrorWithRecovery('The binding is not on a directly connected interface: ' + ip)
        return match[1]

    def mutate_mode(self, device, target):
        current = self.mode(device)
        if target is None or current is None:
            raise RuntimeErrorWithRecovery('An interface disappeared: ' + device)
        changes = [key for key in ('noarp', 'staticarp') if current[key] != target[key]]
        if len(changes) > 1:
            raise RuntimeErrorWithRecovery('Interface ARP flags must be journalled individually.')
        if changes:
            key = changes[0]
            flag = ('-arp' if target[key] else 'arp') if key == 'noarp' else ('staticarp' if target[key] else '-staticarp')
            self.run('/sbin/ifconfig', device, flag)

    def mutate_binding(self, key, target):
        device, ip = key.split('|')
        if target is not None and target['permanent']:
            arguments = ['/usr/sbin/arp', '-i', device, '-s', ip, target['mac']]
            if target['published']:
                arguments.append('pub')
            self.run(*arguments)
            return
        # arp -d hostname does not accept -i and guesses a route interface. Use
        # RTM_DELNEIGH with an explicit ifindex so overlapping subnets stay isolated.
        if not sys.platform.startswith('freebsd'):
            raise RuntimeErrorWithRecovery('Native ARP removal requires FreeBSD netlink.')
        index = socket.if_nametoindex(device)
        body = struct.pack('=BBHiHBB', socket.AF_INET, 0, 0, index, 0, 0, 0)
        body += struct.pack('=HH', 8, 1) + ipaddress.IPv4Address(ip).packed
        sequence = int.from_bytes(os.urandom(4), 'little') or 1
        family = 38
        with socket.socket(family, socket.SOCK_RAW, 0) as connection:
            # CPython FreeBSD ports vary in sockaddr_nl tuple conversion. Bind
            # the native sockaddr and use send/recv without address conversion.
            libc = ctypes.CDLL(None, use_errno=True)
            libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            libc.bind.restype = ctypes.c_int
            libc.getsockname.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
            libc.getsockname.restype = ctypes.c_int
            address = ctypes.create_string_buffer(struct.pack('=BBHII', 12, family, 0, 0, 0), 12)
            if libc.bind(connection.fileno(), address, 12):
                raise OSError(ctypes.get_errno(), 'Native ARP socket bind failed')
            length = ctypes.c_uint32(12)
            if libc.getsockname(connection.fileno(), address, ctypes.byref(length)) or length.value != 12:
                raise RuntimeErrorWithRecovery('Native ARP socket identity is unavailable.')
            size, returned_family, _, pid, groups = struct.unpack('=BBHII', address.raw)
            if size != 12 or returned_family != family or not pid or groups:
                raise RuntimeErrorWithRecovery('Native ARP socket identity is invalid.')
            header = struct.pack('=IHHII', 16 + len(body), 29, 1 | 4, sequence, pid)
            if connection.send(header + body) != len(header + body):
                raise RuntimeErrorWithRecovery('The ARP netlink request was incomplete.')
            deadline = time.monotonic() + 5
            for _ in range(32):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                connection.settimeout(remaining)
                packet = connection.recv(65536)
                offset = 0
                while offset + 16 <= len(packet):
                    length, kind, _, received, port = struct.unpack_from('=IHHII', packet, offset)
                    if length < 16 or offset + length > len(packet):
                        raise RuntimeErrorWithRecovery('Invalid ARP netlink reply.')
                    if received == sequence and port == pid and kind == 2:
                        if length < 36 or packet[offset + 20:offset + 36] != header:
                            raise RuntimeErrorWithRecovery('Invalid ARP netlink acknowledgement.')
                        error, = struct.unpack_from('=i', packet, offset + 16)
                        if error:
                            raise OSError(abs(error), os.strerror(abs(error)))
                        return
                    offset += (length + 3) & ~3
        raise RuntimeErrorWithRecovery('ARP netlink acknowledgement was not received.')



class Runtime:
    def __init__(self, system=None, config_dir=CONFIG_DIR, state_file=STATE_FILE):
        self.system = system or System()
        self.config_dir = Path(config_dir)
        self.state_file = Path(state_file)
        self.state = {'version': 1, 'boot': None, 'bindings': {}, 'modes': {}, 'conflicts': []}
        self.load()

    def load(self):
        if not self.state_file.exists() and not self.state_file.is_symlink():
            return
        info = self.state_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeErrorWithRecovery('The ARP ownership journal must be a private regular file.')
        if info.st_size > 1048576:
            raise RuntimeErrorWithRecovery('The ARP ownership journal is too large.')
        state = json.loads(self.state_file.read_text())
        if (not isinstance(state, dict) or state.get('version') != 1 or
                not isinstance(state.get('boot'), str) or not re.fullmatch(r'[0-9]+:[0-9]+', state['boot'])):
            raise RuntimeErrorWithRecovery('Unrecognized ARP ownership journal; no ownership was assumed.')
        for kind in ('bindings', 'modes'):
            rows = state.get(kind)
            if not isinstance(rows, dict) or len(rows) > 8192:
                raise RuntimeErrorWithRecovery('Invalid ARP ownership journal.')
            for key, row in rows.items():
                if isinstance(row, dict) and 'new' in row and row['new'] is not True:
                    raise RuntimeErrorWithRecovery('Invalid ARP ownership acquisition.')
                device = key.split('|')[0]
                if (not DEVICE.fullmatch(device) or not isinstance(row, dict) or
                        not {'before', 'after', 'interface_index'}.issubset(row) or
                        set(row) - {'before', 'after', 'pending', 'interface_index', 'new'} or
                        type(row['interface_index']) is not int or not 1 <= row['interface_index'] <= 0xffffffff):
                    raise RuntimeErrorWithRecovery('Invalid ARP ownership record.')
                if kind == 'bindings':
                    parts = key.split('|')
                    if len(parts) != 2 or str(ipaddress.IPv4Address(parts[1])) != parts[1]:
                        raise RuntimeErrorWithRecovery('Invalid ARP ownership binding.')
                for field in ('before', 'after', 'pending'):
                    if field == 'pending' and field not in row:
                        continue
                    value = row.get(field)
                    if value is None:
                        continue
                    if kind == 'bindings':
                        if (not isinstance(value, dict) or not MAC.fullmatch(value.get('mac', '')) or
                                type(value.get('permanent')) is not bool or type(value.get('published')) is not bool):
                            raise RuntimeErrorWithRecovery('Invalid ARP ownership binding value.')
                    elif (not isinstance(value, dict) or set(value) != {'noarp', 'staticarp'} or
                          any(type(item) is not bool for item in value.values())):
                        raise RuntimeErrorWithRecovery('Invalid ARP ownership mode value.')
        if (not isinstance(state.get('conflicts', []), list) or len(state['conflicts']) > 16384 or
                any(not isinstance(label, str) or len(label) > 128 for label in state['conflicts'])):
            raise RuntimeErrorWithRecovery('Invalid ARP ownership conflicts.')
        self.state = state
        current_boot = self.system.boot_id()
        if state['boot'] != current_boot:
            # A new kernel cannot retain old interface/neighbor ownership. Keep
            # explicit plugin settings, then snapshot this boot's native baseline.
            self.state = {'version': 1, 'boot': current_boot, 'bindings': {}, 'modes': {}, 'conflicts': []}
            self.save()

    def save(self):
        if self.state['boot'] is None:
            self.state['boot'] = self.system.boot_id()
        parent = self.state_file.parent
        if parent.is_symlink():
            raise RuntimeErrorWithRecovery('The ARP ownership directory must not be a symbolic link.')
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = parent.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeErrorWithRecovery('The ARP ownership directory must be private.')
        descriptor, temporary = tempfile.mkstemp(prefix='.runtime-', dir=parent)
        try:
            with os.fdopen(descriptor, 'w') as output:
                os.fchmod(output.fileno(), 0o600)
                json.dump(self.state, output, sort_keys=True)
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_file)
            directory = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def read(self, kind, key):
        return self.system.binding(key) if kind == 'bindings' else self.system.mode(key)

    def mutate(self, kind, key, target):
        if kind == 'bindings':
            self.system.mutate_binding(key, target)
        else:
            self.system.mutate_mode(key, target)

    def conflict(self, kind, key):
        self.state[kind].pop(key, None)
        label = kind + ':' + key
        if label not in self.state['conflicts']:
            self.state['conflicts'].append(label)
        self.save()

    def transition(self, kind, key, target, final=True):
        row = self.state[kind][key]
        if self.system.interface_index(key.split('|')[0]) != row['interface_index']:
            self.conflict(kind, key)
            return False
        live = self.read(kind, key)
        expected = row['after']
        if live != expected:
            # Administrator edits take precedence over both Apply and Reset.
            self.conflict(kind, key)
            return False
        if kind == 'modes' and live is not None and target is not None and all(live[field] != target[field] for field in ('noarp', 'staticarp')):
            # Each ioctl changes one flag. Persist the exact intermediate mode
            # before touching the next flag so retries do not guess partial success.
            intermediate = {**live, 'noarp': target['noarp']}
            if not self.transition(kind, key, intermediate, final=False):
                return False
            return self.transition(kind, key, target, final=final)
        if live == target:
            if final and target == row['before']:
                self.state[kind].pop(key)
                self.save()
            return True
        row['pending'] = copy.deepcopy(target)
        self.save()  # Write-ahead ownership is required before every kernel change.
        try:
            self.mutate(kind, key, target)
            if self.read(kind, key) != target:
                raise RuntimeErrorWithRecovery('The kernel did not apply the requested ARP state.')
        except Exception:
            # A failed command may have applied its change. Restore only when the
            # exact target is still live, keeping a durable pending record on failure.
            if target is not None and self.read(kind, key) == target:
                try:
                    self.mutate(kind, key, expected)
                except Exception:
                    pass
            rollback = expected if kind == 'modes' or expected is None or expected['permanent'] else None
            if self.read(kind, key) == rollback:
                if row.get('new'):
                    self.state[kind].pop(key)
                else:
                    row['after'] = copy.deepcopy(rollback)
                    row.pop('pending', None)
                self.save()
            raise
        row['after'] = copy.deepcopy(target)
        row.pop('new', None)
        row.pop('pending')
        if final and target == row['before']:
            self.state[kind].pop(key)
        self.save()
        return True

    def recover(self):
        for kind in ('bindings', 'modes'):
            for key, row in list(self.state[kind].items()):
                if 'pending' not in row:
                    continue
                if self.system.interface_index(key.split('|')[0]) != row['interface_index']:
                    self.conflict(kind, key)
                    continue
                live = self.read(kind, key)
                if live == row['pending']:
                    row['after'] = row.pop('pending')
                    row.pop('new', None)
                    if row['after'] == row['before']:
                        self.state[kind].pop(key)
                    self.save()
                elif live == row['after']:
                    if row.get('new'):
                        self.state[kind].pop(key)
                    else:
                        row.pop('pending')
                    self.save()
                else:
                    self.conflict(kind, key)

    def settings(self):
        if self.config_dir.is_symlink() or (self.config_dir.exists() and not self.config_dir.is_dir()):
            raise RuntimeErrorWithRecovery('The settings directory must be a regular directory.')
        for recovery in self.config_dir.glob('.staticarp-recovery-*'):
            if recovery.exists() or recovery.is_symlink():
                raise RuntimeErrorWithRecovery('A previous settings save needs recovery before applying bindings.')
        def lines(name):
            path = self.config_dir / name
            if not path.exists():
                return []
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
                raise RuntimeErrorWithRecovery('A settings file is not a bounded regular file.')
            return [line.split() for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
        enabled = ['enabled=YES'] in lines('settings.conf')
        modes = {}
        for parts in lines('interfaces.conf'):
            if len(parts) != 3 or not DEVICE.fullmatch(parts[1]) or parts[2] not in ('normal', 'staticarp', '-arp'):
                raise RuntimeErrorWithRecovery('Invalid interface mode settings.')
            modes[parts[1]] = {'noarp': parts[2] == '-arp', 'staticarp': parts[2] == 'staticarp'}
        bindings = {}
        interfaces = self.system.interfaces() if enabled else {}
        local = {ip for row in interfaces.values() for ip in row['addresses']}
        for parts in lines('entries.conf') if enabled else []:
            if len(parts) != 2 or not MAC.fullmatch(parts[1].lower()):
                raise RuntimeErrorWithRecovery('Invalid ARP binding settings.')
            ip = str(ipaddress.IPv4Address(parts[0]))
            if ip in local:
                continue
            device = self.system.target_interface(ip)
            if device not in modes or device not in interfaces:
                raise RuntimeErrorWithRecovery('The binding does not belong to an eligible configured interface: ' + ip)
            bindings[device + '|' + ip] = {'mac': parts[1].lower(), 'permanent': True, 'published': False}
        return enabled, bindings, modes

    def apply(self, reset=False):
        self.recover()
        enabled, bindings, modes = self.settings() if not reset else (False, {}, {})
        desired = {'bindings': bindings if enabled else {}, 'modes': modes if enabled else {}}
        # Restore removed bindings before restoring interface ARP restrictions.
        for kind in ('bindings', 'modes'):
            for key, row in list(self.state[kind].items()):
                if key not in desired[kind]:
                    self.transition(kind, key, row['before'])
            for key, target in desired[kind].items():
                label = kind + ':' + key
                if label in self.state['conflicts']:
                    continue
                if key not in self.state[kind]:
                    live = self.read(kind, key)
                    if live == target:
                        continue  # Identical foreign state is never claimed as owned.
                    if kind == 'modes' and live is None:
                        raise RuntimeErrorWithRecovery('An interface is unavailable: ' + key)
                    if kind == 'bindings' and live is not None and (live['published'] or live['mac'] == '(incomplete)'):
                        raise RuntimeErrorWithRecovery('An existing special ARP entry cannot be safely replaced: ' + key)
                    before = live if kind == 'modes' or live is None or live['permanent'] else None
                    index = self.system.interface_index(key.split('|')[0])
                    if index is None:
                        raise RuntimeErrorWithRecovery('An interface is unavailable: ' + key)
                    self.state[kind][key] = {'before': copy.deepcopy(before), 'after': copy.deepcopy(live),
                                             'interface_index': index, 'new': True}
                    # Dynamic entries are compared before overwrite but not restored
                    # with a invented lifetime: normal ARP discovery resumes on Reset.
                    self.transition(kind, key, target)
                else:
                    self.transition(kind, key, target)
        active = {kind + ':' + key for kind in desired for key in desired[kind]}
        conflicts = [label for label in self.state['conflicts'] if label in active]
        self.state['conflicts'] = [label for label in self.state['conflicts'] if label in active]
        if self.state_file.exists() or self.state['bindings'] or self.state['modes'] or self.state['conflicts']:
            self.save()
        if conflicts:
            raise RuntimeErrorWithRecovery('Administrator ARP changes were preserved; remove conflicting settings before applying again.')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('apply', 'reset'):
        return 64
    try:
        Runtime().apply(reset=sys.argv[1] == 'reset')
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
