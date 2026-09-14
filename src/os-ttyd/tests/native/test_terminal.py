"""Run the bundled ttyd with a private PTY and verify its actual WebSocket I/O."""
import base64
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

PACKAGE = Path(__file__).resolve().parents[2]


def send_frame(connection, payload, opcode=2):
    mask = os.urandom(4)
    size = len(payload)
    header = bytes([0x80 | opcode, 0x80 | size]) if size < 126 else bytes([0x80 | opcode, 0xfe]) + struct.pack('!H', size)
    connection.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))


def receive_exact(connection, size):
    result = b''
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EOFError('Terminal WebSocket closed')
        result += chunk
    return result


def receive_frame(connection):
    first, second = receive_exact(connection, 2)
    size = second & 0x7f
    if size == 126:
        size = struct.unpack('!H', receive_exact(connection, 2))[0]
    elif size == 127:
        size = struct.unpack('!Q', receive_exact(connection, 8))[0]
    if size > 1024 * 1024 or second & 0x80:
        raise ValueError('Unexpected terminal frame')
    return first & 0xf, receive_exact(connection, size)


@unittest.skipUnless(sys.platform.startswith('freebsd'), 'Requires bundled FreeBSD ttyd and PTY runtime')
class NativeTerminalTests(unittest.TestCase):
    def test_base_path_serves_terminal_and_websocket_reads_and_writes_real_pty(self):
        major = os.uname().release.split('.')[0]
        vendor = PACKAGE / ('vendor/freebsd' + major + '-amd64')
        self.assertTrue(vendor.is_dir(), 'The bundled runtime for this FreeBSD version is absent')
        with tempfile.TemporaryDirectory(prefix='ttyd-pty-test-') as directory:
            root = Path(directory)
            for dependency in ('libuv', 'libwebsockets', 'ttyd'):
                subprocess.run(['tar', '-xf', str(vendor / (dependency + '.pkg')), '-C', str(root)],
                               check=True, capture_output=True, timeout=10)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            environment = dict(os.environ, LD_LIBRARY_PATH=str(root / 'usr/local/lib') + ':/usr/local/lib')
            log = root / 'terminal.log'
            base = f'http://127.0.0.1:{port}/native-terminal'
            with log.open('w') as stream:
                server = subprocess.Popen([str(root / 'usr/local/bin/ttyd'), '-i', '127.0.0.1',
                                           '-p', str(port), '-b', '/native-terminal', '-W',
                                           'sh', '-c', 'printf "SENTINEL_PTY_READY\\n"; IFS= read -r line; printf "SENTINEL_PTY_REPLY:%s\\n" "$line"'],
                                          stdout=stream, stderr=subprocess.STDOUT, cwd=root, env=environment)
                try:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        self.assertIsNone(server.poll(), log.read_text())
                        try:
                            with urllib.request.urlopen(base + '/', timeout=0.2) as response:
                                self.assertEqual(200, response.status)
                                self.assertIn(b'<html', response.read().lower())
                            break
                        except OSError:
                            time.sleep(0.05)
                    with urllib.request.urlopen(base + '/token', timeout=2) as response:
                        token = json.load(response).get('token', '')
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
                        key = base64.b64encode(os.urandom(16)).decode()
                        request = (f'GET /native-terminal/ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                                   'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                                   f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
                                   'Sec-WebSocket-Protocol: tty\r\n\r\n')
                        connection.sendall(request.encode())
                        headers = b''
                        while not headers.endswith(b'\r\n\r\n') and len(headers) < 8192:
                            headers += receive_exact(connection, 1)
                        self.assertIn(b'101 Switching Protocols', headers)
                        send_frame(connection, json.dumps({'AuthToken': token, 'columns': 80, 'rows': 24}).encode(), 1)
                        output = b''
                        deadline = time.monotonic() + 5
                        while b'SENTINEL_PTY_READY' not in output and time.monotonic() < deadline:
                            opcode, payload = receive_frame(connection)
                            if opcode == 9:
                                send_frame(connection, payload, 10)
                            elif payload.startswith(b'0'):
                                output += payload[1:]
                        self.assertIn(b'SENTINEL_PTY_READY', output)
                        send_frame(connection, b'0native-input\r')
                        deadline = time.monotonic() + 5
                        while b'SENTINEL_PTY_REPLY:native-input' not in output and time.monotonic() < deadline:
                            opcode, payload = receive_frame(connection)
                            if opcode == 9:
                                send_frame(connection, payload, 10)
                            elif payload.startswith(b'0'):
                                output += payload[1:]
                        self.assertIn(b'SENTINEL_PTY_REPLY:native-input', output)
                finally:
                    if server.poll() is None:
                        server.terminate()
                    server.wait(timeout=10)
