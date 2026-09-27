"""Ask the test router DNS questions from a LAN client jail on the far end of an epair.

The router cannot send a query into its own captured interface, so run.sh
starts this in a second VNET jail whose epair end holds the client addresses.
case.py, inside the router jail, drops a request file into the directory both
jails share and waits for the answer file this writes back.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import time


ROOT = Path('/root/dns-client')
REQUESTS = ROOT / 'requests'
ANSWERS = ROOT / 'answers'
# The harness removes this jail when it finishes; a helper left behind by an
# interrupted run gives up on its own.
LIFETIME = 3600


def encode(name):
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.rstrip('.').split('.')) + b'\x00'


def skip_name(reply, offset):
    """Offset after the possibly compressed name that starts at offset."""
    while True:
        length = reply[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def receive(client, size):
    data = b''
    while len(data) < size:
        part = client.recv(size - len(data))
        if not part:
            raise ConnectionError('the server closed the connection')
        data += part
    return data


def query(source, server, name, transport, timeout, port=53):
    """The response code and IPv4 addresses the server gives for name, asked from source."""
    packet = struct.pack('!HHHHHH', secrets.randbits(16), 0x0100, 1, 0, 0, 0) + encode(name) + struct.pack('!HH', 1, 1)
    kind = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as client:
        client.settimeout(timeout)
        client.bind((source, 0))
        # Connected, so only a reply from the address asked is accepted.
        client.connect((server, port))
        if transport == 'udp':
            client.send(packet)
            reply = client.recv(4096)
        else:
            client.sendall(struct.pack('!H', len(packet)) + packet)
            reply = receive(client, struct.unpack('!H', receive(client, 2))[0])
    if len(reply) < 12 or reply[:2] != packet[:2] or not reply[2] & 0x80:
        raise ValueError('the reply does not answer the query')
    count = struct.unpack('!H', reply[6:8])[0]
    offset = skip_name(reply, 12) + 4
    addresses = []
    for _ in range(count):
        offset = skip_name(reply, offset)
        kind, _, _, length = struct.unpack('!HHIH', reply[offset:offset + 10])
        offset += 10
        if kind == 1 and length == 4:
            addresses.append(socket.inet_ntoa(reply[offset:offset + 4]))
        offset += length
    return {'rcode': reply[3] & 0x0F, 'addresses': addresses}


def answer(path):
    try:
        request = json.loads(path.read_text())
        path.unlink()
    except (OSError, ValueError):
        return
    try:
        result = query(request['source'], request['server'], request['name'],
                       request['transport'], float(request['timeout']), int(request.get('port', 53)))
    except (OSError, ValueError, KeyError, IndexError, TypeError, struct.error) as error:
        result = {'error': type(error).__name__ + ': ' + str(error)}
    try:
        ANSWERS.mkdir(parents=True, exist_ok=True)
        temporary = ANSWERS / ('.' + path.stem)
        temporary.write_text(json.dumps(result))
        os.replace(temporary, ANSWERS / path.name)
    except OSError:
        pass


def main():
    deadline = time.monotonic() + LIFETIME
    while time.monotonic() < deadline:
        try:
            pending = sorted(REQUESTS.glob('*.json'))
        except OSError:
            pending = []
        for path in pending:
            answer(path)
        time.sleep(0.05)


if __name__ == '__main__':
    sys.exit(main())
