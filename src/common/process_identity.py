#!/usr/local/bin/python3
"""Read exact FreeBSD amd64 process metadata without parsing displayed argv."""
import ctypes
import os
import re
import struct


BIRTH = re.compile(r'^([0-9]+):([0-9]{1,6})$')
BOOT = re.compile(r'^\{\s*sec\s*=\s*([0-9]+),\s*usec\s*=\s*([0-9]+)\s*\}')


def parse_boot(value):
    """Parse a kern.boottime reading into (seconds, microseconds).

    sysctl appends a human-readable date after the structure, so only the
    leading timeval is significant.
    """
    if not isinstance(value, str):
        raise ValueError('A kernel boot time is required.')
    match = BOOT.match(value.strip())
    if match is None:
        match = BIRTH.fullmatch(value.strip())
    if match is None:
        raise ValueError('A kernel boot time is invalid.')
    sec, usec = int(match.group(1)), int(match.group(2))
    if not 0 <= usec < 1000000:
        raise ValueError('A kernel boot time is invalid.')
    return sec, usec


def relative_birth(birth, boot):
    """Return a birth time measured from its boot time, or None.

    FreeBSD moves kern.boottime and every existing process start time by the
    same delta when the wall clock is stepped, so this difference is stable
    within one boot and cannot be confused with a reboot by the clock alone.
    """
    if not isinstance(birth, str) or boot is None:
        return None
    match = BIRTH.fullmatch(birth)
    if match is None:
        return None
    try:
        boot_sec, boot_usec = parse_boot(boot)
    except ValueError:
        return None
    return (int(match.group(1)) - boot_sec) * 1000000 + int(match.group(2)) - boot_usec


def rebase_birth(birth, delta):
    """Move a birth by delta microseconds, keeping the canonical text form."""
    match = BIRTH.fullmatch(birth) if isinstance(birth, str) else None
    if match is None or type(delta) is not int:
        return None
    total = int(match.group(1)) * 1000000 + int(match.group(2)) + delta
    if total < 0:
        return None
    seconds, microseconds = divmod(total, 1000000)
    return str(seconds) + ':' + str(microseconds)


def sysctl_value(name):
    """Read one bounded kernel value without a process selector."""
    if not isinstance(name, str) or not name:
        raise RuntimeError('A kernel value name is required.')
    library = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 8)()
    count = ctypes.c_size_t(8)
    if library.sysctlnametomib(name.encode(), mib, ctypes.byref(count)):
        raise OSError(ctypes.get_errno(), 'Cannot resolve a kernel value.')
    if not 0 < count.value <= len(mib):
        raise RuntimeError('Invalid kernel value selector.')
    size = ctypes.c_size_t()
    if library.sysctl(mib, count, None, ctypes.byref(size), None, 0) or size.value > 4096:
        raise OSError(ctypes.get_errno(), 'Cannot read a bounded kernel value.')
    buffer = ctypes.create_string_buffer(size.value)
    if library.sysctl(mib, count, buffer, ctypes.byref(size), None, 0):
        raise OSError(ctypes.get_errno(), 'The kernel value changed.')
    return buffer.raw[:size.value]


def boot_time():
    """Return the current kern.boottime as (seconds, microseconds), or None."""
    try:
        raw = sysctl_value('kern.boottime')
    except (OSError, AttributeError):
        return None
    if len(raw) != 16:
        return None
    sec, usec = struct.unpack('=qq', raw)
    if sec <= 0 or not 0 <= usec < 1000000:
        return None
    return sec, usec


def boot_token():
    """Return the current boot as a canonical 'seconds:microseconds' token."""
    value = boot_time()
    return None if value is None else str(value[0]) + ':' + str(value[1])


def birth_frame_shift(token):
    """Return (delta, current_token) to move recorded births into the live frame.

    Journals store the boot they were written under; after a wall-clock step
    every recorded start can be moved by the boot difference so the unchanged
    process still compares equal. None means the journal cannot be rebased and
    callers must keep the exact comparison.
    """
    try:
        recorded = parse_boot(token)
    except ValueError:
        return None
    current = boot_time()
    if current is None:
        return None
    delta = (current[0] - recorded[0]) * 1000000 + current[1] - recorded[1]
    return delta, str(current[0]) + ':' + str(current[1])


def kernel_value(name, pid):
    if type(pid) is not int or not 0 < pid < 2147483648:
        raise RuntimeError('Refusing an invalid process PID.')
    library = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 24)()
    count = ctypes.c_size_t(23)
    if library.sysctlnametomib(name.encode(), mib, ctypes.byref(count)):
        raise OSError(ctypes.get_errno(), 'Cannot resolve process metadata.')
    if not 0 < count.value < len(mib):
        raise RuntimeError('Invalid process metadata selector.')
    mib[count.value] = pid
    count.value += 1
    size = ctypes.c_size_t()
    if library.sysctl(mib, count, None, ctypes.byref(size), None, 0) or size.value > 1024 * 1024:
        raise OSError(ctypes.get_errno(), 'Cannot read bounded process metadata.')
    buffer = ctypes.create_string_buffer(size.value)
    if library.sysctl(mib, count, buffer, ctypes.byref(size), None, 0):
        raise OSError(ctypes.get_errno(), 'Process metadata changed.')
    return buffer.raw[:size.value]


def metadata(pid):
    if type(pid) is not int or not 0 < pid < 2147483648:
        raise RuntimeError('Refusing an invalid process PID.')
    # The stable kinfo_proc prefix is shared by FreeBSD 14/15 amd64 sys/user.h.
    # Unknown layouts fail closed instead of guessing a process identity.
    if os.uname().machine != 'amd64' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError('Unsupported process identity ABI.')
    raw = kernel_value('kern.proc.pid', pid)
    if not raw:
        return None
    if len(raw) != 1088 or struct.unpack_from('=i', raw)[0] != 1088:
        raise RuntimeError('Unrecognized process metadata layout.')
    actual, parent = struct.unpack_from('=ii', raw, 72)
    uid, = struct.unpack_from('=I', raw, 168)
    sec, usec = struct.unpack_from('=qq', raw, 336)
    state = raw[388]
    if actual != pid or parent < 0 or sec <= 0 or not 0 <= usec < 1000000 or not 1 <= state <= 7:
        raise RuntimeError('Invalid process identity metadata.')
    if state == 5:
        return None
    return {'pid': pid, 'ppid': parent, 'uid': uid, 'birth': str(sec) + ':' + str(usec), 'stopped': state == 4}


def process(pid):
    if type(pid) is not int or not 0 < pid < 2147483648:
        raise RuntimeError('Refusing an invalid process PID.')
    try:
        before = metadata(pid)
        if before is None:
            return None
        try:
            executable = os.fsdecode(kernel_value('kern.proc.pathname', pid).rstrip(b'\0'))
            argv = [os.fsdecode(item) for item in kernel_value('kern.proc.args', pid).rstrip(b'\0').split(b'\0')]
        except OSError as error:
            if error.errno not in (2, 3):
                raise RuntimeError('Cannot establish process ownership.') from error
            # kern.proc.pid already proved this process was alive. A missing
            # pathname or argument vector means its executable was removed or
            # replaced in place (a package upgrade), never that it exited.
            if metadata(pid) is None:
                return None
            raise RuntimeError('The executable of live process ' + str(pid) + ' is unavailable.') from error
        after = metadata(pid)
        if before != after or not executable or not argv or not argv[0]:
            return None
        return {**before, 'executable': executable, 'argv': argv}
    except ProcessLookupError:
        return None
    except OSError as error:
        # ESRCH/ENOENT means the process disappeared; other lookup failures
        # cannot authorize changing a PID file or importing settings.
        if error.errno in (2, 3):
            return None
        raise RuntimeError('Cannot establish process ownership.') from error
