#!/usr/local/bin/python3
"""Read exact FreeBSD amd64 process metadata without parsing displayed argv."""
import ctypes
import os
import struct


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
        executable = os.fsdecode(kernel_value('kern.proc.pathname', pid).rstrip(b'\0'))
        argv = [os.fsdecode(item) for item in kernel_value('kern.proc.args', pid).rstrip(b'\0').split(b'\0')]
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
