from __future__ import annotations

import errno
import fcntl
import os
import ctypes
import ctypes.util
import signal
import time
from typing import Optional

from .maps import MemoryMap, parse_maps


class MemoryReadError(Exception):
    pass


class PtraceError(Exception):
    pass


_libc_path = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_path, use_errno=True)


class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


# ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def _check_errno(result: int, func_name: str) -> None:
    if result == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e) + f" ({func_name})")


def _process_vm_readv(
    pid: int, remote_address: int, size: int, max_chunk_size: int = 1024 * 1024
) -> bytes:
    # Prepare iovecs
    process_vm_readv = getattr(_libc, "process_vm_readv", None)
    if process_vm_readv is None:
        raise OSError(errno.ENOSYS, "process_vm_readv not available")

    process_vm_readv.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(IOVec),
        ctypes.c_ulong,
        ctypes.POINTER(IOVec),
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    process_vm_readv.restype = ctypes.c_ssize_t

    remaining = size
    data_chunks: list[bytes] = []
    cursor = 0

    while remaining > 0:
        chunk = min(remaining, max_chunk_size)
        local_buffer = (ctypes.c_char * chunk)()
        local_iov = IOVec(ctypes.cast(local_buffer, ctypes.c_void_p), chunk)
        remote_iov = IOVec(ctypes.c_void_p(remote_address + cursor), chunk)

        nread = process_vm_readv(
            ctypes.c_int(pid),
            ctypes.pointer(local_iov),
            1,
            ctypes.pointer(remote_iov),
            1,
            0,
        )
        if nread < 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e) + " (process_vm_readv)")
        data_chunks.append(bytes(local_buffer[: nread]))
        if nread == 0:
            break
        cursor += nread
        remaining -= nread

    return b"".join(data_chunks)


def _ptrace_attach(pid: int) -> None:
    res = _libc.ptrace(PTRACE_ATTACH, ctypes.c_int(pid), None, None)
    _check_errno(res, "ptrace(PTRACE_ATTACH)")
    # Wait for the process to stop
    while True:
        try:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
            if waited_pid == pid:
                if os.WIFSTOPPED(status):
                    return
        except ChildProcessError:
            break
        time.sleep(0.01)


def _ptrace_detach(pid: int) -> None:
    res = _libc.ptrace(PTRACE_DETACH, ctypes.c_int(pid), None, None)
    _check_errno(res, "ptrace(PTRACE_DETACH)")


def _read_via_proc_mem(pid: int, address: int, size: int) -> bytes:
    _ptrace_attach(pid)
    try:
        mem_path = f"/proc/{pid}/mem"
        fd = os.open(mem_path, os.O_RDONLY)
        try:
            # Ensure O_NONBLOCK off
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
            os.lseek(fd, address, os.SEEK_SET)
            data = os.read(fd, size)
            return data
        finally:
            os.close(fd)
    finally:
        _ptrace_detach(pid)


def read_process_memory(pid: int, address: int, size: int) -> bytes:
    try:
        return _process_vm_readv(pid, address, size)
    except OSError:
        return _read_via_proc_mem(pid, address, size)


def safe_read(pid: int, address: int, size: int) -> bytes:
    maps = parse_maps(pid)
    end_address = address + size
    for m in maps:
        if not m.is_readable:
            continue
        if address >= m.start and end_address <= m.end:
            return read_process_memory(pid, address, size)
    raise MemoryReadError("Requested range not within a readable mapping")
