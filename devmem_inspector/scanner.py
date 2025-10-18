from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from .maps import MemoryMap, parse_maps
from .mem import read_process_memory


@dataclass
class ScanResult:
    address: int


_SUPPORTED_TYPES = {
    "i8": (1, "<b"),
    "u8": (1, "<B"),
    "i16": (2, "<h"),
    "u16": (2, "<H"),
    "i32": (4, "<i"),
    "u32": (4, "<I"),
    "i64": (8, "<q"),
    "u64": (8, "<Q"),
    "f32": (4, "<f"),
    "f64": (8, "<d"),
}


def _ensure_session_dir() -> str:
    base = os.path.join("/tmp", "devmem_inspector")
    os.makedirs(base, exist_ok=True)
    return base


def _session_path(pid: int, session: str) -> str:
    base = _ensure_session_dir()
    return os.path.join(base, f"scan_{pid}_{session}.json")


def _pack_value(value: str, value_type: str) -> bytes:
    if value_type not in _SUPPORTED_TYPES:
        raise ValueError(f"Unsupported type: {value_type}")
    _, fmt = _SUPPORTED_TYPES[value_type]
    if value_type.startswith("f"):
        v = float(value)
    else:
        v = int(value, 0) if isinstance(value, str) else int(value)
    return struct.pack(fmt, v)


def _iter_readable_maps(pid: int) -> Iterable[MemoryMap]:
    for m in parse_maps(pid):
        if not m.is_readable:
            continue
        # Skip some special mappings that frequently fail
        if m.pathname in {"[vsyscall]", "[vvar]", "[vdso]"}:
            continue
        yield m


def scan_values(pid: int, value: str, value_type: str, session: str, chunk_size: int = 1024 * 1024) -> List[ScanResult]:
    needle = _pack_value(value, value_type)
    size = len(needle)
    results: List[ScanResult] = []

    for m in _iter_readable_maps(pid):
        region_size = m.size
        base = m.start
        offset = 0
        while offset < region_size:
            to_read = min(chunk_size, region_size - offset)
            try:
                data = read_process_memory(pid, base + offset, to_read)
            except Exception:
                offset += to_read
                continue
            idx = 0
            while True:
                idx = data.find(needle, idx)
                if idx == -1:
                    break
                results.append(ScanResult(address=base + offset + idx))
                idx += 1
            offset += to_read

    # Save session
    path = _session_path(pid, session)
    payload = {
        "pid": pid,
        "session": session,
        "type": value_type,
        "addresses": [r.address for r in results],
        "timestamp": time.time(),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)

    return results


def rescan_values(pid: int, value: str, value_type: str, session: str) -> List[ScanResult]:
    path = _session_path(pid, session)
    if not os.path.exists(path):
        raise FileNotFoundError("No previous scan session found")
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if payload.get("type") != value_type or payload.get("pid") != pid:
        raise ValueError("Session PID/type mismatch")

    needle = _pack_value(value, value_type)
    size = len(needle)

    filtered: List[ScanResult] = []
    for addr in payload.get("addresses", []):
        try:
            data = read_process_memory(pid, int(addr), size)
        except Exception:
            continue
        if data == needle:
            filtered.append(ScanResult(address=int(addr)))

    # Save updated
    payload["addresses"] = [r.address for r in filtered]
    payload["timestamp"] = time.time()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)

    return filtered
