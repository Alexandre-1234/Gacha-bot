from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: str
    user_id: int


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def list_processes() -> List[ProcessInfo]:
    entries: List[ProcessInfo] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        status_path = f"/proc/{pid}/status"
        cmdline_path = f"/proc/{pid}/cmdline"
        comm_path = f"/proc/{pid}/comm"

        if not os.path.exists(status_path):
            continue

        try:
            st = os.stat(f"/proc/{pid}")
            uid = st.st_uid
        except Exception:
            uid = -1

        cmdline_raw = _read_text(cmdline_path)
        cmdline = cmdline_raw.replace("\x00", " ").strip()
        comm = _read_text(comm_path).strip()
        name = comm or (cmdline.split(" ")[0] if cmdline else str(pid))

        entries.append(ProcessInfo(pid=pid, name=name, cmdline=cmdline, user_id=uid))
    return sorted(entries, key=lambda p: p.pid)
