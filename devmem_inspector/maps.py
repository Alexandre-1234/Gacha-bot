from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MemoryMap:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    pathname: Optional[str]

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def is_readable(self) -> bool:
        return "r" in self.perms


def parse_maps(pid: int) -> List[MemoryMap]:
    maps: List[MemoryMap] = []
    path = f"/proc/{pid}/maps"
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Example line:
            # 55b2b6fe7000-55b2b6fea000 r--p 00000000 103:02 1443382                   /usr/bin/cat
            parts = line.split()
            addr_range, perms, offset, dev, inode = parts[:5]
            pathname = " ".join(parts[5:]) if len(parts) > 5 else None
            start_str, end_str = addr_range.split("-")
            start = int(start_str, 16)
            end = int(end_str, 16)
            maps.append(
                MemoryMap(
                    start=start,
                    end=end,
                    perms=perms,
                    offset=int(offset, 16),
                    dev=dev,
                    inode=int(inode),
                    pathname=pathname if pathname else None,
                )
            )
    return maps
