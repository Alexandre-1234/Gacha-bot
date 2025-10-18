from __future__ import annotations

import argparse
import binascii
import os
from typing import List

from .processes import list_processes
from .maps import parse_maps
from .mem import safe_read
from .scanner import scan_values, rescan_values


def _fmt_size(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def cmd_list_procs(_: argparse.Namespace) -> None:
    procs = list_processes()
    uid = os.getuid()
    for p in procs:
        if p.user_id != uid and uid != 0:
            continue
        cmd = p.cmdline or p.name
        print(f"{p.pid:>6}  {p.name:<20}  {cmd}")


def cmd_maps(args: argparse.Namespace) -> None:
    maps = parse_maps(args.pid)
    for m in maps:
        path = m.pathname or ""
        print(f"0x{m.start:016x}-0x{m.end:016x} {m.perms} {path} ({_fmt_size(m.size)})")


def cmd_read(args: argparse.Namespace) -> None:
    addr = int(args.addr, 0)
    data = safe_read(args.pid, addr, args.length)
    if args.hex:
        print(binascii.hexlify(data).decode("ascii"))
    else:
        try:
            print(data.decode("utf-8", errors="replace"))
        except Exception:
            print(data)


def cmd_scan(args: argparse.Namespace) -> None:
    results = scan_values(args.pid, args.value, args.type, session=args.session)
    print(f"Found {len(results)} matches. Session='{args.session}'.")
    for r in results[: min(20, len(results))]:
        print(f"  0x{r.address:016x}")


def cmd_rescan(args: argparse.Namespace) -> None:
    results = rescan_values(args.pid, args.value, args.type, session=args.session)
    print(f"Remaining {len(results)} matches after rescan. Session='{args.session}'.")
    for r in results[: min(20, len(results))]:
        print(f"  0x{r.address:016x}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="devmem-inspector",
        description=(
            "Developer-only memory inspector (read-only). Use on your own processes. "
            "No stealth/evasion."
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list-procs", help="List accessible processes")
    sp.set_defaults(func=cmd_list_procs)

    sp = sub.add_parser("maps", help="Show /proc/<pid>/maps")
    sp.add_argument("--pid", type=int, required=True)
    sp.set_defaults(func=cmd_maps)

    sp = sub.add_parser("read", help="Read memory at address")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--addr", required=True, help="Address (hex like 0x1234 or decimal)")
    sp.add_argument("--length", type=int, required=True, help="Bytes to read")
    sp.add_argument("--hex", action="store_true", help="Print as hex instead of utf-8")
    sp.set_defaults(func=cmd_read)

    sp = sub.add_parser("scan", help="Scan for a value across readable mappings")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--value", required=True, help="Value to search (int or float)")
    sp.add_argument("--type", required=True, choices=[
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"
    ])
    sp.add_argument("--session", required=False, default="default", help="Session name for scan/rescan")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("rescan", help="Rescan previous matches for new value")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--value", required=True, help="New value to match at prior addresses")
    sp.add_argument("--type", required=True, choices=[
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"
    ])
    sp.add_argument("--session", required=False, default="default", help="Session name used in scan")
    sp.set_defaults(func=cmd_rescan)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
