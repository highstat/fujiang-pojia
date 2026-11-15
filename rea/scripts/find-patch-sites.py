#!/usr/bin/env python3
"""Locate conditional branches and other patch candidates in a binary.

Usage:
    python3 find-patch-sites.py <binary> [--kind jcc|jmp|call] [--arch auto|x86|arm64]

Finds the byte patterns that a licence patch usually targets and prints them
with the surrounding context so the intended branch can be confirmed before
it is modified.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

JCC_SHORT_X86 = {0x70 + i: name for i, name in enumerate([
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
])}
JCC_NEAR_X86 = {0x80 + i: name for i, name in enumerate([
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
])}

INVERT_SHORT = {
    "je": "jne", "jne": "je", "jb": "jae", "jae": "jb",
    "jbe": "ja", "ja": "jbe", "jl": "jge", "jge": "jl",
    "jle": "jg", "jg": "jle", "js": "jns", "jns": "js",
    "jp": "jnp", "jnp": "jp", "jo": "jno", "jno": "jo",
}
INVERT_NEAR = {
    "je": "jne", "jne": "je", "jb": "jae", "jae": "jb",
    "jbe": "ja", "ja": "jbe", "jl": "jge", "jge": "jl",
    "jle": "jg", "jg": "jle", "js": "jns", "jns": "js",
    "jp": "jnp", "jnp": "jp", "jo": "jno", "jno": "jo",
}

ARM64_COND = {
    0: "eq", 1: "ne", 2: "hs", 3: "lo", 4: "mi", 5: "pl",
    6: "vs", 7: "vc", 8: "hi", 9: "ls", 10: "ge", 11: "lt",
    12: "gt", 13: "le", 14: "al", 15: "nv",
}
ARM64_INVERT = {
    "eq": "ne", "ne": "eq", "hs": "lo", "lo": "hs",
    "mi": "pl", "pl": "mi", "vs": "vc", "vc": "vs",
    "hi": "ls", "ls": "hi", "ge": "lt", "lt": "ge",
    "gt": "le", "le": "gt",
}


def detect_arch(data: bytes) -> str:
    if data[:2] == b"MZ":
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        machine = struct.unpack_from("<H", data, pe + 4)[0]
        if machine not in (0x8664, 0x14C, 0xAA64):
            raise ValueError("unsupported PE architecture")
        return "arm64" if machine == 0xAA64 else "x86"
    if data[:4] == b"\x7fELF":
        endian = "<" if data[5] == 1 else ">"
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        if machine not in (3, 0x3E, 0xB7):
            raise ValueError("unsupported ELF architecture; ARM32 is not ARM64")
        return "arm64" if machine == 0xB7 else "x86"
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (0xFEEDFACF, 0xCFFAEDFE, 0xFEEDFACE, 0xCEFAEDFE):
        endian = "<" if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
        cpu = struct.unpack_from(endian + "I", data, 4)[0]
        if cpu not in (7, 0x01000007, 0x0100000C):
            raise ValueError("unsupported Mach-O CPU type")
        return "arm64" if cpu == 0x0100000C else "x86"
    if magic in (0xBEBAFECA, 0xCAFEBABE):
        architecture = fat_slices(data)[0][0]
        if architecture not in ("x86", "x86_64", "arm64"):
            raise ValueError("unsupported first universal-binary slice")
        return "arm64" if architecture == "arm64" else "x86"
    raise ValueError("unknown architecture; select --arch for raw byte input")


def fat_slices(data: bytes) -> list[tuple[str, int, int]]:
    """Return [(architecture, file_offset, size)] for a fat Mach-O."""
    # The fat magic is stored in the file's own byte order.
    if data[:4] == b"\xca\xfe\xba\xbe":
        endian = ">"
    elif data[:4] == b"\xbe\xba\xfe\xca":
        endian = "<"
    else:
        return []
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if not count or count > (len(data) - 8) // 20:
        raise ValueError("invalid universal-binary architecture table")
    names = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}
    slices = []
    for index in range(count):
        cputype, _subtype, offset, size = struct.unpack_from(
            endian + "IIII", data, 8 + index * 20
        )
        if offset + size > len(data):
            raise ValueError("universal-binary slice extends beyond the file")
        slices.append((names.get(cputype, hex(cputype)), offset, size))
    return slices


def find_x86(data: bytes, kind: str) -> list[dict]:
    sites = []
    for index in range(len(data)):
        opcode = data[index]
        if kind in ("jcc", "any") and opcode in JCC_SHORT_X86 and index + 2 <= len(data):
            displacement = struct.unpack_from("<b", data, index + 1)[0]
            sites.append({
                "offset": index,
                "bytes": data[index:index + 2],
                "label": JCC_SHORT_X86[opcode],
                "target": index + 2 + displacement,
                "invert": INVERT_SHORT.get(JCC_SHORT_X86[opcode]),
            })
        elif kind in ("jcc", "any") and index + 6 <= len(data) and opcode == 0x0F and data[index + 1] in JCC_NEAR_X86:
            displacement = struct.unpack_from("<i", data, index + 2)[0]
            sites.append({
                "offset": index,
                "bytes": data[index:index + 6],
                "label": JCC_NEAR_X86[data[index + 1]],
                "target": index + 6 + displacement,
                "invert": INVERT_NEAR.get(JCC_NEAR_X86[data[index + 1]]),
            })
        elif kind in ("jmp", "any") and opcode == 0xE9 and index + 5 <= len(data):
            displacement = struct.unpack_from("<i", data, index + 1)[0]
            sites.append({
                "offset": index,
                "bytes": data[index:index + 5],
                "label": "jmp rel32",
                "target": index + 5 + displacement,
                "invert": None,
            })
        elif kind in ("call", "any") and opcode == 0xE8 and index + 5 <= len(data):
            displacement = struct.unpack_from("<i", data, index + 1)[0]
            sites.append({
                "offset": index,
                "bytes": data[index:index + 5],
                "label": "call rel32",
                "target": index + 5 + displacement,
                "invert": None,
            })
    return sites


def find_arm64(data: bytes, kind: str) -> list[dict]:
    sites = []
    for index in range(0, len(data) - 3, 4):
        word = struct.unpack_from("<I", data, index)[0]
        top = word >> 26
        if kind in ("jcc", "any") and word & 0xFF000010 == 0x54000000:
            condition = word & 0xF
            imm19 = (word >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            sites.append({
                "offset": index,
                "bytes": data[index:index + 4],
                "label": f"b.{ARM64_COND[condition]}",
                "target": index + imm19 * 4,
                "invert": ARM64_INVERT.get(ARM64_COND[condition]),
            })
        elif kind in ("jmp", "any") and top == 0b000101:
            imm26 = word & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            sites.append({
                "offset": index,
                "bytes": data[index:index + 4],
                "label": "b",
                "target": index + imm26 * 4,
                "invert": None,
            })
        elif kind in ("call", "any") and top == 0b100101:
            imm26 = word & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            sites.append({
                "offset": index,
                "bytes": data[index:index + 4],
                "label": "bl",
                "target": index + imm26 * 4,
                "invert": None,
            })
    return sites


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--kind", default="any",
        choices=["any", "jcc", "jmp", "call"],
        help="branch kind to report",
    )
    parser.add_argument("--arch", default="auto", choices=["auto", "x86", "arm64"])
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")

    data = args.binary.read_bytes()
    arch = detect_arch(data) if args.arch == "auto" else args.arch

    slices = fat_slices(data)
    slice_offset = 0
    if slices:
        print(f"{args.binary}: fat Mach-O with {len(slices)} slice(s)")
        for architecture, offset, size in slices:
            print(f"  slice: {architecture} at file 0x{offset:x}, {size} bytes")
        # Analyse the first slice only; offsets are relative to that slice.
        architecture, slice_offset, slice_size = slices[0]
        print(f"  analysing the {architecture} slice")
        data = data[slice_offset:slice_offset + slice_size]
        arch = "arm64" if architecture == "arm64" else "x86"
    else:
        print(f"{args.binary}: architecture {arch}, size {len(data)} bytes")

    sites = find_arm64(data, args.kind) if arch == "arm64" else find_x86(data, args.kind)

    for site in sites[: args.limit]:
        invert = f"  invert -> {site['invert']}" if site["invert"] else ""
        print(
            f"  0x{site['offset'] + slice_offset:08x}  {site['bytes'].hex(' '):<20}"
            f"{site['label']:<10} file-relative target 0x{site['target'] + slice_offset:x}{invert}"
        )
    if len(sites) > args.limit:
        print(f"  ... {len(sites) - args.limit} more")
    print(f"{len(sites)} raw-byte candidates; confirm instruction boundaries and executable regions before patching")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, IndexError, struct.error) as error:
        print(f"cannot inspect: {error}", file=sys.stderr)
        sys.exit(1)
