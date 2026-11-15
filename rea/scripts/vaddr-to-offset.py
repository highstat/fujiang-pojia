#!/usr/bin/env python3
"""Translate virtual addresses to file offsets across PE, ELF and Mach-O.

Usage:
    python3 vaddr-to-offset.py <binary> <virtual-address> [virtual-address ...]

Uses the standard library only. PE input defaults to preferred-image virtual
addresses; pass --rva for RVAs. Universal Mach-O input selects slice 0 unless
--slice INDEX is supplied. Runtime ASLR addresses must first be unslid.
"""

from __future__ import annotations

import struct
import argparse
import sys
from pathlib import Path

PE = 0x4550                    # "PE\0\0"
ELF = 0x464C457F               # "\x7fELF"
MACHO_MAGICS = {
    0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE,
}
FAT_MAGICS = {0xBEBAFECA, 0xCAFEBABE}

CPU_NAMES = {
    7: "x86", 0x01000007: "x86_64",
    12: "arm", 0x0100000C: "arm64",
}


def fat_slices(data: bytes) -> list[tuple[str, int, int]]:
    """Return [(architecture, file_offset, size)] for a fat Mach-O."""
    # The fat magic is stored in the file's own byte order:
    #   ca fe ba be -> big-endian fields, be ba fe ca -> little-endian fields.
    if data[:4] == b"\xca\xfe\xba\xbe":
        endian = ">"
    elif data[:4] == b"\xbe\xba\xfe\xca":
        endian = "<"
    else:
        return []

    count = struct.unpack_from(endian + "I", data, 4)[0]
    if not count or count > (len(data) - 8) // 20:
        raise ValueError("invalid universal-binary architecture table")
    slices = []
    for index in range(count):
        base = 8 + index * 20
        cputype, _subtype, offset, size = struct.unpack_from(
            endian + "IIII", data, base
        )
        if offset + size > len(data):
            raise ValueError("universal-binary slice extends beyond the file")
        slices.append((CPU_NAMES.get(cputype, hex(cputype)), offset, size))
    return slices


def parse_pe(data: bytes, address: int, address_is_rva: bool = False) -> int | None:
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    coff = pe_offset + 4
    number_of_sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:            # PE32+
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    else:
        raise ValueError("unsupported PE optional header")
    rva = address if address_is_rva else address - image_base
    if rva < 0:
        return None
    headers_size = struct.unpack_from("<I", data, optional + 60)[0]

    sections = optional + optional_size
    for index in range(number_of_sections):
        base = sections + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, base + 8
        )
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            delta = rva - virtual_address
            return raw_pointer + delta if delta < raw_size and raw_pointer + delta < len(data) else None

    # Not in a section: fall back to the header mapping, where RVA == file offset.
    if rva < min(headers_size, len(data)):
        return rva
    return None


def parse_elf(data: bytes, vaddr: int) -> int | None:
    if data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("unsupported ELF class or byte order")
    endian = "<" if data[5] == 1 else ">"
    is_64 = data[4] == 2
    if is_64:
        phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
        phentsize = struct.unpack_from(endian + "H", data, 0x36)[0]
        phnum = struct.unpack_from(endian + "H", data, 0x38)[0]
    else:
        phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
        phentsize = struct.unpack_from(endian + "H", data, 0x2A)[0]
        phnum = struct.unpack_from(endian + "H", data, 0x2C)[0]
    if phentsize < (56 if is_64 else 32) or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid ELF program-header table")

    for index in range(phnum):
        base = phoff + index * phentsize
        if is_64:
            p_type = struct.unpack_from(endian + "I", data, base)[0]
            p_offset = struct.unpack_from(endian + "Q", data, base + 8)[0]
            p_vaddr = struct.unpack_from(endian + "Q", data, base + 16)[0]
            p_filesz = struct.unpack_from(endian + "Q", data, base + 32)[0]
            p_memsz = struct.unpack_from(endian + "Q", data, base + 40)[0]
        else:
            p_type = struct.unpack_from(endian + "I", data, base)[0]
            p_offset = struct.unpack_from(endian + "I", data, base + 4)[0]
            p_vaddr = struct.unpack_from(endian + "I", data, base + 8)[0]
            p_filesz = struct.unpack_from(endian + "I", data, base + 16)[0]
            p_memsz = struct.unpack_from(endian + "I", data, base + 20)[0]
        if p_type != 1:                     # PT_LOAD
            continue
        if p_vaddr <= vaddr < p_vaddr + p_memsz:
            delta = vaddr - p_vaddr
            if delta >= p_filesz:
                return None                # in .bss: no file content
            return p_offset + delta if p_offset + delta < len(data) else None
    return None


def parse_macho(data: bytes, vaddr: int) -> int | None:
    # The Mach-O magic is stored in a fixed byte order:
    #   fe ed fa ce  MH_MAGIC      32-bit, big-endian fields
    #   ce fa ed fe  MH_CIGAM      32-bit, little-endian fields
    #   fe ed fa cf  MH_MAGIC_64   64-bit, big-endian fields
    #   cf fa ed fe  MH_CIGAM_64   64-bit, little-endian fields
    header = data[:4]
    if header == b"\xfe\xed\xfa\xce":
        endian, is_64 = ">", False
    elif header == b"\xce\xfa\xed\xfe":
        endian, is_64 = "<", False
    elif header == b"\xfe\xed\xfa\xcf":
        endian, is_64 = ">", True
    elif header == b"\xcf\xfa\xed\xfe":
        endian, is_64 = "<", True
    else:
        return None

    ncmds = struct.unpack_from(endian + "I", data, 16)[0]
    offset = 32 if is_64 else 28

    segments: list[tuple[int, int, int, int]] = []
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise ValueError("truncated Mach-O command table")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise ValueError("invalid Mach-O command size")
        if cmd in (0x19, 0x01) and cmdsize < (72 if cmd == 0x19 else 56):
            raise ValueError("truncated Mach-O segment")
        if cmd == 0x19:                    # LC_SEGMENT_64
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                endian + "QQQQ", data, offset + 24
            )
            segments.append((vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x01:                  # LC_SEGMENT
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                endian + "IIII", data, offset + 24
            )
            segments.append((vmaddr, vmsize, fileoff, filesize))
        offset += cmdsize

    for vmaddr, vmsize, fileoff, filesize in segments:
        if vmaddr <= vaddr < vmaddr + vmsize:
            delta = vaddr - vmaddr
            if delta >= filesize:
                return None
            return fileoff + delta if fileoff + delta < len(data) else None
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("addresses", nargs="+")
    parser.add_argument("--rva", action="store_true", help="interpret PE addresses as RVAs rather than preferred-image VAs")
    parser.add_argument("--slice", type=int, default=0, help="universal Mach-O slice index (default 0; inspect the printed identity)")
    args = parser.parse_args()
    path = args.binary
    data = path.read_bytes()

    if data[:2] == b"MZ":
        kind = "PE"
    elif data[:4] == b"\x7fELF":
        kind = "ELF"
    else:
        magic = struct.unpack_from("<I", data, 0)[0]
        kind = "Mach-O fat" if magic in FAT_MAGICS else (
            "Mach-O" if magic in MACHO_MAGICS else "unknown"
        )

    print(f"{path}: format {kind}, size {len(data)} bytes")

    if kind == "Mach-O fat":
        slices = fat_slices(data)
        for architecture, offset, size in slices:
            print(f"  slice: {architecture} at file 0x{offset:x}, {size} bytes")
        if not slices:
            print("  no slices found", file=sys.stderr)
            return 1
        # Use the first slice as the analysis target; addresses are per-slice.
        if not 0 <= args.slice < len(slices):
            raise ValueError("universal-binary slice index is out of range")
        architecture, slice_offset, slice_size = slices[args.slice]
        print(f"  using the {architecture} slice")
        data = data[slice_offset:slice_offset + slice_size]
        base = slice_offset
        kind = "Mach-O"
    else:
        base = 0

    failures = 0
    for argument in args.addresses:
        vaddr = int(argument, 0)
        if vaddr < 0:
            raise ValueError("addresses must be non-negative")
        if kind == "PE":
            offset = parse_pe(data, vaddr, args.rva)
        elif kind == "ELF":
            offset = parse_elf(data, vaddr)
        elif kind == "Mach-O":
            offset = parse_macho(data, vaddr)
        else:
            print(f"  0x{vaddr:x}: unsupported format", file=sys.stderr)
            failures += 1
            continue

        if offset is None:
            print(f"  0x{vaddr:x}: not mapped to a file offset")
            failures += 1
        else:
            window = data[offset:offset + 16]
            absolute = base + offset
            print(f"  0x{vaddr:x} -> file 0x{absolute:x}  {window.hex(' ')}")

    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, IndexError, struct.error) as error:
        print(f"cannot map address: {error}", file=sys.stderr)
        sys.exit(1)
