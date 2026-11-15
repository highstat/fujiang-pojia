#!/usr/bin/env python3
"""Patch a Mach-O boolean return in place.

Usage:
    python3 patch-macho-bool.py <macho> <offset> --output OUT [--true|--false]

Finds the "mov w0, #0 ; ret" or "mov w0, #1 ; ret" sequence at the given file
offset and flips it, or writes the requested value. Also handles the x86_64
form "mov al, 1 ; ret".

The offset is a file offset. Use vaddr-to-offset.py to convert an address from
a disassembler.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ARM64_FALSE = bytes.fromhex("00008052c0035fd6")   # mov w0, #0 ; ret
ARM64_TRUE = bytes.fromhex("20008052c0035fd6")    # mov w0, #1 ; ret
X86_TRUE = bytes.fromhex("b001c3")                # mov al, 1 ; ret
X86_FALSE = bytes.fromhex("b000c3")               # mov al, 0 ; ret


def patch(data: bytearray, offset: int, want_true: bool) -> str:
    arm64_target = ARM64_TRUE if want_true else ARM64_FALSE
    x86_target = X86_TRUE if want_true else X86_FALSE

    current = bytes(data[offset:offset + 8])
    if current[:8] == ARM64_FALSE or current[:8] == ARM64_TRUE:
        data[offset:offset + 8] = arm64_target
        return f"arm64 mov w0, #{1 if want_true else 0} ; ret"

    if current[:3] == X86_FALSE or current[:3] == X86_TRUE:
        data[offset:offset + 3] = x86_target
        return f"x86 mov al, {1 if want_true else 0} ; ret"

    raise SystemExit(
        f"no known boolean-return sequence at 0x{offset:x}: {current.hex(' ')}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("macho", type=Path)
    parser.add_argument("offset", type=lambda value: int(value, 0))
    parser.add_argument("--true", dest="want_true", action="store_true", default=True)
    parser.add_argument("--false", dest="want_true", action="store_false")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    data = bytearray(args.macho.read_bytes())
    if args.offset < 0 or args.offset + 3 > len(data):
        print("offset is past the end of the file", file=sys.stderr)
        return 1

    print(f"before: {data[args.offset:args.offset + 8].hex(' ')}")
    description = patch(data, args.offset, args.want_true)
    print(f"after:  {data[args.offset:args.offset + 8].hex(' ')}  ({description})")

    output = args.output
    if output is None or output.resolve() == args.macho.resolve() or output.exists() or output.is_symlink():
        print('--output must be a new path, different from the original', file=sys.stderr)
        return 1
    with output.open("xb") as stream:
        stream.write(bytes(data))
    output.chmod(args.macho.stat().st_mode & 0o777)
    print(f"wrote {output} — re-sign the bundle before launching")
    return 0


if __name__ == "__main__":
    sys.exit(main())
