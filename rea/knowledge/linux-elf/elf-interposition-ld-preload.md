---
id: "elf-interposition-ld-preload"
title: "ELF interposition with LD_PRELOAD"
domain: "linux-elf"
kind: "technique"
platforms: "linux"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "gcc,readelf,objdump,strace,ltrace"
verified: false
updated: "2026-11-15"
summary: "Explains how the dynamic linker resolves a symbol to the first definition in the LD_PRELOAD list, how symbol versioning and RTLD_LOCAL change whether a preloaded definition actually wins, and how to prove the interposition with LD_DEBUG=bindings and readelf --dyn-syms."
---

## Summary

Interposition is the cheapest way to observe or alter the behaviour of a running Linux program
without editing it: define a symbol with the same name in a shared object, preload that object, and
the dynamic linker binds every later reference to the preloaded definition. This entry covers the
lookup order, the rules that make an interposition fail (symbol versioning, `RTLD_LOCAL`,
secure-execution mode), and the commands that prove the binding actually changed. Reach for it when
a target refuses to start, needs a clock rolled back, or has a licence check that consults a
function that can be shadowed.

## Recognition

- The target is dynamically linked: `readelf -d ./target` shows a `NEEDED` entry for `libc.so.6`.
- The target is not setuid: `stat -c '%A %U' ./target` shows no `s` in the mode bits, and
  `getauxval(AT_SECURE)` returns `0`.
- `LD_PRELOAD=/tmp/x.so ./target` produces no diagnostic but the behaviour is unchanged, and
  `LD_DEBUG=bindings` shows no binding to `/tmp/x.so`.
- `LD_DEBUG=libs ./target` prints the search list, with the preloaded object listed first.
- `readelf --dyn-syms ./target | grep strcmp` shows the reference resolves through the PLT with a
  `GLIBC_2.2.5` version tag.
- A statically linked binary (`file` says `statically linked`) cannot be interposed at all.

## Method

### 1. Confirm the target is a candidate

```bash
cd /path/to/work
file ./target
readelf -h ./target | grep Type
readelf -d ./target | grep NEEDED
```

Expected: `Type: DYN` (PIE) or `EXEC`, and a `NEEDED` entry for `libc.so.6`. A `Type: EXEC` with no
`INTERP` segment is static:

```bash
readelf -l ./target | grep -A1 INTERP
```

### 2. Write the interposer

```c
// fake.c — interpose strcmp and report every comparison
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

int strcmp(const char *a, const char *b) {
    static int enabled = 1;
    if (enabled) {
        fprintf(stderr, "[fake] strcmp(\"%s\", \"%s\")\n", a, b);
    }
    return 0;   /* every string compares equal */
}
```

`strcmp` is declared in `<string.h>`, so the definition must match the prototype exactly or the
compiler emits a conflicting-type error.

### 3. Build it

```bash
cd /path/to/work
gcc -shared -fPIC -o fake.so fake.c -ldl
```

`-fPIC` is mandatory for a shared object, `-shared` produces a `DYN` object, `-ldl` is harmless on
modern glibc (where `libdl` is merged into `libc`) but keeps the command portable to glibc < 2.34.

Confirm the export:

```bash
readelf --dyn-syms fake.so | grep -E ' strcmp'
```

Expected:

```text
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  16 strcmp
```

The `GLOBAL` binding and `DEFAULT` visibility are what make the definition eligible to interpose.
A `LOCAL` symbol or one with `HIDDEN` visibility is invisible to the dynamic linker.

### 4. Run it

```bash
cd /path/to/work
LD_PRELOAD=$PWD/fake.so ./target
```

For a setuid-style target the variable is silently dropped; see the secure-execution section.

### 5. Prove the interposition with LD_DEBUG

```bash
cd /path/to/work
LD_DEBUG=bindings LD_PRELOAD=$PWD/fake.so ./target 2>&1 | grep -E "symbol \`strcmp'"
```

Expected:

```text
     4126:     binding file ./target [0] to /path/to/work/fake.so [0]: normal symbol `strcmp'
```

Without the preload the same line reads:

```text
     4126:     binding file ./target [0] to /lib/x86_64-linux-gnu/libc.so.6 [0]: normal symbol `strcmp' [GLIBC_2.2.5]
```

Two differences matter. The target of the binding changed from `libc.so.6` to `fake.so`, and the
version tag `[GLIBC_2.2.5]` disappeared because the preloaded definition carries no version.

The library search order is printed by:

```bash
LD_DEBUG=libs LD_PRELOAD=$PWD/fake.so ./target 2>&1 | grep -m5 'find library'
```

The preloaded object is searched before the executable's `DT_NEEDED` list.

### 6. Understand the resolution rules

The global search scope, in order, is:

1. the main executable,
2. every object in the `LD_PRELOAD` list, in list order,
3. the `DT_NEEDED` dependencies of the executable, breadth first,
4. objects added later with `dlopen(..., RTLD_GLOBAL)`.

A reference resolves to the *first* definition of the symbol found in that order. The first match
wins, so a preload placed earlier in the list beats a later one.

**Binding and visibility.** Only symbols with `STB_GLOBAL` or `STB_WEAK` binding are candidates.
`STB_WEAK` definitions lose against a `STB_GLOBAL` definition of the same name in the same object
but still participate in the global lookup. A `STV_HIDDEN` or `STV_INTERNAL` symbol is not
exported into the dynamic symbol table at all and can never interpose anything.

**Symbol versioning.** libc exports `strcmp` with the version tag `GLIBC_2.2.5`. A reference in
the target is recorded as `strcmp@GLIBC_2.2.5` in `.gnu.version_r`. When the preloaded object
carries no version definitions of its own, glibc cannot match a version and accepts the
unversioned definition, so the interposition succeeds. If the preloaded object *does* define its
own versions, the linker compares version names and the unversioned definition no longer matches.

Export the versioned alias explicitly to be safe:

```c
// versioned.c — export strcmp with the GLIBC version tag
#define _GNU_SOURCE
#include <string.h>

int fake_strcmp(const char *a, const char *b) {
    (void)a; (void)b;
    return 0;
}

__asm__(".symver fake_strcmp,strcmp@@GLIBC_2.2.5");
```

```bash
printf '%s\n' 'GLIBC_2.2.5 { global: strcmp; local: *; };' > versions.map
gcc -shared -fPIC -Wl,--version-script=versions.map -o versioned.so versioned.c
readelf --dyn-syms versioned.so | grep -E 'strcmp'
```

Expected output shows both the versioned and the default version entries:

```text
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  16 strcmp@@GLIBC_2.2.5
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  16 strcmp@GLIBC_2.2.5
```

Note the double `@` on the default-version entry. A lookup with a specific version
(`dlsym` equivalent, `dlvsym`) finds the first entry; a plain `dlsym(handle, "strcmp")` finds the
second.

**`RTLD_LOCAL` versus `RTLD_GLOBAL`.** A library opened with `dlopen(path, RTLD_LOCAL)` keeps its
symbols out of the global namespace, so it cannot interpose symbols resolved by other objects. It
still binds its *own* references to its own definitions, because the dynamic linker always prefers
the defining object for that object's own references. `RTLD_GLOBAL` publishes the symbols and lets
them interpose subsequent resolutions.

**`dlopen` order.** Objects loaded later with `dlopen` are appended to the global scope, after the
preload list. A preloaded definition therefore beats a `dlopen`ed one, provided the preload is in
the list before the `dlopen` call happens. If the target resolves the symbol before the preload is
processed — the case for symbols bound at load time via `BIND_NOW` — the preload still wins,
because the preload list is placed ahead of the executable's dependencies in the initial scope.

### 7. Secure-execution mode

glibc sets `AT_SECURE` for setuid, setgid and file-capability binaries. In secure mode the dynamic
linker removes `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `LD_PROFILE`,
`LD_BIND_NOW` and `LD_ORIGIN_PATH` from the environment before resolving anything.

```c
/* secure.c — report the execution mode */
#include <stdio.h>
#include <sys/auxv.h>

int main(void) {
    unsigned long mode = getauxval(AT_SECURE);
    printf("AT_SECURE=%lu\n", mode);
    return mode ? 1 : 0;
}
```

```bash
gcc -o secure secure.c
./secure ; echo "exit=$?"        # -> AT_SECURE=0, exit=0
sudo cp secure /tmp/secure && chmod u+s /tmp/secure
/tmp/secure ; echo "exit=$?"     # -> AT_SECURE=1, exit=1
```

The same effect comes from file capabilities:

```bash
sudo setcap cap_dac_override+ep ./secure
./secure ; echo "exit=$?"        # -> AT_SECURE=1
```

Confirm the environment stripping from the kernel side:

```bash
sudo strace -f -e trace=execve ./target 2>&1 | grep -i LD_
```

A stripped environment shows no `LD_PRELOAD` in the `execve` argument list.

### 8. Confirm the runtime effect

```bash
cd /path/to/work
strace -f -e trace=openat ./target 2>&1 | grep -E '\.so' | head
ltrace -e 'strcmp+memcmp' ./target 2>&1 | head -20
```

`ltrace` shows the preloaded `strcmp` calls with the arguments, which is the fastest confirmation
that the interposition is live.

## Variations

- **`LD_AUDIT`.** Runs an audit module that can rewrite bindings before they are resolved, with
  access to the symbol name, the object and the reference site. More powerful than interposition
  and more invasive; the module must export `la_version`, `la_objsearch` and `la_symbind`.
- **`LD_PROFILE` and `LD_DEBUG`.** Diagnostics, not interposition, but `LD_DEBUG=bindings` is the
  standard proof tool.
- **Static binaries.** No dynamic linker, no interposition. The equivalent routes are binary
  patching or a `ptrace`-based tool.
- **Go and Rust binaries.** Go binaries link libc dynamically only when cgo is used; a pure Go
  binary calls `strcmp` through its own runtime and the interposer still works because the call
  goes through the PLT. Rust binaries link libc dynamically and are trivially interposed.
- **glibc 2.34 and later.** `libpthread`, `libdl` and `librt` became empty stub libraries. A
  preloaded definition of a symbol that moved into `libc.so.6` (for example `pthread_create`) must
  be compiled and linked the same way, and the stub library no longer provides the real
  implementation, so the preloaded definition is the only one present.
- **Musl and dietlibc.** The dynamic linker is different: musl resolves `LD_PRELOAD` objects in
  order and applies version checks differently. Unversioned interposition works; versioned
  `.symver` aliases are not supported by musl's `ldso`.
- **Windows and macOS analogues.** Windows uses IAT hooking or `Detours`; macOS uses
  `DYLD_INSERT_LIBRARIES`, which is far more restricted — see
  `../macos/hardened-runtime-and-library-validation.md`.

## Verification

Positive — the binding changed:

```bash
LD_DEBUG=bindings LD_PRELOAD=$PWD/fake.so ./target 2>&1 | grep "to /path/to/work/fake.so"
```

Expected: at least one line naming `fake.so` as the binding target.

Negative — the interposition is real and not an artefact of the environment. Remove the preload
and confirm the behaviour returns to normal:

```bash
./target
LD_PRELOAD=$PWD/fake.so ./target
```

Expected: the first run does not print `[fake] strcmp(...)`, the second does. If the behaviour is
identical in both runs, the target never calls the symbol through the PLT — for example a call
resolved to a local, inlined copy.

Negative — confirm the export is real:

```bash
readelf --dyn-syms fake.so | grep -E ' GLOBALS? .* strcmp'
nm -D fake.so | grep strcmp
```

Expected: one `GLOBAL DEFAULT` entry.

Negative — confirm the security boundary holds:

```bash
sudo cp ./target /tmp/t && sudo chmod u+s /tmp/t
LD_PRELOAD=$PWD/fake.so /tmp/t
```

Expected: no `[fake]` output, because `AT_SECURE` stripped the variable. This is the control that
proves the previous positive result was caused by the preload and not by the target's own code.

## Pitfalls

- `gcc -shared -fPIC` without `-fPIC` produces a non-relocatable object and the link fails with
  `relocation R_X86_64_PC32 against symbol ... can not be used when making a shared object`.
- A missing `-fvisibility=default` in a build that defaults to hidden visibility makes the symbol
  invisible to the dynamic linker. `readelf --dyn-syms` shows it as `LOCAL`.
- Interposing `strcmp` to always return `0` makes every string compare equal, which can crash
  targets that then index a hash table with the wrong key. Return the real comparison result
  except for the specific pair being tested.
- Interposing `malloc`/`free` breaks targets that mix allocations across the boundary, because the
  preloaded `malloc` and the libc `free` may use different arenas.
- `LD_DEBUG` output goes to stderr. Redirect it or the terminal looks empty.
- `LD_DEBUG=bindings` on a large target produces megabytes of output. Filter with `grep` and a
  specific symbol name.
- A symbol bound with `-Bsymbolic` or `-Bsymbolic-functions` inside the defining library binds
  internally and ignores the preload.
- A call made through a hidden alias (`strcmp` resolved to a private symbol such as
  `__strcmp_avx2` after an IFUNC/optimised dispatch) bypasses the interposition. Check
  `readelf --dyn-syms libc.so.6 | grep strcmp` for the GNU IFUNC variants.
- `LD_PRELOAD` is ignored when the target is launched through a wrapper that resets the
  environment, such as `sudo` without `-E` or a systemd unit with `SecureBits=`.
- A preload that prints to stdout corrupts the target's output protocol. Log to stderr, or to a
  file descriptor that the target does not read.

## References

- `man 8 ld.so` and `man 7 ld.so` — the search order, `LD_PRELOAD`, `RTLD_LOCAL`, `RTLD_GLOBAL`
  and the secure-execution rules
- `man 2 getauxval` — `AT_SECURE`
- `man 1 ldconfig`, `man 5 ld.so.conf` — library path configuration
- ELF gABI and the GNU extension `.gnu.version_r` / `.gnu.version_d` for symbol versioning
- `readelf`, `nm` and `objdump` documentation from binutils
- Sibling entries: `elf-patch-elf-toolchain.md`, `../macos/hardened-runtime-and-library-validation.md`
