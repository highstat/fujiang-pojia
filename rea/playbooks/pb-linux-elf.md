# Playbook: Linux ELF licence bypass

**Target**: a Linux application or shared library that gates features behind a licence check.
**Outcome**: either a patched binary or an interposed library that satisfies the check, with the
approach chosen by what the target actually needs.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app app && chmod +x app
sha256sum app | tee app.sha256
file app
readelf -hW app
readelf -dW app | grep -E 'NEEDED|RPATH|RUNPATH'
checksec --file=app 2>/dev/null || (readelf -lW app | grep -i gnu_stack)
```

Note whether the binary is PIE, whether RELRO is full, and whether it is statically linked
(`file` says "statically linked" — then no interposition is possible).

## 1. Choose the route

| Condition | Route |
| --- | --- |
| Statically linked | file patch only |
| The check lives in a shared library the app loads | patch the library, or `LD_PRELOAD` |
| The check is a simple comparison in the executable | file patch |
| The check depends on runtime state that must be observed first | `LD_PRELOAD` hook to observe, then patch |
| The app is setuid or has `AT_SECURE` | `LD_PRELOAD` is ignored — patch the file |

## 2. Locate the check

```sh
strings -a -t x app | grep -iE 'licen|serial|trial|expir|registr|not activ'
r2 -q -c 'izz~licen; axt @@ str.*' app
r2 -q -c 'aaa; afl~licen' app
```

What the process opens at startup:

```sh
strace -f -e trace=openat,open,stat,access,readlink ./app 2>&1 | grep -iE 'licen|config|json|machine-id'
```

## 3A. File patch

Translate the virtual address to a file offset:

```sh
r2 -q -c '?v 0x401234' app        # virtual address -> file offset
r2 -q -c 'iS~.text' app           # section table with vaddr and paddr
```

Patch with radare2:

```sh
r2 -q -w -c 's 0x401234; p8 8; wx b001c3; p8 8; q' app
```

Or with LIEF 1.0.0:

```python
import lief
from pathlib import Path

binary = lief.ELF.parse("app")
vaddr = 0x401234
seg = next(s for s in binary.segments
           if s.virtual_address <= vaddr < s.virtual_address + s.virtual_size)
offset = seg.file_offset + (vaddr - seg.virtual_address)

data = bytearray(Path("app").read_bytes())
print("bytes at", hex(offset), data[offset:offset+8].hex(" "))
data[offset:offset+3] = b"\xB0\x01\xC3"          # mov al,1 ; ret
Path("app_patched").write_bytes(data)
```

### ELF structural repair

`patchelf` is convenient but rewrites the dynamic section:

```sh
patchelf --replace-needed libold.so.1 libnew.so.1 app_patched
patchelf --print-needed app_patched
readelf -lW app_patched        # compare the program headers with the original
```

If the result stops loading, the section header table is stale. LIEF rebuilds the structure and
is the safer route:

```python
import lief
binary = lief.ELF.parse("app")
binary.add(lief.ELF.Library("hook.so", lief.ELF.Header.RPATH_MODE.RUNPATH))
binary.write("app_patched")
```

## 3B. Interposition

Write the hook:

```c
/* hook.c */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>

typedef int (*strcmp_t)(const char *, const char *);

int strcmp(const char *a, const char *b) {
    static strcmp_t real;
    if (!real) real = (strcmp_t)dlsym(RTLD_NEXT, "strcmp");
    if (a && b && strstr(a, "LIC-") && strstr(b, "LIC-")) {
        fprintf(stderr, "[hook] %s == %s\n", a, b);
        return 0;
    }
    return real(a, b);
}
```

```sh
gcc -shared -fPIC -o hook.so hook.c -ldl
LD_PRELOAD=./hook.so ./app
LD_DEBUG=bindings ./app 2>&1 | grep -i lic    # confirm the interposition took
```

Inspect symbol versioning when an interposition fails:

```sh
readelf --dyn-syms app | grep -i strcmp
```

```
0000000000000000  12 GLIBC_2.2.5 strcmp
```

An unversioned preload can satisfy many versioned glibc references. Do not add an undefined
`real_strcmp` alias to a function-pointer variable. If an explicit export version is required,
follow the complete version-script example in
[the interposition guide](../knowledge/linux-elf/elf-interposition-ld-preload.md):

```c
int strcmp(const char *left, const char *right);
```

Interposing a file read, for a machine-id based check:

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>

typedef int (*open_t)(const char *, int, ...);

int open(const char *path, int flags, ...) {
    static open_t real;
    if (!real) real = (open_t)dlsym(RTLD_NEXT, "open");
    if (path && strstr(path, "machine-id"))
        return real("/tmp/machine-id", flags);
    return real(path, flags);
}
```

```sh
echo -n "0123456789abcdef0123456789abcdef" > /tmp/machine-id
LD_PRELOAD=./hook.so ./app
```

## 4. Verify

```sh
file app_patched
readelf -hW -lW app_patched
ldd app_patched
./app_patched; echo "exit=$?"
```

Then:

1. Repeat the operation that was locked.
2. Run from a clean environment: `env -i HOME=$HOME PATH=/usr/bin:/bin ./app_patched`.
3. Confirm the patch: `r2 -q -c 'pd 4 @ 0x401234' app_patched` shows the new bytes.
4. If interposing, confirm the hook fired: the `[hook]` line appears in stderr.

## 5. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The hook never fires | symbol versioning, internal binding, or inlining | inspect dynamic symbols and binding evidence before selecting a version script |
| The hook fires but nothing changes | the check is elsewhere | follow the `[hook]` output to the next stage |
| `LD_PRELOAD` ignored | setuid / `AT_SECURE` | patch the file |
| The patched binary does not start | `patchelf` corrupted the layout | rebuild with LIEF, compare `readelf -lW` |
| The app runs under a different user | the licence state is per-user | check `~/.config/<app>` for the actual user |
| A snap/flatpak sandbox hides the file | confinement | patch inside `~/snap/<app>/current` or `~/.var/app/<id>` |

## Deliverable

`app_patched` or `hook.so`, the manifest with offsets, the original hash, and the verification
output.
