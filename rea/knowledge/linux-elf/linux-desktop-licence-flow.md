---
id: "linux-desktop-licence-flow"
title: "Linux desktop licence flow"
domain: "linux-elf"
kind: "technique"
platforms: "linux"
arch: "x86-64, arm64"
difficulty: "intermediate"
tools: "rg,strace,lsof,r2,gdb,secret-tool"
verified: false
updated: "2026-11-15"
summary: "Maps where a Linux desktop application keeps its licence state and how it binds that state to the machine, then gives the observation commands and the three patch points — the config file, the validation function and the expiry comparison."
---

## Summary

A Linux desktop app keeps its licence in one of a small number of predictable places, and the
location is discovered by watching the process rather than by guessing. This entry covers the
`XDG` directories, the keyring, the confinement-specific paths for Flatpak and Snap, the machine
identifiers used for binding, and the three places a licence decision can be changed. Reach for it
when an app starts in trial mode, shows a feature list that is missing paid entries, or refuses to
run on a machine it was licensed for.

## Recognition

- `~/.config/<app>/` contains a file named `licence.json`, `license.json`, `license.dat`,
  `settings.json` or `subscription.json`.
- `~/.local/share/<app>/` contains a licence blob, often a `.json` file next to a `licences/` or
  `keys/` subdirectory.
- `/var/lib/<app>/` holds machine-wide state and is only writable as root.
- `~/.config/dconf/user` is a binary database that many GNOME and KDE apps use for trial and
  activation flags.
- `~/.local/share/keyrings/login.keyring` and `~/.local/share/kwalletd/` hold the secret when the
  app uses `libsecret` or KWallet.
- The app refuses to start, or starts with the paid entries greyed out, and a dialog names the
  licence: `License expired`, `This machine is not registered`, `Subscription inactive`.
- `strace` shows an `openat` of a file under `~/.config/<app>/` immediately after start-up, followed
  by a `read` of a small JSON blob.
- The binary contains the literal path `/machine-id`, `product_uuid`, `machine_id` or a MAC
  address format string.

## Method

### 1. Sweep the user directories

```bash
rg --hidden --no-ignore -g '!proc' -g '!node_modules' -i 'licen' ~/.config ~/.local/share 2>/dev/null | head -40
```

`rg --hidden` includes dot-directories; `--no-ignore` bypasses `.gitignore` and `.ignore` rules
that would otherwise hide state directories. The `-g '!proc'` exclusion keeps the sweep off
`/proc`.

For the key-value shape of the licence file, list every JSON under the config directory:

```bash
find ~/.config -maxdepth 3 -name '*.json' -newermt '-90 days' -print 2>/dev/null | head -40
for f in $(find ~/.config -maxdepth 3 -name '*.json' 2>/dev/null | head -40); do
  if grep -qiE '"(expires|expiry|licensed|valid|subscription|trial|machine)"' "$f" 2>/dev/null; then
    echo "== $f"; cat "$f"
  fi
done
```

### 2. Watch the process open its state

```bash
cd /path/to/work
strace -f -e trace=openat,read,close -s 200 -o /tmp/trace.txt ./app
```

Then read the trace:

```bash
grep -iE 'licen|licence|license|\.json|keyring|kwallet|machine-id|product_uuid' /tmp/trace.txt | head -40
```

Expected excerpt:

```text
[pid 12345] openat(AT_FDCWD, "/home/user/.config/fooapp/licence.json", O_RDONLY|O_CLOEXEC) = 3
[pid 12345] read(3, "{\"expires\":\"2026-01-01\",\"machine\":\"9c3f...\"}", 128) = 62
[pid 12345] close(3) = 0
[pid 12345] openat(AT_FDCWD, "/etc/machine-id", O_RDONLY|O_CLOEXEC) = 3
[pid 12345] read(3, "9c3f1d2e4a5b6c7d8e9f0a1b2c3d4e5f\n", 33) = 33
```

The `openat` path followed by a `read` of the same file descriptor is the proof that the file is
consulted at launch.

While the app is running, confirm the open file descriptors:

```bash
pgrep -n app
lsof -p "$(pgrep -n app)" 2>/dev/null | grep -iE 'licen|json|keyring'
```

### 3. Enumerate the candidate locations explicitly

```bash
echo "XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}"
echo "XDG_DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}"
echo "XDG_STATE_HOME=${XDG_STATE_HOME:-$HOME/.local/state}"
echo "XDG_CACHE_HOME=${XDG_CACHE_HOME:-$HOME/.cache}"
ls -la "${XDG_CONFIG_HOME:-$HOME/.config}" | head -40
ls -la /var/lib 2>/dev/null | head -40
```

The locations and what each one holds:

| Location | Content |
| --- | --- |
| `$XDG_CONFIG_HOME/<app>/` | Configuration, including `licence.json`, `settings.json` |
| `~/.config/dconf/user` | Binary GSettings/dconf database; trial and activation flags |
| `$XDG_DATA_HOME/<app>/` | Application data: licence blobs, key files, cached activation |
| `~/.local/state/<app>/` | State, often a trial counter with a first-run timestamp |
| `/var/lib/<app>/` | Machine-wide install state; requires root to read or write |
| `/usr/share/<app>/` | Vendor-shipped defaults, read-only |
| `~/.local/share/keyrings/login.keyring` | `libsecret` / gnome-keyring secrets |
| `~/.local/share/kwalletd/` | KWallet secrets |

Read the dconf database:

```bash
dconf dump / 2>/dev/null | grep -iE 'licen|trial|activ|subscription' | head -20
```

### 4. Keyring inspection

```bash
# libsecret / gnome-keyring
secret-tool search --all 2>/dev/null | grep -iE 'licen|activ|subscription'
secret-tool lookup application fooapp

# KWallet
kwallet-query -l kdewallet 2>/dev/null | grep -iE 'licen|activ'
```

`secret-tool lookup application fooapp` prints the stored secret for the entry named `fooapp`. The
`login.keyring` file itself is encrypted with a key derived from the login password, so it cannot be
read directly without the password.

### 5. Flatpak and Snap confinement

A sandboxed application never sees the host's `~/.config`. Its paths are remapped into the
per-application directory:

```bash
ls -la ~/.var/app/<app-id>/
ls -la ~/.var/app/<app-id>/config/<app>/
ls -la ~/.var/app/<app-id>/data/<app>/

flatpak info --show-location <app-id>
flatpak run --command=sh <app-id> 'ls -la ~/.config; cat ~/.config/<app>/licence.json'
```

Snap keeps the data under the snap name and revision:

```bash
ls -la ~/snap/<snap-name>/
ls -la ~/snap/<snap-name>/<revision>/.config/
sudo ls -la /var/snap/<snap-name>/<revision>/ 2>/dev/null
```

For a Flatpak target the host `~/.var/app/<app-id>/config/<app>/licence.json` is the file to edit;
for a Snap target it is `~/snap/<snap-name>/<revision>/.config/<app>/licence.json`.

### 6. Machine binding

```bash
cat /etc/machine-id
cat /var/lib/dbus/machine-id 2>/dev/null
cat /sys/class/dmi/id/product_uuid 2>/dev/null
cat /sys/class/net/*/address
ip -o link show | awk -F'link/ether ' '{print $2}'
```

`/etc/machine-id` is a 32-character hex string; `/var/lib/dbus/machine-id` is usually a symlink to
it. `/sys/class/dmi/id/product_uuid` is the SMBIOS system UUID and is readable only on real
hardware. A MAC address is the weakest of the three because it changes with docking, USB adapters
and virtualisation.

Find which one the app reads:

```bash
strace -f -e trace=openat ./app 2>&1 | grep -E 'machine-id|product_uuid|/sys/class/net'
```

### 7. Patch point (a): the config file

```bash
mkdir -p ~/.config/fooapp
cp ~/.config/fooapp/licence.json ~/.config/fooapp/licence.json.bak
cat > ~/.config/fooapp/licence.json <<'JSON'
{
  "licence": "00000000-0000-0000-0000-000000000000",
  "expires": "2999-12-31",
  "machine": "9c3f1d2e4a5b6c7d8e9f0a1b2c3d4e5f",
  "trial": false,
  "activated": true,
  "offline": true
}
JSON
```

The exact key names come from the file itself. The value that matters is the expiry date; set it
past the end of time so no date comparison can fail. Keep the machine identifier identical to the
one already in the file, otherwise the binding check fails for a different reason.

A binary blob is handled the same way, but the expiry is encoded inside it. Find it:

```bash
strings -a ~/.config/fooapp/licence.dat | grep -E '20[0-9]{2}-[0-9]{2}-[0-9]{2}'
```

### 8. Patch point (b): the validation function

Locate the code that consumes the file:

```bash
cd /path/to/work
r2 -qc 'aaa; iz~licen' ./app
r2 -qc 'aaa; axt @@ str.*licen*' ./app
```

Expected: a function such as `LicenseManager::is_valid` or `validate_license` that loads the JSON,
extracts a field, and returns a boolean. Read the function:

```bash
r2 -qc 'aaa; s 0xADDR; pdf' ./app
```

Force the boolean result. On x86-64 the function returns the verdict in `eax`; `mov eax, 0` is
`b8 00 00 00 00` and `mov eax, 1` is `b8 01 00 00 00`:

```
b8 00 00 00 00   ->   b8 01 00 00 00
```

On AArch64 the return value is in `w0`; `mov w0, #0` is `00 00 80 52` and `mov w0, #1` is
`20 00 80 52`:

```
00 00 80 52   ->   20 00 80 52
```

Build the sequences before writing them:

```bash
rasm2 -a x86 -b 64 -d 'mov eax, 1'
rasm2 -a arm -b 64 -d 'mov w0, #1'
```

Apply and verify:

```bash
r2 -w -qc 'wx b801000000 @ 0xADDR; q' ./app
r2 -qc 'aaa; s 0xADDR; p8 8' ./app
```

### 9. Patch point (c): the expiry comparison

The comparison is usually a `strcmp` against a formatted date, a `time()` call compared against a
parsed expiry, or a `struct tm` comparison. Find the clock calls:

```bash
r2 -qc 'aaa; ii~time' ./app
r2 -qc 'aaa; axt @@ sym.imp.time' ./app
```

Read the comparison and neutralise it by forcing the "not expired" flag:

```bash
r2 -qc 'aaa; s 0xADDR; pd 12' ./app
```

The typical shape is `cmp`/`test` followed by a `jle`/`jge`. Force the flag register instead of
patching the branch. `SETcc r/m8, imm8` is encoded as `0f 9c` followed by the ModR/M byte and the
immediate, so the two encodings differ only in the last byte:

```
0f 9c c0   setl al, 0
0f 9c c1   setl al, 1
```

Confirm the encoding before patching:

```bash
rasm2 -a x86 -b 64 -d 'setl al, 1'
```

### 10. The runtime variant: interpose the clock

No binary edit, and it also defeats a trial counter that compares against the current time:

```c
// timehook.c — roll the clock back so expiry checks pass
#define _GNU_SOURCE
#include <time.h>
#include <sys/time.h>

time_t time(time_t *t) {
    static const time_t fake = 1600000000;   /* 2020-09-13 */
    if (t) *t = fake;
    return fake;
}

int clock_gettime(clockid_t clk, struct timespec *tp) {
    tp->tv_sec = 1600000000;
    tp->tv_nsec = 0;
    return 0;
}

int gettimeofday(struct timeval *tv, void *tz) {
    if (tv) { tv->tv_sec = 1600000000; tv->tv_usec = 0; }
    return 0;
}
```

```bash
gcc -shared -fPIC -o timehook.so timehook.c
LD_PRELOAD=$PWD/timehook.so ./app
```

The same mechanism interposes `open`/`fopen` to redirect the licence file to a patched copy, and
`strcmp` to make one specific comparison succeed.

## Variations

- **Snap and Flatpak sandboxing.** The patch point is inside the sandbox's own directory tree, and
  the host's `~/.config` is irrelevant. Editing `~/.var/app/<app-id>/config/<app>/licence.json` is
  the equivalent of editing `~/.config/<app>/licence.json` on a native install.
- **System-wide installs.** `/var/lib/<app>/` and `/etc/<app>/` hold the machine-wide state; the
  patch needs root and the change is reverted by every package upgrade.
- **Keyring-backed licences.** When the secret lives in the keyring, the config file only holds a
  reference. The patch point moves to the `libsecret` call — `secret_password_lookup_sync` — or to
  the KWallet entry, which can be edited with `kwallet-query` under the right wallet.
- **dconf-backed flags.** A trial flag in `~/.config/dconf/user` is edited with
  `dconf write /path/to/key true`; the file is binary, so a hex patch is the wrong tool.
- **Rust and Go targets.** Rust binaries keep their string literals in `.rodata` and are readable
  with `strings`; Go binaries split them across the `.rodata` section and `strings` finds them
  only with `-a`. Both are interposable with `LD_PRELOAD` — see `elf-interposition-ld-preload.md`.
- **Server-side licences.** When the app validates against a vendor server, the local state is only
  a cache and the decision happens on the response. The patch point moves to the JSON parser for
  the field carrying the entitlement.

## Verification

Positive — the state change took effect:

```bash
strace -f -e trace=openat,read -s 200 -o /tmp/trace2.txt ./app
grep -A2 -i 'licence.json' /tmp/trace2.txt | head -10
```

Expected: the `read` shows the new expiry value, and the app starts with the paid features enabled.

Negative — the check is really gone, not merely cached. Remove every piece of licence state and
re-run:

```bash
rm -rf ~/.config/fooapp ~/.local/share/fooapp ~/.cache/fooapp
./app
```

Expected: with route (a) the app returns to the unlicensed state, which proves the config file was
the operative input. With routes (b) and (c) the app stays licensed, which proves the decision point
was changed rather than the data.

Negative — the machine binding still holds or was bypassed consistently. Change the recorded
machine identifier and confirm the outcome:

```bash
python3 - <<'PY'
import json, pathlib
p = pathlib.Path.home() / ".config/fooapp/licence.json"
d = json.loads(p.read_text())
d["machine"] = "00000000000000000000000000000000"
p.write_text(json.dumps(d))
PY
./app
```

Expected: the app rejects the licence. Restore the backup afterwards.

Negative — confirm the binary patch is present and reversible:

```bash
r2 -qc 'aaa; s 0xADDR; p8 8' ./app
sha256sum ./app ./app.orig
```

Expected: the new bytes at the address, and a differing digest that confirms the original is
retained for rollback.

## Pitfalls

- `rg` without `--hidden` skips `~/.config` contents, and without `--no-ignore` it skips
  directories covered by an ignore file.
- `strace` on a GUI app produces a very large trace; `-e trace=openat` alone is usually enough, and
  `-f` follows the child processes that may own the licence code.
- `strace` needs no privileges for the target's own files but cannot trace a setuid binary or a
  process owned by another user without `sudo`.
- A licence file that is rewritten by the app on every exit is overwritten by the next run; a file
  made read-only (`chmod 444`) reveals that behaviour immediately.
- Editing `/var/lib/<app>/` state is undone by a package upgrade and may be re-validated by a
  daemon that restores it.
- Interposing `time()` breaks TLS: certificate validity checks compare against the real clock, and
  a rolled-back clock makes every certificate look expired or not yet valid. Interpose the specific
  comparison function instead of the clock when the app makes network calls.
- Interposing `strcmp` to always return `0` breaks hash tables and string maps. Return the real
  result except for the exact pair under test.
- Keyring contents are encrypted with a key derived from the login password; editing
  `login.keyring` as bytes corrupts the whole keyring, not just one entry.
- `dconf write` affects only the current session unless the profile is locked with
  `dconf profile update`.
- A Flatpak application cannot see the host's `~/.config` at all; a patch there has no effect and
  the licence file under `~/.var/app/<app-id>/` is the only one that counts.
- The trial counter often lives in `~/.local/state/` or `~/.cache/`, not in `~/.config`, and
  deleting only `~/.config` does not reset the trial.

## References

- `man 1 strace`, `man 8 lsof`, `man 1 rg`
- freedesktop.org, *XDG Base Directory Specification* — the meaning of `XDG_CONFIG_HOME`,
  `XDG_DATA_HOME`, `XDG_STATE_HOME` and `XDG_CACHE_HOME`
- `man 5 dconf`, `man 1 secret-tool`, `man 1 kwallet-query`
- `man 1 flatpak`, `man 1 snap` — the confinement directory layout
- `man 5 machine-id`, `/sys/class/dmi/id/product_uuid` — the machine identifiers
- Sibling entries: `elf-interposition-ld-preload.md`, `elf-patch-elf-toolchain.md`
