# Playbook: licence keygen reconstruction

**Target**: any application whose licence check compares the entered serial against a rule that
can be reconstructed.
**Outcome**: a generator that produces serials the unmodified target accepts.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app app
sha256sum app
```

Collect every known-good serial. One is enough to start, several are better: they let you
confirm the algorithm generalises rather than memorising one value.

## 1. Find the comparison

```sh
strings -a -t x app | grep -iE 'licen|serial|key|registr|invalid|expired'
r2 -q -c 'izz~invalid' app
r2 -q -c 'aaa; axt @@ str.*' app
```

Read the function that owns the "invalid serial" reference. The compare is a few instructions
above it.

## 2. Classify the algorithm

| Shape | Recognition | Recovering the rule |
| --- | --- | --- |
| Equality | one `cmp` against an embedded string | the expected value is the key |
| Checksum | a loop over the characters producing a small value compared with a stored digit | the weights and the modulus |
| Per-group | several independent checks, one per group of the serial | one rule per group |
| Transform-then-compare | the input is hashed or permuted, then compared with a stored digest | the transform is the algorithm |
| Field decomposition | the serial splits into named parts (name, expiry, seat count) validated separately | one rule per field |
| Container | the serial is Base32/Base64 or custom-alphabet decoded before use | the alphabet and the decode |

## 3. Extract the constants

From the disassembly, collect:

- the alphabet or character set
- the weight table or the constants used in the arithmetic
- the modulus
- the expected digest, when the check is transform-then-compare
- the per-field offsets and lengths

Write them down before writing any code. A missing constant is the usual reason a reconstructed
algorithm does not reproduce the target's verdict.

## 4. Implement the rule in Python

Worked example — a three-group serial, each group five characters over a 32-symbol alphabet,
where the third group is a weighted sum of the first two modulo 32:

```python
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # 32 symbols
WEIGHTS  = [7, 3, 11, 5, 9, 13, 2, 17, 19, 23, 29, 31]

def index(ch: str) -> int:
    return ALPHABET.index(ch)

def weighted(group: str, offset: int) -> int:
    total = 0
    for pos, ch in enumerate(group):
        total += index(ch) * WEIGHTS[(offset + pos) % len(WEIGHTS)]
    return total % len(ALPHABET)

def group3(g1: str, g2: str) -> str:
    value = (weighted(g1, 0) * 31 + weighted(g2, 4)) % len(ALPHABET)
    return ALPHABET[value] * 5

def serial(name: str, org: str) -> str:
    g1 = "".join(ALPHABET[(ord(c) * 7 + 13) % len(ALPHABET)] for c in name.upper()[:5].ljust(5, "X"))
    g2 = "".join(ALPHABET[(ord(c) * 11 + 5) % len(ALPHABET)] for c in org.upper()[:5].ljust(5, "X"))
    return f"{g1}-{g2}-{group3(g1, g2)}"

if __name__ == "__main__":
    print(serial("ACME", "CORP"))
```

## 5. Validate the reconstruction

The rule must reproduce the target's verdict exactly:

```python
def target_verdict(candidate: str) -> bool:
    """Mirror of the reconstructed rule, as the target evaluates it."""
    parts = candidate.split("-")
    if len(parts) != 3:
        return False
    g1, g2, g3 = parts
    if len(g1) != 5 or len(g2) != 5 or len(g3) != 5:
        return False
    if any(ch not in ALPHABET for ch in g1 + g2 + g3):
        return False
    return g3 == group3(g1, g2)
```

Test it against every known-good serial:

```python
for known in KNOWN_GOOD:
    assert target_verdict(known), f"rule rejects a known-good serial: {known}"
```

Then test the negative: a mutated serial must be rejected.

```python
assert not target_verdict(known[:-1] + ("A" if known[-1] != "A" else "B"))
```

If the rule rejects a known-good serial, the constants are wrong. Go back to the disassembly
rather than adjusting the code until it fits — a fitted rule that happens to accept one sample
is not the algorithm.

## 6. Generate

Once the rule reproduces the target's behaviour, the generator is the inverse problem:

- **Direct inversion** — the missing field is a closed-form function of the known fields.
  Implement it and verify against the target.
- **Search** — the missing field is a small space (one character over a 32-symbol alphabet is 32
  candidates). Brute-force it; this is the correct method, not a fallback.

```python
def solve_group3(g1: str, g2: str) -> str:
    """Brute-force the checksum group."""
    for ch in ALPHABET:
        candidate = ch * 5
        if target_verdict(f"{g1}-{g2}-{candidate}"):
            return candidate
    raise ValueError("no solution")
```

Note the check function used by the solver must be the *target's* rule, not a fitted
approximation.

## 7. Verify against the real target

```sh
./app --licence ABCDE-23456-XXXXX
```

or feed it through the app's own entry point — a GUI, a command-line flag, or an activation
request. The serial must be accepted by the unmodified binary.

If the target also validates a machine binding, the generated serial is valid but the machine id
must match — see `knowledge/license-crypto/hardware-fingerprint-binding.md`.

## 8. When the algorithm is not invertible

| Situation | Approach |
| --- | --- |
| The checksum spans more than one character | enumerate the checksum space — 32² = 1024 candidates is trivial |
| The comparison is transform-then-compare with a hash | the hash is not invertible — patch the comparison instead |
| The rule involves a signature | the private key is not recoverable — forge a blob, see `pb-signed-blob-forgery.md` |
| The rule reads server state | no offline generator exists — the protocol is the target |

## 9. Deliverable

The generator script, the recovered constants with their source offsets, the known-good serials
used for validation, and the target's acceptance output.
