# Authoring guide

Rules for adding entries to the REA corpus. The schema is in [`../knowledge/SCHEMA.md`](../knowledge/SCHEMA.md);
this document covers how to write a good entry.

## The one-sentence test

An entry earns its place if it answers a question a practitioner actually has: *given this symptom,
what do I do, in what order, with which bytes?* If the entry only explains a concept, fold it into
an entry that also carries a procedure, or delete it.

## Anatomy of a strong entry

### Recognition

Concrete and observable. What does the practitioner see?

- Exact strings: `Invalid license key`, `Serial number is not registered`, `ERR_LICENSE_013`
- Error codes, exit codes, HTTP status codes
- Control-flow shape: a compare followed by a conditional jump, a table lookup indexed by a
  checksum of the input
- UI behaviour: the feature greyed out, the dialog that appears before the main window, the
  request that fails with 403 only when the key is absent
- Runtime artefacts: a registry key, a file under `~/Library/Application Support`, a SQLite table

Avoid "the app validates the licence" as recognition. Name the artefact.

### Method

Numbered and ordered. Each step states what to observe, not just which tool to open.

```
3. Locate the comparison. With the app suspended at the failure dialog, search for the message
   string in the text section and take the cross-reference to its use site:

   r2 -q -c 'izz~Invalid license key; axt @@ str.*' target.exe
```

Where a byte value is the outcome, give it exactly:

```
The branch is `0F 85 40 00 00 00` (`JNE`). Flip the low byte to `84` for `JE`:

   0F 85 40 00 00 00   ->   0F 84 40 00 00 00
```

State the working directory before commands that write files. State the input file name.

### Variations

The places the same technique appears differently:

- x86 vs x64 vs ARM64 encodings of the same idea
- Managed equivalent of a native technique
- Runtime-only variant when a static patch is impossible
- A hardened variant of the same check (server-side, hardware-bound)

### Verification

A verification that only proves the happy path is weak. Include the negative test:

> Re-run the original failing operation and confirm it now succeeds. Then confirm the check is
> really gone rather than merely bypassed for the cached state: clear the licence cache, restart
> the process, and repeat. A patch that only survives in memory is not a patch.

For signed formats, verification includes the signature step: after modifying a Mach-O the code
signature is invalid and the process will not launch until re-signed.

### Pitfalls

The failure that will actually happen:

- Editing a file inside a signed container invalidates the signature and the loader refuses it
- The offset moved between versions; the byte pattern matched a different function
- The check runs twice — once in the UI and once in the service — so only the visible one changed
- Checksums: PE optional header checksum, Authenticode, ELF build-id, DEX header SHA-1

## Tooling conventions

- Prefer `r2`/`rabin2` and `LIEF` for reproducible scripted work; prefer Ghidra for exploration.
- Give the command, then the interpretation of its output.
- When an API changed between major versions, state the version: "LIEF 1.0.0" or "Frida 17.x".
- Where a tool is missing from the host, give the manual fallback rather than a dead end.

## Anti-patterns

| Pattern | Why it is rejected |
| --- | --- |
| "Use a debugger to find the check" | Not an instruction. Name the breakpoint condition. |
| "Patch the jump" | Which jump, to what, at which offset? |
| Copy of upstream documentation with no local detail | Add the specific offsets, strings or API calls. |
| "Simply disable the check" | "Simply" hides the hard part. |
| Steps without expected output | The reader cannot tell success from failure. |
| Claims about behaviour never observed | Mark `verified: false` and phrase as expectation. |

## Entries that change the corpus

Update `updated:` in the frontmatter, add the new section, and keep the original content if it
remains correct. When a technique is superseded, add a `## Variations` note pointing at the
replacement instead of deleting history.

## Verification discipline

`verified: true` means the procedure ran end to end on a real target and the expected result was
observed. It is a statement about the author, not about the technique. Techniques assembled from
public write-ups stay `verified: false` until someone runs them.

## Cross-linking

Link sibling entries with relative Markdown paths from the entry's own directory. Do not link to
files that do not exist; the corpus is checked for broken relative references before release.
