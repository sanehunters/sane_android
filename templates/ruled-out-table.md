# Ruled-Out Register

> Negative results are a **deliverable**, not an omission. This table is how the client sees what was
> tested and found clean, and it is what stops a tester re-walking disproven ground.
>
> A finding list without this table looks like a sample. With it, it looks like an audit.

| Checklist ID | Surface tested | Attacker model | What was tried | Observed result | Why this is a true negative | Date |
|---|---|---|---|---|---|---|
| SANE-D07-004 | `content://com.target.files` `openFile()` | AM-03 | `..%2f`, `../`, double-encoded, absolute paths, symlink | `SecurityException` on all | `openFile` calls `getCanonicalFile()` and asserts `startsWith(base)` at `FileProv.java:61` — traversal is structurally closed, not merely filtered | |
| | | | | | | |

## Rules for this table

1. **"The scanner found nothing" is not a true negative.** Only a manifest read, a code read, or a
   controlled experiment with a verified precondition establishes one.
2. **Name the mechanism that closes it**, not the tool that missed it. "drozer returned nothing" is
   worthless; "the provider has `android:exported="false"` and no `grantUriPermissions`" is evidence.
3. **Record the attacker model.** Clean for AM-03 says nothing about AM-05.
4. **A tool's silence is never a negative result.** Hooking an abstract framework class records nothing
   because the concrete class is different; zero hits from a base-class hook is a false negative.
5. **If a negative later turns out wrong, strike it through and keep it.** The correction is the evidence
   of rigour.
