# Findings Index — <target> <version> (<package>)

| ID | Title | Status | Severity | VRT path | CWE | Component |
|----|-------|--------|----------|----------|-----|-----------|
| F-001 | <impact-category title, not the mechanism> | **evidence-complete** | Medium | `broken_access_control...` | CWE-nnn | `com.target...` |

**Status vocabulary (one lifecycle, START.md §6):** `candidate → confirmed → evidence-complete → reported → accepted | declined | retracted`

## Severity reasoning
> One line per finding explaining the rating from **demonstrated** capability. Name any unproven link.
- F-001 Medium: real UID-sandbox crossing, zero permissions — but the attacker never receives the bytes
  (outward URI grant tested, does not exist).

## Ruled out — do NOT re-walk
> The list that stops the next session wasting a day. Each entry names the mechanism, with file:line.
-
