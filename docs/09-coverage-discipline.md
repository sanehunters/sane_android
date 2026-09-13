# Coverage Discipline — the anti-tunnel-vision system

> **The problem this document exists to solve.**
>
> An agent sweeping an Android app finds an arbitrary file read in hour two. It is genuinely exciting,
> so it chases it: builds the PoC, tries to escalate, tests three variants, writes the report. Six hours
> later it has one good finding — and it has not looked at the WebView, the deep-link router, the
> backend API, the payment flow or the other forty exported components.
>
> The client's programme then pays an independent hunter for an account takeover in the deep-link
> router. We had the app for two weeks and never opened that door.
>
> **The bug was not missed because it was hard. It was missed because something else was interesting.**

Tunnel vision is the single largest source of lost value in an agent-run assessment. It is not a
knowledge problem and more checklist items will not fix it. It is a **control-flow problem**, and it
needs mechanical countermeasures.

---

## 1. Why it happens to an LLM specifically

| Cause | What it looks like |
|---|---|
| **The plan lives in context, the finding fills context** | Four hours into a chase, the original sweep plan has been pushed out of the window. The agent is not ignoring the plan; it no longer has it. |
| **Local reward gradient** | Every step of an escalation produces a satisfying result. Sweeping component 23 of 47 produces nothing. The agent follows the gradient. |
| **No forcing function** | Nothing ever interrupts to say "log it and go back". A human lead would; there is no lead. |
| **Depth feels like rigour** | Producing one deeply-proved finding *feels* like a thorough job. It is a narrow job. |
| **No externalised state** | If coverage is only in the agent's head, a context compaction silently destroys it and nothing notices. |

**The countermeasure to every row in that table is the same: move the plan out of the context window
and onto disk, and make progress through it mechanically checkable.**

---

## 2. The five mechanisms

### Mechanism 1 — Breadth before depth is a phase boundary, not a preference

The phases are not a suggested order. They encode a hard rule:

> **During P3, P4, P5 and P6 you are FORBIDDEN from escalating.**
> You enumerate, you test, you confirm a primitive exists, you write it down, **and you move on**.
> All escalation happens in **P7**, after coverage is complete.

When you find the arbitrary file read in P5, the correct behaviour is:

1. Confirm the primitive exists — minimum proof only, five minutes.
2. Write a stub to the parking lot with what you know and what the next experiment is.
3. Set the checklist row to `true`, `result=finding`.
4. **Go to the next component.**

The file read is not going anywhere. The forty components you have not looked at are where the other
findings are. You come back in P7 with *every* primitive on the table at once — which is also when you
can see the chains, because chains are only visible when you have several primitives side by side.

> **You cannot find the chain between primitive A and primitive C if you spent the whole engagement
> on primitive A.**

### Mechanism 2 — The parking lot

The moment something looks juicy, it goes to `hypotheses/` as a stub and you return to the sweep.

```markdown
# H-004 — ShareReceiverActivity may allow arbitrary app-private file read

Found during: P5, D07 sweep, component C-023
Looks juicy because: it takes a `content://` URI from an untrusted Intent and re-opens it with
                     the app's own UID, with no canonicalisation visible at ShareReceiver.java:88
Minimum proof obtained: `adb shell content read` returns bytes for a path outside the intended root
Next experiment: build the attacker APK, confirm from AM-03, then test whether the sheet grants the
                 minted URI outward (that decides Medium vs High)
Estimated escalation cost: 2h
DEFERRED TO P7.
```

Thirty seconds to write. It preserves everything the escalation would have needed, and it lets the
agent leave.

### Mechanism 3 — The three-strike rule

A concrete, checkable heuristic for "am I in a rabbit hole?":

> **If you have spent more than ~15 tool calls on a single checklist item without either confirming it
> or ruling it out, STOP.**
>
> Write what you know to the parking lot, mark the row `blocked` with the open question, and move to the
> next item. If it is genuinely worth more time, P7 is where that time is spent.

Three strikes, concretely:

1. **Strike one** — the item is not settled after ~15 tool calls. Note it.
2. **Strike two** — you have re-run a variant of the same probe three times. You are guessing.
3. **Strike three** — you are writing exploit code during P3–P6. That is a phase violation.

Any one strike means: park it, move on.

### Mechanism 4 — Coverage is external, two-dimensional and mechanically gated

Coverage is not a feeling. It is two CSV files in the engagement folder.

**Dimension 1 — the methodology.** `checklist-status.csv`, one row per checklist item across all 27
domains. Every row is `true` or `false`.

**Dimension 2 — the application.** `inventory/components.csv`, one row per component **that actually
exists in this app** — every exported activity, every provider authority, every deep-link host, every
WebView, every bridge method, every endpoint.

The second one is what lets you say the sentence the client actually wants:

> *"All 47 exported components, 8 provider authorities, 23 deep-link hosts and 5 WebViews in version
> 18.15.0 were individually tested. Here is the result for each."*

Testing "domain D07" is not the same as testing **all eight provider authorities**. Only a per-instance
register proves the latter, and only the latter is an audit.

Build it once, in P3:

```bash
python3 ~/sane_android/scripts/inventory.py base.apk --out inventory/
```

Then the gate:

```bash
python3 ~/sane_android/scripts/coverage.py checklist-status.csv --components inventory/components.csv --gate p7
```

`--gate p7` **exits non-zero** while any in-scope P3–P6 row or any component instance is still untested.
You are not permitted to begin escalation until it exits zero.

### Mechanism 5 — The session ritual

Context does not survive. Disk does. So every session starts and ends the same way.

**On start, before anything else:**

```bash
cat BugBountyTarget/<Target>_<date>/report/assessment-status.md      # where am I
python3 ~/sane_android/scripts/coverage.py .../checklist-status.csv  # what is still false
cat BugBountyTarget/<Target>_<date>/hypotheses/*.md                  # what did I park
```

**On end, and after every phase:**

- update `assessment-status.md` — `COMPLETED`, `IN PROGRESS`, `NEXT TARGET`, `BLOCKERS`
- flip the rows you settled
- commit and push both copies

A session that ends without doing this has destroyed its own state, and the next session restarts
rather than resumes.

---

## 3. The rule, stated once

> **Depth is earned by breadth.**
>
> You may go as deep as you like on any primitive — in **P7**, after every in-scope checkpoint and every
> component instance has been settled. Before P7, depth is a bug.

And its corollary, which is what makes the whole thing commercially valuable:

> **A finding proves you looked somewhere. The ruled-out register proves you looked everywhere.**
>
> The second one is the deliverable the client cannot get from a lone hunter, and it is the reason they
> pay a firm rather than waiting for their programme.

---

## 4. Think beyond the checklist — but only after it

There is a real tension here and it should be stated plainly rather than papered over.

The checklist is a **floor, not a ceiling**. Novel findings — the ones that come from noticing something
nobody wrote down — are the highest-value output of the whole engagement. An agent that mechanically
walks 900 checkboxes and thinks about nothing is also failing, just differently.

The resolution is sequencing, not suppression:

| When | What |
|---|---|
| **P3–P6** | Sweep everything. When you notice something novel, **park it as a hypothesis** with the experiment that would settle it. Do not chase it. |
| **P7** | Now chase. Work the parking lot in expected-value order, with every primitive visible at once. This is where cross-surface joins appear, and they are only visible from breadth. |
| **Any time** | If you find a class the checklist does not cover at all, file a [Checklist gap issue](https://github.com/sanehunters/sane_android/issues/new?template=04-checklist-gap.yml) so the next engagement starts ahead of this one. |

Curiosity is not the problem. **Unsequenced** curiosity is.

---

## 5. What to do when you catch yourself

You will catch yourself mid-chase. The recovery is fixed:

1. **Stop where you are.** Do not finish the thought.
2. **Park it.** One stub in `hypotheses/`: what you know, why it is juicy, the next experiment.
3. **Find your place.** `coverage.py` — the first `false` row is where you were.
4. **Resume the sweep.**
5. **Do not feel bad about it.** The parking lot means nothing was lost. That is what it is for.

---

## 6. Checklist for this document

- [ ] `inventory/components.csv` built in P3, before any deep review
- [ ] `checklist-status.csv` seeded with every row `false`
- [ ] No escalation attempted during P3–P6; every juicy finding parked instead
- [ ] Three-strike rule applied — nothing consumed more than ~15 tool calls unsettled
- [ ] `coverage.py --gate p7` exits zero before P7 begins
- [ ] `assessment-status.md` updated after every phase, and pushed
- [ ] Every parked hypothesis either escalated in P7 or moved to the ruled-out register with a reason

---

## 7. Related

- [`ISSUES.md`](../ISSUES.md) — the phase order this document enforces
- [`AGENTS.md`](../AGENTS.md) — the SOP
- [`docs/02-severity-and-reportability.md`](02-severity-and-reportability.md) — why a primitive is not a finding
- [`BugBountyTarget/README.md`](../BugBountyTarget/README.md) — where the state files live
