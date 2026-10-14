# 00 — bootstrap (new target, Claude Code)

**Operator steps, in a terminal:**

```bash
git clone https://github.com/sanehunters/sane_android.git sane_android 2>/dev/null || git -C sane_android pull --ff-only
cd sane_android                  # the methodology checkout (any path)
claude --version                 # 2.1.280 or later (Claude Opus 5.5 needs it)
claude                           # start Claude Code here: CLAUDE.md, hooks, skills, agents and workflows load from the checkout
```

In the session, run `/model` and confirm it shows **Claude Opus 5.5** (`claude-opus-5-5`, the project default at
`high` effort). If Opus 5.5 is unavailable (usage limit, credits, outage), `/model claude-opus-5` selects the
fallback; nothing else changes. Then paste the block below with the slots filled. The authorisation, programme and
scope you give here are recorded in `engagement.json` and travel with every task the session delegates.

```text
You are the lead Android bug-bounty researcher on this engagement and you operate autonomously; nobody is
watching. Your entire operating procedure is in this repository: read START.md in full first (CLAUDE.md is
already loaded); it is the only file you must read whole.

ENGAGEMENT PARAMETERS
  TARGET NAME     : <<< <Target> >>>
  APK / PACKAGE   : <<< /path/to/base.apk  OR  com.example.app on a connected device >>>
  PROGRAM & SCOPE : <<< e.g. https://hackerone.com/example — Android app + api.example.com; exclusions: ... >>>
  AUTHORISATION   : <<< public-programme | sow | own-app | vdp | lab  (engagement.json.authorisation.basis) >>>
  ACCOUNTS        : <<< account A / account B credentials, or "not yet provided" >>>
  EVIDENCE REMOTE : <<< private git url for the engagement's evidence repo (SANE_EVIDENCE_REMOTE / --remote), or "none yet" (then the hooks state the blocker: no evidence remote configured: evidence is committed locally only — set SANE_EVIDENCE_REMOTE or git -C $E remote add origin <private url>) >>>

Then follow START.md §3 (doctor → new-engagement → engagement.json → first commit in the engagement's own git
repository — the evidence repo — pushed to its private remote; never commit or push engagement evidence to the
methodology repository (it is public)) and work the state machine in §4 from P0, recording per §6 and pushing
after every batch (R7). For the breadth phases use /breadth-phase and verify candidates with /verify-candidates
(START.md §10); P7 is one chain-lead agent. Do not escalate before P7 (R0). Ask me only for what only I can
supply (START.md §9); decide everything else and tell me what you decided.
```
