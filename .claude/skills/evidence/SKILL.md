---
name: evidence
description: Produce the evidence tree and the seven-beat PoC video for a confirmed finding (phase 8).
---

# /evidence F-0NN

Follow `docs/04-poc-and-evidence-standard.md`: one continuous take, device identity in frame, ground truth from the legitimate app, attacker identity, **negative control in the same take**, the legitimate flow, the granted scope from the platform's own API, the exploit and the delta; a planted canary visible in both ground truth and exploit output. Evidence tree per START.md §6 (`logs/`, `screenshots/`, `pocs/F-0NN/` source only, `videos/F-0NN.mp4` under 5 MB). Run the reviewer checklist in docs/04 §9 before marking the finding evidence-complete. Never reconstruct a video for something you did not execute.
