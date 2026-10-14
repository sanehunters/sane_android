# prompts/ — copy-paste blocks for a Claude Code session

Start `claude` in the methodology checkout (Claude Opus 5.5 by default, Opus 5 as the fallback — see
`00-bootstrap.md`), fill the `<<< >>>` slots and paste. Each prompt makes the model read `START.md` first;
nothing else needs explaining.

| Prompt | Use |
|---|---|
| `00-bootstrap.md` | a fresh session, a new target |
| `01-resume.md` | continue an engagement folder that already exists |
| `02-single-domain.md` | work exactly one domain this session |
| `03-triage-reply.md` | answer a programme's pushback on a finding |
| `04-retest.md` | verify a fix on a new build |
| `05-fanout-multi-agent.md` | breadth via `/breadth-phase`, then `/verify-candidates`; the worker contract and the merge |
| `06-report-assembly.md` | produce the final report and submissions |
| `07-lab-practice.md` | run the methodology against a deliberately vulnerable lab app |
