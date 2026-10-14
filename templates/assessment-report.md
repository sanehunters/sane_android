# Assessment Report Template

> The client-facing deliverable. Findings alone are not a report. Copy to `final/assessment-report.md` in the
> engagement; references below name files in the methodology repo in plain text because relative links do not
> survive the copy. Delete every blockquote before delivery.

## 1. Executive summary
> Non-technical. What is the business risk, what should be fixed first, and what is the overall posture.
> Three paragraphs maximum. No jargon, no tool names.

## 2. Scope & method
- Package(s), versionName/versionCode, build track, date pulled
- Build fingerprints and API levels tested
- Attacker models in scope (docs/05 attacker models, methodology repo)
- Explicitly out of scope, and why
- Accounts and test data provided
- Anything that blocked coverage, and its effect

## 3. Findings
> Severity-ordered, Critical first. One section per finding, using the finding template
> (templates/finding-report.md in the methodology repo → findings/F-NNN/report.md here).

| ID | Title | Severity | Attacker model | Status |
|---|---|---|---|---|

## 4. Attack-surface inventory
> Everything enumerated, whether or not it produced a finding. This is what the client cannot generate
> themselves and is often the most reused part of the report.

- Exported activities / services / receivers / providers, with permissions
- Deep-link and App Link hosts, and their verification state
- WebViews, their settings, and every bridge method
- ContentProvider authorities and `FileProvider` roots
- Endpoint map extracted from the binary
- Third-party SDKs and versions (SBOM)
- Permissions requested, and which are used

## 5. Ruled out
> The ruled-out register in full (templates/ruled-out-table.md shape; rows from checklist-status.csv `result=ruled-out`).

## 6. Remediation plan
> Prioritised, with effort estimates and concrete patches. Group systemic causes rather than listing
> twenty instances of one mistake.

## 7. Retest
> What will be retested, when, and against which build.

## Appendix A — Coverage crosswalk
> Which MASTG/MASVS/MITRE items were covered — docs/07 coverage crosswalk (methodology repo) plus `scripts/coverage.py` output.

## Appendix B — Tooling and versions
## Appendix C — Evidence index
