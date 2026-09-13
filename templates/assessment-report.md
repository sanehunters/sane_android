# Assessment Report Template

> The client-facing deliverable. Findings alone are not a report.

## 1. Executive summary
> Non-technical. What is the business risk, what should be fixed first, and what is the overall posture.
> Three paragraphs maximum. No jargon, no tool names.

## 2. Scope & method
- Package(s), versionName/versionCode, build track, date pulled
- Build fingerprints and API levels tested
- Attacker models in scope (see [attacker models](../docs/05-attacker-models.md))
- Explicitly out of scope, and why
- Accounts and test data provided
- Anything that blocked coverage, and its effect

## 3. Findings
> Severity-ordered, Critical first. One section per finding, using
> [`finding-report.md`](finding-report.md).

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
> [`ruled-out-table.md`](ruled-out-table.md) in full.

## 6. Remediation plan
> Prioritised, with effort estimates and concrete patches. Group systemic causes rather than listing
> twenty instances of one mistake.

## 7. Retest
> What will be retested, when, and against which build.

## Appendix A — Coverage crosswalk
> Which MASTG/MASVS/MITRE items were covered — see [`docs/07-coverage-crosswalk.md`](../docs/07-coverage-crosswalk.md).

## Appendix B — Tooling and versions
## Appendix C — Evidence index
