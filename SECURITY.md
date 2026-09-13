# Responsible Use

This repository is a **penetration-testing methodology** for authorised engagements. It contains no
exploits and no client data.

## Authorisation is not optional

Every technique here is legal only against a target you are authorised to test. Before Phase 1 of any
engagement, one of these must be true and on file:

| Context | Permits |
|---|---|
| Your own app, or your employer's | Full assessment |
| A signed statement of work | Per contract |
| A public bug bounty programme | In-scope assets only; programme rules bind |
| A vendor VDP (Google, Samsung, OEM) | Per programme. **No third-party user data.** |
| A deliberately vulnerable lab app | Anything |

## Hard limits, regardless of authorisation

- Never test accounts or data you do not own. Cross-account testing uses **two tester-owned accounts**.
- No denial of service against production.
- No automated scanning of production without written permission.
- Minimise traffic. You are a guest on their infrastructure.
- Never exfiltrate a third party's data, even to prove a point. Use planted canary values.
- Report what you find to the owner. Do not disclose publicly outside the programme's terms.

## Practice targets

Learn on these, never on production: OVAA, InsecureShop, InjuredAndroid, DIVA, Damn Vulnerable Bank,
InsecureBankv2, Vuldroid, the OWASP MAS Crackmes, and the Mobile Hacking Lab free labs.

## Reporting an issue in this repository

If a checklist item here is wrong, dangerous or out of date, open a
[Checklist gap](https://github.com/sanehunters/sane_android/issues/new?template=04-checklist-gap.yml)
issue. Corrections are more valuable than additions.
