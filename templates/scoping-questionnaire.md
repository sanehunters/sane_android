# Scoping & Rules of Engagement

> Complete **before** Phase 1. Every blank here is a day lost later.

## Target
- [ ] Package name(s), including flavours and white-labels
- [ ] Distribution: Play / App Bundle splits / sideload / enterprise / regional variants
- [ ] Will we get the **full APK set** (base + config splits)? Miss a split, miss code and native libs
- [ ] Build track to test: production, or a staging build? (a debug build invalidates several checks)
- [ ] `minSdkVersion` and `targetSdkVersion`
- [ ] Cross-platform framework in use (React Native / Flutter / Cordova / Unity / Xamarin / native)
- [ ] Does the app use **OTA code delivery** (expo-updates, CodePush, custom updater)? If yes, we must
      analyse the on-device bundle, not the APK

## Backend
- [ ] API hosts in scope, and any explicitly excluded
- [ ] Staging environment available? (strongly preferred for destructive tests)
- [ ] Rate limits or WAF that will interfere, and whether we can be allow-listed
- [ ] GraphQL / gRPC / REST / WebSocket

## Accounts and data
- [ ] **Two tester-owned accounts minimum** — required for cross-account IDOR
- [ ] Accounts at each privilege level (user, premium, admin, merchant...)
- [ ] KYC / verification state pre-completed, or a route to complete it
- [ ] Payment sandbox and test instruments
- [ ] OTP delivery route the tester can actually receive
- [ ] Seed data we may modify or destroy

## Rules of engagement
- [ ] Attacker models in scope (AM-01 … AM-12)
- [ ] Is physical-access testing in scope?
- [ ] Is social engineering of staff in scope? (default: no)
- [ ] Automated scanning permitted? Against which hosts?
- [ ] Testing window, timezone, and any freeze periods
- [ ] Emergency contact for production impact
- [ ] Disclosure terms and report retention

## Deliverables
- [ ] Report format and deadline
- [ ] Video PoC required for every dynamic finding (default: yes, see PoC standard)
- [ ] Retest window and what it covers
- [ ] Who receives the report, and how it is transmitted securely

## Authorisation
- [ ] Signed authorisation naming the packages and hosts, held on file before Phase 1 begins
