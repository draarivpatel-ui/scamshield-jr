# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/scamshield-jr/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname, real health information or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| latest `main` | Supported |

Security fixes are applied to the latest state of the default branch.

## Scope

This policy covers the static ScamShield Jr browser application, including pasted-message analysis, drill content, tactic explanations, local persistence, offline behavior and browser rendering.

In scope:

- A cross-site scripting or HTML injection path through pasted messages, drill content, detector output, stored state or rendered explanations.
- A service worker, cache-control or static-file flaw that serves attacker-controlled application code across an update.
- A detector, serialization or share-output flaw that bypasses validation, corrupts another message analysis, or executes attacker-controlled code.
- A report, copy or export flaw that makes generated output execute a formula or script when opened.
- A privacy boundary flaw that sends pasted message content off the device when the application is presented as offline.

Out of scope:

- Browser vulnerabilities, operating system compromise or physical access to the machine.
- Damage caused by modified copies of the static application that do not come from this repository.
- The documented inability of the offline prototype to inspect live links, prove sender control or certify a message as safe, unless a report shows a specific validation or output integrity failure.

## Coordinated disclosure

- Acknowledgment: within 3 business days.
- Initial triage: within 14 calendar days.
- Fix or mitigation target: within 90 calendar days for confirmed reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
