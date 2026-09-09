# Security Policy

## Supported versions

Only the latest tagged release and the current `main` branch receive security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting for this repository, or contact the designated security owner through the organization's approved private channel. Include affected versions, reproduction steps, impact, and suggested remediation. Do not include live credentials or customer scan data.

## Response targets

| Severity | Triage | Remediation target |
| --- | --- | --- |
| Critical, exploited, or credential exposure | 4 hours | 24 hours |
| High | 1 business day | 7 days |
| Medium | 3 business days | 30 days |
| Low | 10 business days | 90 days |

Secrets are rotated immediately. An incident review must identify root cause, affected releases, customer impact, and a preventive control. Security fixes require tests and the same CI gates as normal changes; emergency releases may expedite review but may not bypass the required security gate.
