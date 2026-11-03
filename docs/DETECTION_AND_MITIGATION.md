# Detection and mitigation playbook

| Scenario | Detection signal | Mitigation | Verification |
|---|---|---|---|
| BOLA | `access_denied` for actor/target mismatch | Object-level authorization | Cross-account GET returns 403 |
| Mass assignment | `mass_assignment_blocked` with rejected fields | Explicit allowlist and schema validation | PATCH with `role` returns 422 |
| Rate-limit bypass | `rate_limit_exceeded` on repeated login attempts | Enforce limit on server-observed identity | Fourth request returns 429 |

## Analyst workflow
1. Record request path, authenticated principal, target resource and server-side client identity.
2. Group failed logins in a 60-second window, checking distributed traffic and NAT false positives.
3. Inspect authorization denials and forbidden field attempts, but do not treat a single signal as proof of compromise.
4. Reproduce each finding only in the local lab using `python scripts/demo.py`.
5. Confirm hardened behavior through regression tests.

## Important caveat
The vulnerable mode logs some actions for comparison, but does not constitute a SIEM. Events are in-memory and are lost on restart. There is no production logging, tracing or alert dispatch.
