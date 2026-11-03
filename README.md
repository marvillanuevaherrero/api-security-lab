# API Security Lab — Vulnerabilities, Detection and Mitigation

A reproducible, localhost-only Python laboratory demonstrating three common API security failures and their hardened counterparts. The project includes a FastAPI application, deterministic in-process attack demonstrations, security-event instrumentation, regression tests, Docker Compose, and CI.

## Scope

| Scenario | Vulnerable behavior | Hardened behavior | OWASP API Security |
|---|---|---|---|
| Broken object-level authorization | Any authenticated user can read/update another profile | Per-object ownership checks | API1:2023 BOLA |
| Mass assignment | Client-controlled fields can overwrite `role` | Strict field allowlist | API3:2023 Broken Object Property Level Authorization |
| Rate-limit bypass | Trusts spoofed `X-Forwarded-For` and does not enforce threshold | Uses server-observed client identity and enforces a request budget | API4:2023 Unrestricted Resource Consumption |

These scenarios are local educational examples, not exploitation tooling for third-party APIs.

## Architecture

```text
HTTP requests -> FastAPI routes -> Authentication / authorization
                                 -> In-memory state + security events
                                 -> Vulnerable OR hardened controls
scripts/demo.py -> TestClient -> both modes -> status-code comparison
pytest -> security regression tests -> GitHub Actions
```

## Quick start (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python scripts/demo.py
python -m pytest -q
```

The demo runs **in-process** and does not open any network listener. It compares the two modes and prints JSON containing the status codes of each test.

## Local HTTP lab

```powershell
$env:LAB_MODE = "hardened"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Browse to `http://127.0.0.1:8000/docs` for the OpenAPI interface. To intentionally demonstrate vulnerable behavior, stop the server, set `$env:LAB_MODE = "vulnerable"`, and restart. **Never expose vulnerable mode beyond localhost.**

## Docker Compose

```bash
docker compose up --build
```

The default is hardened mode. To run vulnerable mode for local study, set `LAB_MODE=vulnerable` in a local `.env` file (not committed). Docker Compose publishes port 8000 only on `127.0.0.1`, drops Linux capabilities and enables a read-only root filesystem. Container restrictions reduce exposure but are not a guarantee of isolation.

## Example request

```bash
curl -s http://127.0.0.1:8000/health
```

Demo users: `alice / alice-demo` and `bob / bob-demo`. These credentials are intentionally public and must never be reused.

## Security instrumentation

The app records `login_failed`, `login_success`, `authentication_failed`, `access_denied`, `mass_assignment_blocked`, `rate_limit_exceeded`, `profile_read`, and `profile_updated` in a bounded in-memory buffer. These events demonstrate detection signals; they are **not** durable audit logs. The intentionally vulnerable mode exposes a lab-only `/events` route to inspect them; hardened mode denies access.

## Testing and CI

`python -m pytest -q` verifies vulnerable and hardened behavior for all three scenarios, authentication, legitimate updates, and event exposure. GitHub Actions runs the tests and demonstration script on pushes and pull requests. This repository does not claim cloud deployment, production authentication, or an external DAST scan.

## Repository structure

```text
app/                    API routes and in-memory state
scripts/demo.py         In-process demonstration
tests/                  Security regression tests
docs/                   Threat model and detection playbook
.github/workflows/      Continuous integration
Dockerfile              Non-root application image
compose.yaml            Localhost-only container configuration
pyproject.toml          Package metadata and dependencies
```

## Limitations

The hardened mode is a teaching reference, not production-ready authentication. Tokens have no expiration, passwords are demo plaintext, the rate limiter is in-memory and per-process, and IP-based limiting can penalize users behind NAT. See `docs/THREAT_MODEL.md` for security assumptions and `docs/DETECTION_AND_MITIGATION.md` for analyst workflow.

## Responsible use

Use only on your own machine or explicitly authorized lab infrastructure. No real accounts, customer data, or third-party endpoints are needed.

## License

MIT — see `LICENSE`.

---

Por Mar Villanueva Herrero
