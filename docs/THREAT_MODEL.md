# Threat model and scope

## Assets
In-memory demo user profiles, authentication tokens, and audit events.

## Trust boundaries
Client-supplied JSON and HTTP headers must not determine authorization or trusted client identity.

## Scenarios
- **BOLA / broken object-level authorization:** a logged-in user reads another user's profile in vulnerable mode. Hardened mode enforces ownership.
- **Mass assignment:** vulnerable mode copies arbitrary JSON fields onto the user record. Hardened mode only permits `display_name`.
- **Rate-limit bypass:** vulnerable mode trusts client-supplied `X-Forwarded-For` and has no effective rate-limit enforcement. Hardened mode enforces a small per-client request budget based on server-observed peer IP.

## Limits
This is a deterministic educational demonstration, not a production auth service. The hardened mode uses in-memory tokens, demo passwords, and per-process rate limiting; it is not suitable for production. A production deployment needs a trusted reverse-proxy model, durable/distributed rate limiting, secure identity provider, password hashing, HTTPS, token expiry, and robust audit storage.

## Safety
Never bind the intentionally vulnerable API to a public interface. The Docker Compose host binding is localhost-only. No real user data or secrets should be supplied. The demonstration script calls the application in-process without network access.
