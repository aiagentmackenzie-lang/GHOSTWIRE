# Security Policy

## Reporting a Vulnerability

GHOSTWIRE is a network forensics tool. If you find a security issue in
GHOSTWIRE itself (not a detection gap in the threat corpus), report it
responsibly:

- **Email:** aiagent.mackenzie@gmail.com
- **Do not** open a public GitHub issue for security-sensitive bugs.
- Include a minimal reproduction (input that triggers the issue, expected
  vs. actual behavior, environment).

We will acknowledge within **5 business days** and aim to ship a fix within
**30 days** for high-severity issues. Coordinated disclosure is fine — we
credit reporters in the changelog unless you ask us not to.

## Scope

In scope:
- Authentication bypass, path traversal, or injection in the API server
  (`server/`).
- The engine (`engine/`) mishandling a capture such that it crashes the
  process in a way that could be exploited (denial-of-service via crafted
  PCAP), or writes outside its intended output paths.
- Hardcoded secrets or credentials in the repository.

Out of scope (please file a normal issue, not a security report):
- False positives / false negatives in detection rules.
- Performance on pathologically large captures (we document the cap; see
  README "Limits").
- Theoretical timing attacks without a concrete PoC.

## Threat model note

GHOSTWIRE is designed to run on an operator's machine against captures the
operator controls. The API server binds loopback by default and refuses to
bind a non-loopback host without `GHOSTWIRE_API_KEY`. Operators who expose
the server to a network are responsible for transport-layer protection
(reverse proxy with TLS) and key management.