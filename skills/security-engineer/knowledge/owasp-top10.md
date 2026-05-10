# OWASP Top 10 (2021) — Quick Reference

## A01 Broken Access Control
- Elevation of privilege, missing function-level access control, IDOR
- Fix: deny-by-default, enforce on server, log failures, invalidate tokens on logout

## A02 Cryptographic Failures
- Weak algorithms (MD5, SHA-1, DES), cleartext data, missing TLS, hard-coded keys
- Fix: AES-256-GCM, bcrypt/argon2 for passwords, TLS 1.2+, secrets in vaults

## A03 Injection
- SQL, NoSQL, LDAP, OS command, template injection
- Fix: parameterised queries, input validation, least-privilege DB accounts, WAF

## A04 Insecure Design
- Missing threat model, insecure design patterns, no security requirements
- Fix: threat modelling (STRIDE), secure design principles, abuse cases in user stories

## A05 Security Misconfiguration
- Default credentials, verbose errors, open cloud buckets, unnecessary features enabled
- Fix: hardening guides, IaC scanning (Checkov, tfsec), remove default accounts

## A06 Vulnerable and Outdated Components
- Known CVEs in dependencies, unmaintained libraries
- Fix: SCA tools (Dependabot, Snyk), SBOM, vendor security advisories

## A07 Identification and Authentication Failures
- Weak passwords, missing MFA, insecure session tokens, credential stuffing
- Fix: MFA, rate limiting on login, secure password reset, short-lived JWTs

## A08 Software and Data Integrity Failures
- Insecure CI/CD, unsigned packages, auto-update without integrity check
- Fix: sign releases, verify checksums, pin dependencies, secure pipeline

## A09 Security Logging and Monitoring Failures
- No audit trail, alerts not firing, logs not protected
- Fix: structured logging, SIEM, alert on repeated failures, protect log integrity

## A10 Server-Side Request Forgery (SSRF)
- Agent calls internal metadata endpoints or internal services via attacker-supplied URL
- Fix: allowlist outbound URLs, block private IP ranges, disable redirects
