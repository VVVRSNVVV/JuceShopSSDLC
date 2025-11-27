# Security Requirements — JuiceShopSSDLC

## 1. Overview and Scope

This document defines security requirements for the JuiceShopSSDLC project — a deliberately vulnerable Juice Shop application, extended with a Secure Software Development Life Cycle (SSDLC).

The goal is **not** to remove every single vulnerability from the original OWASP Juice Shop, but to:
- demonstrate **secure design and implementation** on selected parts of the system;
- show how to **integrate security controls** into the development and deployment process;
- provide **documentation** that reflects a real-world SSDLC approach.

Where possible, requirements are aligned with **OWASP ASVS Level 1–2** and **OWASP Top 10 (2021)**.

---

## 2. Protected Assets

| ID  | Asset                            | Description                                           |
|-----|----------------------------------|--------------------------------------------------------|
| A1  | User accounts & credentials      | Email, password, reset tokens, OAuth tokens           |
| A2  | Authentication sessions / JWT    | Access tokens, refresh tokens                         |
| A3  | Application configuration        | Secrets, API keys, encryption keys, .env              |
| A4  | Product & order data             | Products, reviews, baskets, addresses                 |
| A5  | Logs and audit trail             | Security and application logs                         |
| A6  | Source code & CI/CD pipeline     | GitHub repo, workflows, security configs              |

---

## 3. Assumptions and Out-of-Scope

- Project is deployed in a **lab / educational environment**, not in production.
- Some legacy OWASP Juice Shop challenges may remain intentionally vulnerable.
- Requirements below apply **primarily to new/modified code** in the SSDLC fork.

---

## 4. Authentication & Session Management

**SR-AUTH-1** — Password storage  
- Passwords **MUST** be stored only as salted, slow hashes (e.g. bcrypt, argon2).  
- Plaintext or reversible encryption is forbidden.

**SR-AUTH-2** — Login  
- Login endpoints **MUST** enforce rate limiting (e.g. max 5 attempts / min / IP).  
- Login responses **MUST NOT** reveal whether email exists.

**SR-AUTH-3** — Sessions / JWT  
- JWT **MUST** be signed with a strong asymmetric key (RSA/ECDSA).  
- Keys **MUST NOT** be hard-coded in source code.  
- Token lifetime **SHOULD** be ≤ 6h for access tokens.

**SR-AUTH-4** — Password reset  
- Reset tokens must be single-use, time-limited, and unguessable.

---

## 5. Authorization & Access Control

**SR-AUTHZ-1** — Enforce authorization on server side  
- Every sensitive route **MUST** check user identity and role on the server.  
- Relying on client-side checks alone is forbidden.

**SR-AUTHZ-2** — Least privilege  
- Admin routes **MUST** be accessible only to users with explicit admin role.  
- Technical routes (`/ftp`, `/logs`, `/encryptionkeys`, etc.) **MUST NOT** be exposed to regular users.

**SR-AUTHZ-3** — IDOR protection  
- Access to resources by ID (orders, profiles, baskets) **MUST** verify ownership.

---

## 6. Input Validation & Output Encoding

**SR-INPUT-1** — Central validation layer  
- All external input (HTTP body, query, params, headers, filenames) **MUST** pass through a central validation layer (e.g. Zod/Joi schema).

**SR-INPUT-2** — SQL Injection prevention  
- Dynamic SQL concatenation with user data is forbidden.  
- Only parameterized queries or ORM methods may be used.

**SR-INPUT-3** — XSS prevention  
- User-controlled HTML **MUST** be sanitized before rendering (DOMPurify or equivalent).  
- Output encoding **MUST** be applied in templates (Angular/Handlebars bindings).

**SR-INPUT-4** — File upload validation  
- Only whitelisted MIME types and extensions allowed.  
- File size must be limited.  
- Filenames must be normalized and randomized.

---

## 7. Data Protection & Secrets Management

**SR-DATA-1** — Secrets handling  
- JWT keys, DB passwords, API keys **MUST** be stored in environment variables or a secrets store.  
- Secrets **MUST NOT** be committed to Git.

**SR-DATA-2** — Transport security  
- Application **MUST** be accessible only via HTTPS in production.  
- HSTS **SHOULD** be enabled for production deployments.

**SR-DATA-3** — Backups  
- If backups are configured, they must be stored encrypted and access-controlled.

---

## 8. Logging, Monitoring & Auditing

**SR-LOG-1** — Security event logging  
- The following events **MUST** be logged: authentication success/failure, admin actions, file downloads/uploads, configuration changes.

**SR-LOG-2** — No sensitive data in logs  
- Passwords, full credit card numbers, full JWT tokens **MUST NOT** be written to logs.

**SR-LOG-3** — Audit trail integrity  
- Audit logs **SHOULD** be stored in an append-only location or with integrity protections (e.g. hashing, external log sink).

---

## 9. Error Handling

**SR-ERR-1** — Generic messages for users  
- Users must not see stack traces or SQL errors.  
- Only generic error messages are returned (e.g. “Something went wrong”).

**SR-ERR-2** — Detailed errors in logs  
- Full stack traces **MUST** be logged on the server side only.

---

## 10. Dependency & Supply Chain Security

**SR-DEP-1** — Dependency scanning  
- `npm audit` and/or a third-party scanner (Dependabot, Snyk) **MUST** be enabled.  

**SR-DEP-2** — Update policy  
- Critical/high vulnerabilities in dependencies must be fixed within defined SLA (see Vulnerability Management document).

---

## 11. CI/CD & Security Testing

**SR-CI-1** — Mandatory security checks in CI  
- The CI pipeline **MUST** run:
  - unit + integration tests  
  - SAST (Semgrep, CodeQL)  
  - secret scanning (Gitleaks)  
  - dependency scanning  

**SR-CI-2** — Blocking failures  
- Builds **MUST FAIL** when critical security checks fail (configurable per severity).

---

## 12. Operational Security

**SR-OPS-1** — Environment separation  
- Separate configuration for development and production (`.env.development`, `.env.production`).  

**SR-OPS-2** — Least privilege for runtime  
- Docker container must not run as root.  
- Network exposure should be minimal (only required ports).

---
