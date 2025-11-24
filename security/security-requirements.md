# Security Requirements for JuiceShopSSDLC

This document defines mandatory security requirements that MUST be respected during development, testing, deployment, and maintenance of the project.

These requirements are based on:
- OWASP ASVS v4.0
- OWASP Top 10:2021
- JuiceShop known vulnerability set
- Internal SSDLC procedures

---

# 1. Authentication & Authorization
1.1 Passwords MUST be hashed using bcrypt or Argon2.  
1.2 Hard-coded credentials MUST NOT exist in the codebase.  
1.3 JWT secrets MUST NOT be stored in source code; only environment variables are allowed.  
1.4 JWT tokens MUST use:
- HS256 or RS256
- expiry ≤ 6h  

1.5 Endpoints MUST validate user roles (RBAC).

---

# 2. Data Validation & Sanitization
2.1 Raw SQL queries are FORBIDDEN.  
Only parameterized Sequelize queries are allowed.

2.2 Any user-controlled input MUST be validated on:
- client,
- server,
- ORM layer.

2.3 Blacklist-based validation is forbidden. Only allowlist validation is allowed.

2.4 All HTML output MUST be sanitized using DOMPurify or equivalent.

---

# 3. Access Control (IDOR Protection)
3.1 Every resource request MUST check object ownership.  
3.2 ID-based access MUST NOT rely solely on user input.

---

# 4. Logging & Monitoring
4.1 Logs MUST NOT contain:
- passwords  
- tokens  
- secrets  
- sensitive PII  

4.2 Application MUST log:
- failed login attempts  
- access to restricted endpoints  
- administrative actions

4.3 Logs MUST NOT be accessible through public endpoints.

---

# 5. Cryptography
5.1 Only Node.js crypto or approved libraries are allowed.  
MD5, SHA1, Base64-encoding-as-"crypto" are forbidden.

5.2 Encryption keys MUST NOT be stored in the repo.

---

# 6. Error Handling
6.1 API MUST NOT expose stack traces to the user.  
6.2 Client-visible errors MUST be generic.

---

# 7. Security Headers
7.1 Application MUST apply at least:
- Content-Security-Policy  
- X-Frame-Options  
- X-XSS-Protection  
- Strict-Transport-Security  
- Referrer-Policy  

---

# 8. Dependency Management
8.1 `npm audit` MUST show zero critical vulnerabilities.  
8.2 Dependencies MUST be updated monthly.

---

# 9. Infrastructure & Deployment
9.1 Only HTTPS with TLS 1.2+ allowed.  
9.2 Environment variables MUST be used for sensitive configuration.  
9.3 Docker images MUST NOT run as root.  
9.4 Production build MUST NOT contain development tools.

---

# 10. DevSecOps / CI/CD Requirements
10.1 Each PR MUST pass SAST (Semgrep).  
10.2 Critical/High SAST findings MUST block the merge.  
10.3 Every push to `main` MUST run OWASP ZAP DAST.  
10.4 DAST High/Critical MUST block deployment.  
10.5 CI MUST prevent pushing secrets to repository.

---

# 11. Forbidden Patterns in Code
The following are strictly prohibited:
- eval()  
- new Function()  
- exec()  
- raw SQL  
- dynamic require()  
- user-provided paths in file operations  
- hard-coded tokens, passwords, secrets  

---

# 12. Security Testing Requirements
12.1 Unit tests MUST cover security-related functions.  
12.2 Manual penetration testing MUST be performed each release.  
12.3 QA MUST test against the OWASP Top 10 checklist.

---

# 13. Documentation Requirements
13.1 Any new API endpoint MUST include:
- authentication rules  
- authorization rules  
- input validation rules  

13.2 All security changes MUST be documented in CHANGELOG.
