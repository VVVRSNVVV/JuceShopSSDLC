# Secure Release Checklist — JuiceShopSSDLC

This checklist must be completed before tagging a release or deploying a new version of JuiceShopSSDLC.

Each item can be marked as:

- ✅ Done
- ⚠️ N/A (not applicable, must be justified)
- ❌ Blocker (release must not proceed)

---

## 1. Code & Tests

- [ ] All unit tests pass (`npm test` / equivalent).
- [ ] Linting passes (ESLint / TypeScript checks).
- [ ] No debug code or temporary test routes remain.

---

## 2. Static Application Security Testing (SAST)

- [ ] Semgrep scan passes with **no Critical or High** findings.  
  - Command: `semgrep scan --config p/owasp-top-ten .`
- [ ] CodeQL workflow in GitHub Actions is green.
- [ ] All SAST-related GitHub Issues labeled `security` + `severity:critical|high` are closed or explicitly accepted with documented justification.

---

## 3. Secret Scanning

- [ ] Gitleaks pipeline passes with **0 captured secrets**.
- [ ] No secrets present in Git history for the release commit (or they were rotated).
- [ ] `.env.*` files are excluded from Git via `.gitignore`.

---

## 4. Dependency & Supply Chain Security

- [ ] `npm audit` (or equivalent) runs clean from Critical/High issues, or they are triaged with clear justification.
- [ ] Dependabot (or other) alerts are reviewed; no open Critical alerts for this repo.
- [ ] Package-lock / pnpm-lock is committed and up to date.

---

## 5. Dynamic Application Security Testing (DAST)

- [ ] OWASP ZAP baseline scan executed against the current build.  
- [ ] No new Critical/High findings introduced compared to previous release.
- [ ] All exploitable issues discovered in DAST are tracked as GitHub Issues.

---

## 6. Configuration & Environment

- [ ] Production configuration uses `.env.production` (not development values).
- [ ] Application runs behind HTTPS in the target environment.
- [ ] Security headers middleware is enabled (Helmet/CSP, HSTS where applicable).
- [ ] Docker image runs as non-root user and exposes only required ports.

---

## 7. Logging & Monitoring

- [ ] Audit logging is enabled for authentication and admin actions.
- [ ] Logs do not contain passwords, full tokens or other sensitive data.
- [ ] Log retention and access controls are configured.

---

## 8. Documentation

- [ ] `docs/security/threat-model.md` is updated for major new features.
- [ ] `docs/security/security-requirements.md` reflects the current state.
- [ ] Any security-relevant configuration changes are documented.

---

## 9. Final Approval

- [ ] All checklist items above are ✅ or ⚠️ with justification.
- [ ] Release owner confirms that there are **no known Critical/High unresolved issues**.
- [ ] Version is tagged and release notes include a brief “Security” section.

> **Release Owner:**  
> Name: `__________`  
> Date: `__________`  
> Signature (or GitHub handle): `__________`

---
