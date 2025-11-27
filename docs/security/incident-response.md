# Incident Response Plan — JuiceShopSSDLC

## 1. Goals

Even though JuiceShopSSDLC is an educational project, we treat security incidents as if this were a production system in order to practice real-world processes.

Goals:
- Detect security incidents quickly.
- Limit damage (containment).
- Restore normal operation.
- Learn from each incident and improve SSDLC.

---

## 2. What Is a Security Incident?

For this project, a **security incident** is any event that:

- compromises A1–A6 assets (user data, secrets, config, source code), or  
- abuses the CI/CD pipeline, or  
- exploits a vulnerability that should have been mitigated.

Examples:
- Exposed JWT secret or API key in a public repo.
- Successful SQL Injection used to dump DB contents.
- Unauthorized admin access to the application.
- Malicious code committed to the repository.

---

## 3. Roles (for a small project)

- **Incident Owner** — main person responsible for handling the incident (usually repo maintainer).
- **Security Reviewer** — helps with analysis and recommendations.
- **Reporter** — person or tool that discovered the incident.

In a real company, these roles map to: Incident Commander, Security Engineer, Product Owner, etc.

---

## 4. Severity Levels for Incidents

| Level | Description                                            |
|-------|--------------------------------------------------------|
| SEV-1 | Critical compromise (keys leaked, RCE, massive data)   |
| SEV-2 | Significant unauthorized access or data exposure       |
| SEV-3 | Limited/localized issue, no major impact               |
| SEV-4 | Suspicious activity / near miss, no confirmed impact   |

---

## 5. Incident Handling Phases

### 5.1 Preparation

- Security documentation is stored in `docs/security/*`.
- All secrets are in environment variables, not in Git.
- Logging is enabled for authentication and admin actions.
- Tools (Semgrep, CodeQL, Gitleaks) are integrated into CI.

### 5.2 Identification

Steps:

1. Person or tool detects suspicious behavior.
2. Create a GitHub Issue with label `incident` + severity label (`sev-1`…`sev-4`).
3. Document:
   - what happened,
   - when it was detected,
   - which systems are involved,
   - initial evidence (logs, screenshots, alerts).

### 5.3 Containment

For confirmed incidents:

- Revoke compromised credentials (tokens, keys, passwords).
- Temporarily disable vulnerable functionality (feature flag, route, or service).
- Limit access to affected systems (firewall rules, access removal).

### 5.4 Eradication

- Identify root cause (vulnerable code, misconfiguration, weak credential).
- Implement a fix:
  - code patch,
  - config change,
  - dependency update.
- Ensure that malicious artifacts (backdoors, modified files) are removed.

### 5.5 Recovery

- Re-deploy fixed version of the application.
- Restore services and monitoring.
- Ensure that scanners (SAST/DAST/secret scanning) are passing again.

### 5.6 Lessons Learned

Within a few days of the incident:

- Add a short **post-mortem** as a comment to the incident issue:
  - Summary of incident (timeline, impact).
  - Root cause.
  - What worked and what did not.
  - Actions to avoid similar issues in the future.

---

## 6. Communication Template (Issue Comment)

> **Incident Summary**  
> - Date/time detected:  
> - Reporter:  
> - Systems affected:  
> - Severity: SEV-x  
>
> **Impact**  
> - Data affected:  
> - Users affected:  
>
> **Root Cause**  
> - …  
>
> **Mitigation & Fix**  
> - …  
>
> **Follow-up Actions**  
> - [ ] Add test / rule  
> - [ ] Update documentation  
> - [ ] Improve monitoring  

---

## 7. Relationship to SSDLC

- Incidents should feed back into **Threat Modeling** (new threats)  
- and into **Security Requirements** (new requirements),
- and into **testing** (new SAST rules, regression tests).

---
