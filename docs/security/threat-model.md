1. Introduction
This document describes the Threat Model for the OWASP Juice Shop–based project used to practice Secure Software Development Lifecycle (SSDLC). Juice Shop is intentionally vulnerable, making it ideal for analyzing real-world security risks, identifying threats, and designing mitigations following best practices (STRIDE, DREAD, OWASP ASVS).

2. System Overview
The application is a vulnerable e-commerce platform consisting of:
	•	Frontend: Angular SPA
	•	Backend: Node.js / Express
	•	Database: SQLite (default) or PostgreSQL
	•	Authentication: JSON Web Tokens (JWT)
	•	APIs: REST API
	•	File storage: Local filesystem (/ftp, /logs, /encryptionkeys, /uploads)

3. Architecture Diagram (DFD)
     User → Browser (Angular SPA)
        ↓
     Express API → Database (SQLite/Postgres)
        ↓
      File System (/ftp, /logs, /encryptionkeys)
  Trust Boundaries:
  	•	User ↔ Browser
	  •	Browser ↔ Backend API
	  •	Backend ↔ Database
	  •	Backend ↔ Filesystem (sensitive zone)
4. Assets
     Asset / Description
     User Accounts / Email, password hash, profile information
     JWT Tokens / Used for authentication and authorization
     Product Catalog / Inventory, descriptions, prices
     Orders / Purchase records connected to user accounts
     Logs / Operational logs, may contain sensitive data
     Encryption Keys / Private key for JWT signing
     File System Data / Files in /ftp, /logs, /encryptionkeys, /uploads
     Admin Functions / Privileged management endpoints
5. Threat Actors
     Actor / Capabilities / Goal
     Anonymous Attacker / Medium / Exploit vulnerabilities, extract data
     Registered User / Medium / Privilege escalation, access other data
     Insider (Developer/Admin) / High / Access logs, encryption keys, admin functionality
     Automated Bots / High / DoS attacks, brute-force authentication
6. Assumptions
     •Attackers have full access to the frontend source code.
	  •	APIs are publicly reachable over the internet.
	  •	No WAF or rate limiting is initially applied.
	  •	Source code is public (open-source project).
	  •	Database uses default Juice Shop configuration.
	  •	Backend has filesystem access for logs, keys, FTP directory.
7. Attack Surface

    External Attack Surface
    	•	Login / Registration / Password reset
    	•	Product search endpoint
    	•	User profile API
    	•	Feedback & comment forms
    	•	File download endpoints (/ftp/...)
    	•	Redirect endpoint
    	•	Upload functionality
    	•	Chatbot API
    	•	Admin panel endpoints
    
    Internal Attack Surface
    	•	Sequelize ORM raw queries
    	•	Hardcoded JWT secret
    	•	eval() usage
    	•	Path traversal-enabled endpoints
    	•	Directory listing middleware (serveIndex)
    	•	File system write locations
8. Threat Analysis (STRIDE)
   Spoofing
    | Threat                | Description                                 | File / Evidence      |
| --------------------- | ------------------------------------------- | -------------------- |
| JWT token forging     | Hardcoded private key allows forging tokens | `lib/insecurity.ts`  |
| Login bypass via SQLi | Raw SQL queries allow credential spoofing   | `routes/login.ts`    |
| Weak reset logic      | Attackers can impersonate users             | Password reset flows |

   Tampering
     | Threat         | Description                                    | Evidence                     |
| -------------- | ---------------------------------------------- | ---------------------------- |
| SQL Injection  | DB modification through string concatenation   | Multiple `sequelize.query()` |
| XSS            | Inject arbitrary JS to modify UI/logic         | Feedback / comment forms     |
| Path Traversal | Modify or access files outside intended folder | `routes/fileServer.ts`       |

   Repudiation
      Logs can be accessed or deleted due to directory listing & traversal.
      No tamper-evident audit trail.
   
  Information Disclosure
    | Threat                 | Description                            | Evidence                           |
| ---------------------- | -------------------------------------- | ---------------------------------- |
| Directory listing      | Sensitive files exposed                | `/ftp`, `/logs`, `/encryptionkeys` |
| Private key disclosure | JWT private key in repo                | `lib/insecurity.ts`                |
| Verbose errors         | Stack traces leak internal system info | Express default handler            |

  Denial of Service
      No rate limiting → brute force possible.
      Heavy DB search queries → SQLite freeze.
      Unrestricted file uploads → disk exhaustion.
      
  Elevation of Privilege

      Stealing admin JWT via XSS → full takeover.
      Forging admin token via leaked key.
      Missing RBAC → users access other users' data.
      
9. Risk Rating (DREAD)
   DREAD Scoring Table
       | Threat               | D  | R  | E  | A  | D  | Total | Severity |
| -------------------- | -- | -- | -- | -- | -- | ----- | -------- |
| SQL Injection        | 10 | 10 | 10 | 9  | 10 | 49    | Critical |
| Hardcoded JWT Secret | 10 | 10 | 10 | 10 | 10 | 50    | Critical |
| XSS                  | 9  | 9  | 9  | 8  | 9  | 44    | High     |
| Path Traversal       | 9  | 9  | 8  | 8  | 8  | 42    | High     |
| Directory Listing    | 7  | 8  | 7  | 7  | 7  | 36    | Medium   |
| Verbose Errors       | 5  | 6  | 5  | 6  | 6  | 28    | Medium   |

10. Mitigation Plan
    Mitigation Matrix
    | Threat                | Recommended Mitigation                                |
| --------------------- | ----------------------------------------------------- |
| SQL Injection         | Use ORM parameter binding, avoid string concatenation |
| Hardcoded JWT secret  | Move secret to env vars or secret manager             |
| XSS                   | Sanitize inputs (DOMPurify), escape output, add CSP   |
| Path Traversal        | Sanitize filenames, restrict allowed paths            |
| Directory Listing     | Remove `serveIndex`, lock down directories            |
| Broken Access Control | Implement server-side RBAC/ABAC                       |
| Verbose Errors        | Disable stack traces in production                    |
| DoS (bruteforce)      | Add rate limiting, validate file uploads              |

11. Security Requirements (SR)
    Security Controls
| ID    | Requirement                                        |
| ----- | -------------------------------------------------- |
| SR-01 | DB queries must use parameterized ORM queries      |
| SR-02 | JWT signing keys must not be stored in source code |
| SR-03 | Disable directory listing everywhere               |
| SR-04 | Apply server-side input validation & sanitization  |
| SR-05 | Hide internal details in error messages            |
| SR-06 | Apply rate limiting to authentication endpoints    |
| SR-07 | Enforce robust RBAC/ABAC in backend                |
| SR-08 | Validate upload file types and size                |
| SR-09 | Restrict access to logs, keys, FTP folders         |
| SR-10 | Implement CSRF & XSS protection mechanisms         |

12. Future Work / Open Issues
  Integrate SAST (Semgrep, CodeQL) in CI/CD
  Add DAST scanning (OWASP ZAP Baseline)
  Harden Docker container (non-root, read-only FS)
  Add dependency scanning (npm audit, Snyk)
  Implement secure logging + monitoring
  Add security headers (CSP, HSTS, X-Frame-Options)
  Integrate secret scanning (Gitleaks)
  Develop incident response workflow













