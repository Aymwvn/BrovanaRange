# Security Architecture

Full breakdown of security controls implemented in BrovanaRange, organized by layer.

## 1. Network Security

- HTTPS/TLS access through Nginx (self-signed cert for local dev)
- HTTP (80) redirects to HTTPS (443)
- Frontend (5173), backend (8000), and database (5432) ports never exposed directly
- UFW firewall enabled, default-deny inbound, only required ports allowed
- Docker network segmentation: frontend/DMZ, backend/internal, database, Docker control, and per-user lab networks all separated
- Attack surface reduction verified with Nmap scans

## 2. Reverse Proxy Security

- Nginx handles all public access; backend reached only through `/api`
- WebSocket terminal proxied through Nginx, TLS terminated at Nginx
- Internal Docker service names used instead of public ports — backend/database never directly reachable by public users

## 3. Container Security

- Each lab session runs in its own isolated, per-user Docker container
- Containers are temporary, auto-expiring, and auto-cleaned
- No host folders mounted into lab containers; Docker socket never mounted directly into backend (restricted socket proxy used instead)
- Hardening: `no-new-privileges`, dropped Linux capabilities by default (limited grants only for privesc labs), CPU/RAM/PID limits
- gVisor (runsc) sandboxing supported; `runc` reserved for labs that require it
- Lab containers network-isolated from database/backend networks unless intentionally connected

## 4. Application Security

**Authentication & Sessions**
- JWT access tokens + rotating refresh tokens
- Logout and logout-all (revokes all active sessions)
- Token versioning for session invalidation

**Password & MFA**
- Argon2 password hashing (legacy bcrypt verification supported)
- Strong password policy, email verification, password reset token flow
- TOTP MFA and email OTP challenge support
- Temporary lockout after failed login attempts

**Authorization & API**
- Rate limiting on login/registration
- Protected API routes, users scoped to their own lab sessions
- WebSocket terminal ownership verification
- RBAC with admin-only APIs, admin account seeded from environment variables
- Controlled CORS origins, schema-based input validation
- Server-side, per-session flag validation — flags hashed before validation, redacted in storage

## 5. Rate Limiting

Applied to login, registration, lab start, and flag submission — mitigating brute-force attacks, automated flag guessing, API abuse, resource exhaustion, and lab creation spam.

## 6. Security Headers

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

## 7. Database Security

- PostgreSQL isolated in its own Docker network, no public ports, reachable only by backend
- Passwords, refresh tokens, one-time tokens, and email OTPs stored as hashes; submitted flags stored redacted
- Separate tables for users, labs, sessions, submissions, audit logs, anti-cheat events
- ORM-based access — no raw SQL string building

## 8. Lab Security

- Dynamic, session-bound flags with lifecycle timeout controls
- Backend controls container lifecycle; authenticated WebSocket terminal access with ownership verification
- Expired sessions auto-rejected, crashed sessions tracked
- Vulnerable exercises isolated by category (privesc, web injection, forensics)

## 9. Monitoring and Logging

**Audit Logging** — login success/failure, registration, password reset, session refresh/revoke, lab start/stop/expiration, flag submissions, admin activity

**Admin Visibility** — audit log viewer, active session viewer, container runtime visibility

**Metrics** — Prometheus-compatible `/metrics` endpoint tracking users, active users, running/expired sessions, submissions, anti-cheat events, audit log counts

## 10. Anti-Cheat System

- Fast solve detection, rapid solve burst detection
- Suspicious IP reuse and cross-user flag reuse detection
- Events stored in DB, surfaced on an admin anti-cheat dashboard
- Suspicious submissions auto-flagged

## 11. IDS and Network Monitoring

**Suricata** — Dockerized, monitors the lab network interface, EVE JSON + fast.log alerting, custom ICMP/HTTPS detection rules, deployed passively to avoid disrupting Docker networking

**Zeek** — Dockerized, generates connection, DNS, DHCP, and anomaly ("weird") logs

**Planned**: IPS-style automatic blocking

## 12. Deployment Security

- Secrets via environment variables, `.env.example` template provided
- Backend validates JWT secret strength at startup, fails to boot on a weak secret
- Backend runs as non-root (dedicated `redrange` user)
- Frontend served through Nginx container, Docker Compose for service separation
- Database health checks configured

## 13. Access Control

- Anonymous users cannot list/start labs, submit flags, view scoreboard, or open terminal sessions
- Normal users cannot access admin APIs or touch another user's lab/terminal
- Subscription-aware active lab limits
- Admins manage labs, users, subscriptions, active sessions, and expired lab cleanup

## 14. Future Security Improvements

- Trusted public TLS certificates
- Automatic IPS blocking
- SIEM integration and centralized logging dashboards
- Kubernetes network policies / cloud security groups
- WAF deployment
- Advanced Suricata Emerging Threats rulesets
- Automated vulnerability scanning pipeline
- Backup and disaster recovery
- Dedicated secrets manager
- Production-grade email delivery
- Multi-host lab isolation
- Firecracker/Kata microVM isolation
- Full performance and load testing

## Conclusion

BrovanaRange integrates container isolation, network segmentation, authentication hardening, monitoring, IDS deployment, and access control enforcement into a defense-in-depth architecture — built for cybersecurity education, secure lab deployment, and future enterprise-scale expansion.
