# Formal PFE Section — Implementation of a Secure Cyber Range Platform

The implemented platform provides a controlled environment for offensive security training. It allows authenticated users to start isolated vulnerable machines, interact with them through a browser-based command interface, submit captured flags, and receive score updates. The system follows a layered architecture composed of a React frontend, a FastAPI backend, a PostgreSQL database, and Docker-based lab environments.

The frontend provides the user interface for registration, authentication, dashboard visualization, lab selection, terminal interaction, flag submission, and ranking. The backend exposes REST API endpoints for authentication, lab orchestration, score management, and command execution. PostgreSQL stores users, labs, active sessions, submissions, and audit-related information.

The most important security design choice is the use of per-user ephemeral Docker containers. When a student starts a lab, the backend creates a new container dedicated only to that user. This container is attached to a user-specific Docker network and is configured with CPU, memory, and process limits. Linux capabilities are dropped and the no-new-privileges security option is enabled to reduce the risk of privilege escalation beyond the intended lab environment.

The first implemented laboratory is a Linux privilege escalation scenario named Linux Privilege Escalation. The vulnerable configuration allows the low-privileged student user to execute Vim as root through sudo without a password. The expected exploitation path requires the learner to enumerate sudo permissions, abuse Vim shell escape functionality, obtain a root shell, and read the protected flag file located in the root directory.

The platform validates flags server-side only. The original flag is not stored in plaintext inside the database; instead, the backend stores a password-style hash. When a user submits a flag, the backend verifies it against the stored hash. If the submission is correct and the user has not already solved the lab, the platform updates the user's score.

From a security perspective, the platform addresses multiple threats including container escape, horizontal access between users, denial of service, unauthorized access to lab sessions, and backend API abuse. These risks are mitigated through container isolation, strict ownership checks on sessions, resource limits, authentication, authorization, input validation, and automatic lab expiration.
