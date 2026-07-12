# RedRange v4 Security Model

## Platform Security

RedRange separates the frontend, backend, database, Docker control plane, and user lab networks. The backend does not receive a raw Docker socket. It communicates through a restricted Docker socket proxy. The backend container runs as a non-root user with a read-only filesystem.

## Lab Isolation

Each lab session is created in a private Docker bridge network identified by the user id. The network is internal to prevent outbound abuse. Each lab has memory, CPU, and PID limits and no host bind mounts.

Lab containers use the configured Docker runtime from `LAB_CONTAINER_RUNTIME`. The secure default is `runsc`, which means lab processes run inside a gVisor userspace kernel instead of directly on the host kernel syscall surface. If `runsc` is configured but unavailable, lab startup fails closed. Privilege-escalation labs can use `runc` so controlled sudo/setuid behavior works for the intended exercise.

## Privilege Escalation Lab Exception

Privilege escalation labs intentionally allow controlled sudo behavior inside the container. For this reason, `no-new-privileges` is not used on these specific lab containers. Instead, the container is still isolated by namespaces, cgroups, private networking, no host mounts, resource limits, and limited Linux capabilities.

## Authentication Security

Passwords are hashed using Argon2. Password policy requires at least 10 characters and mixed character classes. Login/register endpoints are rate-limited and repeated login failures temporarily lock the account. Access tokens are short-lived JWTs and refresh tokens are stored hashed with revocation support.

## Flag Security

Flags are generated per user session, written inside the user's lab container, and stored only as hashes in the database. Submitted flags are redacted before storage.

## Admin Security

Admin endpoints require the `admin` role. Admin can view sessions, container metadata, runtime state, anti-cheat events, and audit logs. Admin can create, disable, and delete labs. All important actions are logged.

## Sandbox Orchestration

The backend is the only component allowed to create lab containers. It reaches Docker through a restricted socket proxy and applies a runtime policy before container creation:

```txt
default: runsc
allowed fallback: runc only when ALLOW_UNSANDBOXED_LABS=true
```

Runtime, expiry, user id, and lab slug are written as Docker labels for later inspection and cleanup.
