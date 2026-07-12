# RedRange Sandbox Orchestrator

This design runs every lab as a short-lived Docker container controlled by the backend API. The secure default runtime is `runsc` from gVisor.

## Runtime Policy

```txt
student request -> FastAPI -> Docker SDK -> Docker socket proxy -> Docker daemon -> runsc sandboxed lab
```

The backend uses `LAB_CONTAINER_RUNTIME=runsc` by default. If an admin selects `runc` for a normal lab, the backend still forces `runsc` unless `ALLOW_UNSANDBOXED_LABS=true`. Privilege-escalation labs are an explicit exception because sudo/setuid behavior must work inside the controlled lab container.

## API Surface

Student APIs:

```txt
GET  /labs
POST /labs/{lab_id}/start
POST /labs/{lab_id}/stop
POST /labs/{lab_id}/submit-flag
WS   /labs/sessions/{session_id}/ws
```

Admin APIs:

```txt
GET    /admin/orchestrator/status
GET    /admin/sessions
GET    /admin/labs
POST   /admin/labs
PATCH  /admin/labs/{lab_id}
DELETE /admin/labs/{lab_id}
POST   /admin/cleanup-expired
```

`/admin/orchestrator/status` returns Docker version, default runtime, configured lab runtime, available runtimes, and whether `runsc` is available.

## Container Security Controls

Every lab container receives:

```txt
runtime=runsc
private per-user internal bridge network
mem_limit from LAB_MEMORY_LIMIT
nano_cpus from LAB_CPU_NANOS
pids_limit from LAB_PIDS_LIMIT
cap_drop=["ALL"]
tmpfs for /tmp and /run
no host bind mounts
expiry label
sandbox_runtime label
```

Privilege-escalation labs can add only the specific Linux capabilities required for the exercise. Non-privesc labs use `no-new-privileges`.

## Deployment Structure

Host:

```txt
Docker Engine
gVisor runsc runtime
Docker daemon runtimes config
```

Compose stack:

```txt
frontend        -> static React UI served by Nginx
backend         -> FastAPI orchestrator/API
db              -> PostgreSQL
docker proxy    -> restricted Docker API access
lab containers  -> created dynamically with runsc
```

## Linux Runtime Check

Verify Docker sees `runsc`:

```bash
docker info | grep -A5 Runtimes
docker run --rm --runtime=runsc alpine uname -a
```

Verify RedRange sees it:

```bash
curl -H "Authorization: Bearer <admin_access_token>" \
  http://localhost:8000/admin/orchestrator/status
```

Verify a running lab uses gVisor:

```bash
docker inspect <lab_container_id> --format '{{.HostConfig.Runtime}}'
```

Expected output:

```txt
runsc
```

## Failure Behavior

If `LAB_CONTAINER_RUNTIME=runsc` and Docker does not expose `runsc`, lab startup fails closed with:

```txt
Sandbox runtime runsc is not available on this Docker host
```

This prevents accidentally running vulnerable labs without the configured sandbox.
