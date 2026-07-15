from datetime import datetime, timedelta
import json
import secrets
import docker
from docker.errors import NotFound
from app.core.config import settings

client = docker.DockerClient(base_url=settings.DOCKER_HOST)
api = docker.APIClient(base_url=settings.DOCKER_HOST)

PRIVESC_LABS = {"linux-privilege-escalation", "forensic-skeleton"}

class DockerLabManager:
    def runtime_name(self, lab_runtime: str | None = None, *, allow_unsandboxed: bool = False) -> str:
        runtime = (lab_runtime or settings.LAB_CONTAINER_RUNTIME or "runsc").strip()
        if runtime == "runc" and not (settings.ALLOW_UNSANDBOXED_LABS or allow_unsandboxed):
            return "runsc"
        return runtime

    def runtime_available(self, runtime: str) -> bool:
        try:
            info = client.info()
            return runtime in (info.get("Runtimes") or {})
        except Exception:
            return False

    def orchestrator_status(self) -> dict:
        info = client.info()
        runtimes = sorted((info.get("Runtimes") or {}).keys())
        default_runtime = info.get("DefaultRuntime", "unknown")
        configured_runtime = self.runtime_name()
        return {
            "docker_id": info.get("ID", ""),
            "server_version": info.get("ServerVersion", ""),
            "default_runtime": default_runtime,
            "configured_lab_runtime": configured_runtime,
            "available_runtimes": runtimes,
            "runsc_available": "runsc" in runtimes,
            "sandbox_enforced": configured_runtime == "runsc",
        }

    def ensure_user_network(self, user_id: int):
        name = f"{settings.DOCKER_LAB_NETWORK_PREFIX}_{user_id}"
        try:
            return client.networks.get(name)
        except NotFound:
            return client.networks.create(name, driver="bridge", internal=True, labels={"redrange": "user-lab", "user_id": str(user_id)})

    def generate_flag(self, *, lab_slug: str, user_id: int) -> str:
        token = secrets.token_hex(8)
        clean_slug = lab_slug.replace("-", "_").upper()
        return f"REDRANGE{{{clean_slug}_U{user_id}_{token}}}"

    def is_running(self, container_id: str) -> bool:
        try:
            container = client.containers.get(container_id); container.reload()
            return container.status == "running"
        except NotFound:
            return False

    def start_lab(self, *, user_id: int, lab_slug: str, image: str, flag: str, sandbox_runtime: str | None = None) -> dict:
        self.ensure_user_network(user_id)
        name = f"redrange_u{user_id}_{lab_slug}_{int(datetime.utcnow().timestamp())}"
        is_privesc = lab_slug in PRIVESC_LABS
        runtime = self.runtime_name(sandbox_runtime, allow_unsandboxed=is_privesc)
        if runtime == "runsc" and not self.runtime_available("runsc"):
            raise RuntimeError("Sandbox runtime runsc is not available on this Docker host")
        security_opt = [] if is_privesc else ["no-new-privileges:true"]
        cap_add = ["SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE"] if is_privesc else []
        expires = datetime.utcnow() + timedelta(minutes=settings.LAB_TIMEOUT_MINUTES)
        container = client.containers.run(
            image=image,
            name=name,
            command=["/bin/bash", "-lc", "sleep infinity"],
            detach=True,
            hostname="target",
            network=f"{settings.DOCKER_LAB_NETWORK_PREFIX}_{user_id}",
            mem_limit=settings.LAB_MEMORY_LIMIT,
            nano_cpus=settings.LAB_CPU_NANOS,
            pids_limit=settings.LAB_PIDS_LIMIT,
            runtime=runtime,
            cap_drop=["ALL"],
            cap_add=cap_add,
            security_opt=security_opt,
            read_only=False,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=64m", "/run": "rw,nosuid,size=32m"},
            volumes={},
            labels={"redrange": "lab", "user_id": str(user_id), "lab": lab_slug, "managed_by": "redrange-api", "expires_at": expires.isoformat(), "sandbox_runtime": runtime},
        )
        container.reload()
        if container.status != "running":
            logs = container.logs().decode(errors="replace")[-1000:]
            raise RuntimeError(f"Lab container failed to stay running: {logs}")
        safe_flag = flag.replace("'", "")
        flag_path = '/flag.txt' if lab_slug == 'web-injection' else '/root/flag.txt'
        perms = '644' if lab_slug == 'web-injection' else '600'
        result = container.exec_run(["/bin/bash", "-lc", f"echo '{safe_flag}' > {flag_path} && chmod {perms} {flag_path}"], user="root")
        if result.exit_code != 0:
            raise RuntimeError(result.output.decode(errors="replace"))
        return {"container_id": container.id, "container_name": name, "expires_at": expires, "connection_info": f"Hardened WebSocket terminal connected to isolated {runtime} container {name}"}

    def stop_lab(self, container_id: str):
        try:
            container = client.containers.get(container_id)
            container.stop(timeout=5); container.remove(force=True)
        except NotFound:
            return False
        return True

    def open_tty_socket(self, container_id: str):
        if not self.is_running(container_id):
            raise RuntimeError("Lab container is not running. Stop the lab and start it again.")
        exec_id = api.exec_create(container=container_id, cmd=["/bin/bash", "-li"], stdin=True, stdout=True, stderr=True, tty=True, user="student", workdir="/home/student", environment={"TERM":"xterm-256color", "HOME":"/home/student"})["Id"]
        sock = api.exec_start(exec_id, tty=True, stream=False, socket=True)
        raw = getattr(sock, "_sock", sock)
        try: raw.settimeout(0.25)
        except Exception: pass
        return raw

    def inspect_container(self, container_id: str) -> dict:
        c = client.containers.get(container_id); c.reload()
        stats = c.stats(stream=False)
        inspect = api.inspect_container(container_id)
        host_config = inspect.get("HostConfig", {})
        return {"id": c.id[:12], "name": c.name, "status": c.status, "image": c.image.tags, "labels": c.labels, "runtime": host_config.get("Runtime", c.labels.get("sandbox_runtime", "")), "network_mode": host_config.get("NetworkMode", ""), "memory_bytes": stats.get("memory_stats", {}).get("usage", 0), "pids": stats.get("pids_stats", {}).get("current", 0)}

    def cleanup_expired(self, sessions):
        count = 0
        for s in sessions:
            if self.stop_lab(s.container_id): count += 1
        return count

    def cleanup_orphaned_labs(self) -> int:
        count = 0
        now = datetime.utcnow()
        for container in client.containers.list(all=True, filters={"label": "redrange=lab"}):
            labels = container.labels or {}
            expires_at = labels.get("expires_at")
            try:
                expired = bool(expires_at and datetime.fromisoformat(expires_at) < now)
            except ValueError:
                expired = False
            if expired or container.status in {"exited", "dead"}:
                try:
                    container.remove(force=True)
                    count += 1
                except NotFound:
                    pass
        return count

    def read_honeypot_events(self, *, tail: int = 500) -> list[dict]:
        try:
            container = client.containers.get(settings.HONEYPOT_CONTAINER_NAME)
        except NotFound:
            return []
        raw_logs = container.logs(tail=tail).decode("utf-8", "replace").splitlines()
        events = []
        for line in raw_logs:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "honeypot_request":
                events.append(event)
        return events

docker_manager = DockerLabManager()
