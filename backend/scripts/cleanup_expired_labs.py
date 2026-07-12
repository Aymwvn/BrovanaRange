from datetime import datetime
from app.database import SessionLocal
from app.models import AuditLog, LabSession
from app.services.docker_manager import docker_manager

def main() -> int:
    db = SessionLocal()
    try:
        expired = db.query(LabSession).filter(
            LabSession.status == "running",
            LabSession.expires_at < datetime.utcnow(),
        ).all()
        cleaned = docker_manager.cleanup_expired(expired)
        for session in expired:
            session.status = "expired"
            session.stopped_at = datetime.utcnow()
        orphaned = docker_manager.cleanup_orphaned_labs()
        db.add(AuditLog(action="AUTOMATION_CLEANUP_EXPIRED", detail=f"sessions={cleaned}, orphaned={orphaned}"))
        db.commit()
        print(f"cleaned_sessions={cleaned} orphaned_containers={orphaned}")
        return 0
    finally:
        db.close()

if __name__ == "__main__":
    raise SystemExit(main())
