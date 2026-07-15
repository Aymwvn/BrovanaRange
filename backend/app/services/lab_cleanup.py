from datetime import datetime

from sqlalchemy.orm import Session

from app.models import AuditLog, LabSession
from app.services.docker_manager import docker_manager


def cleanup_expired_sessions(db: Session, *, actor: str = "system", admin_user_id: int | None = None) -> dict:
    expired = db.query(LabSession).filter(LabSession.status == "running", LabSession.expires_at < datetime.utcnow()).all()
    count = docker_manager.cleanup_expired(expired)
    for session in expired:
        session.status = "expired"
        session.stopped_at = datetime.utcnow()
    orphaned = docker_manager.cleanup_orphaned_labs()
    db.add(AuditLog(user_id=admin_user_id, action="ADMIN_CLEANUP_EXPIRED" if admin_user_id else "AUTO_CLEANUP_EXPIRED", detail=f"actor={actor}, sessions={count}, orphaned={orphaned}"))
    db.commit()
    return {"cleaned": count, "orphaned": orphaned}
