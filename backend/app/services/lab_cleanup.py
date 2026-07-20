from datetime import datetime

from sqlalchemy.orm import Session

from app.models import AuditLog, LabSession
from app.services.alerts import create_alert
from app.services.docker_manager import docker_manager


def cleanup_expired_sessions(db: Session, *, actor: str = "system", admin_user_id: int | None = None) -> dict:
    expired = db.query(LabSession).filter(LabSession.status == "running", LabSession.expires_at < datetime.utcnow()).all()
    count = docker_manager.cleanup_expired(expired)
    for session in expired:
        session.status = "expired"
        session.stopped_at = datetime.utcnow()
    orphaned = docker_manager.cleanup_orphaned_labs()
    if len(expired) and count < len(expired):
        create_alert(
            db,
            severity="high",
            source="lab",
            title="Expired lab cleanup incomplete",
            message=f"Cleanup found {len(expired)} expired sessions but removed {count} containers.",
            target="lab-cleanup",
        )
    if orphaned:
        create_alert(
            db,
            severity="medium",
            source="lab",
            title="Orphaned lab containers removed",
            message=f"Automatic cleanup removed {orphaned} orphaned or exited lab containers.",
            target="lab-cleanup",
        )
    db.add(AuditLog(user_id=admin_user_id, action="ADMIN_CLEANUP_EXPIRED" if admin_user_id else "AUTO_CLEANUP_EXPIRED", detail=f"actor={actor}, sessions={count}, orphaned={orphaned}"))
    db.commit()
    return {"cleaned": count, "orphaned": orphaned}
