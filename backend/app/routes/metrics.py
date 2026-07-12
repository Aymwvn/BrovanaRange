from fastapi import APIRouter, Depends, Header, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
from sqlalchemy.orm import Session
from app.core.config import settings
from app.database import get_db
from app.models import AntiCheatEvent, AuditLog, LabSession, Submission, User

router = APIRouter(tags=["metrics"])

@router.get("/metrics")
def metrics(db: Session = Depends(get_db), authorization: str | None = Header(default=None)):
    if settings.PROMETHEUS_METRICS_TOKEN and authorization != f"Bearer {settings.PROMETHEUS_METRICS_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    registry = CollectorRegistry()
    Gauge("redrange_users_total", "Registered users", registry=registry).set(db.query(User).count())
    Gauge("redrange_active_users_total", "Active users", registry=registry).set(db.query(User).filter(User.is_active == True).count())
    Gauge("redrange_lab_sessions_running", "Running lab sessions", registry=registry).set(db.query(LabSession).filter(LabSession.status == "running").count())
    Gauge("redrange_lab_sessions_expired", "Expired lab sessions", registry=registry).set(db.query(LabSession).filter(LabSession.status == "expired").count())
    Gauge("redrange_submissions_total", "Flag submissions", registry=registry).set(db.query(Submission).count())
    Gauge("redrange_correct_submissions_total", "Correct flag submissions", registry=registry).set(db.query(Submission).filter(Submission.correct == True).count())
    Gauge("redrange_anti_cheat_events_total", "Anti-cheat events", registry=registry).set(db.query(AntiCheatEvent).count())
    Gauge("redrange_audit_logs_total", "Audit log rows", registry=registry).set(db.query(AuditLog).count())
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
