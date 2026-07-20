from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import SecurityAlert


def create_alert(
    db: Session,
    *,
    severity: str,
    source: str,
    title: str,
    message: str,
    target: str = "",
    dedupe_minutes: int = 15,
) -> SecurityAlert:
    since = datetime.utcnow() - timedelta(minutes=dedupe_minutes)
    existing = db.query(SecurityAlert).filter(
        SecurityAlert.source == source,
        SecurityAlert.title == title,
        SecurityAlert.target == target,
        SecurityAlert.created_at >= since,
    ).first()
    if existing:
        return existing
    alert = SecurityAlert(
        severity=severity,
        source=source,
        title=title[:160],
        message=message,
        target=target[:255],
    )
    db.add(alert)
    return alert
