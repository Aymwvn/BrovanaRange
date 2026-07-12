from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models import AntiCheatEvent, Submission

FAST_SOLVE_WINDOW = timedelta(seconds=45)
RAPID_SOLVE_WINDOW = timedelta(minutes=3)

def record_event(db: Session, *, user_id: int | None, lab_id: int | None, ip: str, reason: str, detail: str, severity: str = "medium"):
    db.add(AntiCheatEvent(user_id=user_id, lab_id=lab_id, ip=ip, reason=reason, detail=detail, severity=severity))

def evaluate_submission(db: Session, *, user_id: int, lab_id: int, ip: str, submitted_flag: str, correct: bool, session_started_at: datetime | None) -> tuple[bool, str]:
    reasons: list[str] = []
    now = datetime.utcnow()
    if correct and session_started_at and now - session_started_at < FAST_SOLVE_WINDOW:
        reasons.append("solve_too_fast")
        record_event(db, user_id=user_id, lab_id=lab_id, ip=ip, reason="solve_too_fast", detail="Correct flag submitted unusually soon after lab start.", severity="high")

    recent_correct = db.query(Submission).filter(
        Submission.user_id == user_id,
        Submission.correct == True,
        Submission.created_at >= now - RAPID_SOLVE_WINDOW,
    ).count()
    if correct and recent_correct >= 3:
        reasons.append("multiple_solves_too_fast")
        record_event(db, user_id=user_id, lab_id=lab_id, ip=ip, reason="multiple_solves_too_fast", detail=f"{recent_correct + 1} correct solves within {RAPID_SOLVE_WINDOW}.", severity="high")

    ip_users = db.query(func.count(func.distinct(Submission.user_id))).filter(
        Submission.ip == ip,
        Submission.created_at >= now - timedelta(hours=2),
    ).scalar() or 0
    if ip and ip_users >= 3:
        reasons.append("suspicious_ip_usage")
        record_event(db, user_id=user_id, lab_id=lab_id, ip=ip, reason="suspicious_ip_usage", detail=f"IP has recent submissions from {ip_users} users.", severity="medium")

    if correct:
        same_lab_correct = db.query(Submission).filter(
            Submission.lab_id == lab_id,
            Submission.correct == True,
            Submission.user_id != user_id,
        ).count()
        if same_lab_correct > 0:
            reasons.append("flag_reuse_pattern")
            record_event(db, user_id=user_id, lab_id=lab_id, ip=ip, reason="flag_reuse_pattern", detail="Another user has already solved the same dynamic lab; monitor for shared flags.", severity="low")

    return bool(reasons), ",".join(reasons)
