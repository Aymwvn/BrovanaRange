from datetime import datetime
import hashlib
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AntiCheatEvent, AuditLog, BlockedIpWatchlist, HoneypotEvent, Lab, LabSession, Submission, Subscription, User
from app.core.security import require_admin
from app.schemas import AntiCheatOut, AuditOut, BlockedIpWatchlistOut, HoneypotEventOut, IpReputationOut, LabCreate, LabOut, LabUpdate, SubscriptionOut, SubscriptionUpdate, UserAdminOut, UserAdminUpdate
from app.services.docker_manager import docker_manager
from app.services.lab_cleanup import cleanup_expired_sessions
from app.services.threat_intel import get_ip_reputation

router = APIRouter(prefix="/admin", tags=["admin"])

SUSPICIOUS_HONEYPOT_PATHS = {
    "/admin",
    "/login",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/server-status",
}

def classify_honeypot(path: str) -> tuple[str, str]:
    clean_path = path if path.startswith("/") else f"/{path}"
    if clean_path in SUSPICIOUS_HONEYPOT_PATHS:
        return "high", "sensitive_path_probe"
    if any(part in clean_path.lower() for part in ("wp-", "phpmyadmin", ".env", ".git", "admin")):
        return "medium", "common_scanner_probe"
    return "low", "decoy_request"

def parse_honeypot_time(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return datetime.utcnow()

def event_hash(event: dict) -> str:
    key = "|".join([
        str(event.get("timestamp", "")),
        str(event.get("source_ip", "")),
        str(event.get("method", "")),
        str(event.get("path", "")),
        str(event.get("query", "")),
        str(event.get("user_agent", "")),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def ingest_honeypot_events(db: Session) -> int:
    created = 0
    for raw in docker_manager.read_honeypot_events():
        source_ip = str(raw.get("source_ip", ""))[:64]
        path = str(raw.get("path", ""))[:255]
        seen_at = parse_honeypot_time(raw.get("timestamp"))
        fingerprint = event_hash(raw)
        existing = db.query(HoneypotEvent).filter_by(event_hash=fingerprint).first()
        if existing:
            existing.last_seen_at = max(existing.last_seen_at, seen_at)
            continue
        severity, reason = classify_honeypot(path)
        db.add(HoneypotEvent(
            event_hash=fingerprint,
            source_ip=source_ip,
            method=str(raw.get("method", ""))[:16],
            path=path,
            query=str(raw.get("query", ""))[:2000],
            user_agent=str(raw.get("user_agent", ""))[:512],
            content_type=str(raw.get("content_type", ""))[:120],
            content_length=int(raw.get("content_length") or 0),
            severity=severity,
            reason=reason,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
        ))
        if severity in {"medium", "high"}:
            db.add(AuditLog(action="HONEYPOT_SUSPICIOUS_HIT", target=source_ip, detail=f"{raw.get('method', '')} {path}"))
        created += 1
    db.commit()
    return created

@router.get("/sessions")
def active_sessions(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sessions = db.query(LabSession).filter(LabSession.status == "running").order_by(LabSession.started_at.desc()).all()
    output = []
    for s in sessions:
        item = {
            "id": s.id,
            "user_id": s.user_id,
            "lab_id": s.lab_id,
            "container_name": s.container_name,
            "started_at": s.started_at,
            "expires_at": s.expires_at,
            "status": s.status,
        }
        try:
            item["container"] = docker_manager.inspect_container(s.container_id)
        except Exception as exc:
            item["container_error"] = str(exc)
        output.append(item)
    return output

@router.post("/sessions/{session_id}/stop")
def stop_session(session_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    session = db.query(LabSession).filter_by(id=session_id).first()
    if not session:
        raise HTTPException(404, "Session not found")
    stopped = docker_manager.stop_lab(session.container_id)
    session.status = "stopped"
    session.stopped_at = datetime.utcnow()
    db.add(AuditLog(user_id=admin.id, action="ADMIN_SESSION_STOPPED", target=session.container_name, detail=f"session_id={session.id}, docker_removed={stopped}"))
    db.commit()
    return {"message": "Session stopped", "docker_removed": stopped}

@router.get("/orchestrator/status")
def orchestrator_status(admin: User = Depends(require_admin)):
    return docker_manager.orchestrator_status()

@router.get("/audit", response_model=list[AuditOut])
def audit_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()

@router.get("/users", response_model=list[UserAdminOut])
def users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).order_by(User.created_at.desc()).limit(200).all()

@router.patch("/users/{user_id}", response_model=UserAdminOut)
def update_user(user_id: int, payload: UserAdminUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        from fastapi import HTTPException
        raise HTTPException(404, "User not found")
    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(user, key, value)
    db.add(AuditLog(user_id=admin.id, action="ADMIN_USER_UPDATED", target=str(user_id), detail=str(data)))
    db.commit(); db.refresh(user)
    return user

@router.get("/labs", response_model=list[LabOut])
def all_labs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(Lab).order_by(Lab.id.asc()).all()

@router.post("/labs", response_model=LabOut)
def create_lab(payload: LabCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    data = payload.model_dump()
    data["slug"] = data["slug"].strip().lower()
    data["title"] = data["title"].strip()
    data["category"] = data["category"].strip()
    data["difficulty"] = data["difficulty"].strip()
    data["description"] = data["description"].strip()
    data["docker_image"] = data["docker_image"].strip()
    exists = db.query(Lab).filter_by(slug=data["slug"]).first()
    if exists:
        raise HTTPException(409, "Lab slug already exists")
    lab = Lab(flag_hash="", **data)
    db.add(lab)
    db.add(AuditLog(user_id=admin.id, action="ADMIN_LAB_CREATED", target=data["slug"], detail=data["title"]))
    db.commit(); db.refresh(lab)
    return lab

@router.patch("/labs/{lab_id}", response_model=LabOut)
def update_lab(lab_id: int, payload: LabUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    lab = db.query(Lab).filter_by(id=lab_id).first()
    if not lab:
        raise HTTPException(404, "Lab not found")
    data = payload.model_dump(exclude_unset=True)
    if "slug" in data:
        data["slug"] = data["slug"].strip().lower()
        duplicate = db.query(Lab).filter(Lab.slug == data["slug"], Lab.id != lab_id).first()
        if duplicate:
            raise HTTPException(409, "Lab slug already exists")
    for key in ("title", "category", "difficulty", "description", "docker_image"):
        if key in data and isinstance(data[key], str):
            data[key] = data[key].strip()
    for key, value in data.items():
        setattr(lab, key, value)
    db.add(AuditLog(user_id=admin.id, action="ADMIN_LAB_UPDATED", target=str(lab_id), detail=str(data)))
    db.commit(); db.refresh(lab)
    return lab

@router.delete("/labs/{lab_id}")
def delete_lab(lab_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    lab = db.query(Lab).filter_by(id=lab_id).first()
    if not lab:
        raise HTTPException(404, "Lab not found")
    running = db.query(LabSession).filter_by(lab_id=lab_id, status="running").all()
    stopped = 0
    for session in running:
        if docker_manager.stop_lab(session.container_id):
            stopped += 1
        session.status = "stopped"
        session.stopped_at = datetime.utcnow()
    has_history = db.query(LabSession).filter_by(lab_id=lab_id).first() or db.query(Submission).filter_by(lab_id=lab_id).first()
    if has_history:
        lab.is_active = False
        db.add(AuditLog(user_id=admin.id, action="ADMIN_LAB_DELETED", target=lab.slug, detail=f"soft_deleted=true, stopped_sessions={stopped}"))
        message = "Lab disabled because it has historical sessions or submissions"
    else:
        slug = lab.slug
        db.delete(lab)
        db.add(AuditLog(user_id=admin.id, action="ADMIN_LAB_DELETED", target=slug, detail=f"hard_deleted=true, stopped_sessions={stopped}"))
        message = "Lab deleted"
    db.commit()
    return {"message": message, "stopped_sessions": stopped}

@router.get("/subscriptions", response_model=list[SubscriptionOut])
def subscriptions(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(Subscription).order_by(Subscription.created_at.desc()).limit(200).all()

@router.put("/users/{user_id}/subscription", response_model=SubscriptionOut)
def upsert_subscription(user_id: int, payload: SubscriptionUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        from fastapi import HTTPException
        raise HTTPException(404, "User not found")
    sub = db.query(Subscription).filter_by(user_id=user_id).first()
    if not sub:
        sub = Subscription(user_id=user_id)
        db.add(sub)
    for key, value in payload.model_dump().items():
        setattr(sub, key, value)
    db.add(AuditLog(user_id=admin.id, action="ADMIN_SUBSCRIPTION_UPDATED", target=str(user_id), detail=f"{payload.plan}:{payload.status}"))
    db.commit(); db.refresh(sub)
    return sub

@router.get("/anti-cheat", response_model=list[AntiCheatOut])
def anti_cheat_events(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(AntiCheatEvent).order_by(AntiCheatEvent.created_at.desc()).limit(200).all()

@router.get("/honeypot/events", response_model=list[HoneypotEventOut])
def honeypot_events(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    ingest_honeypot_events(db)
    events = db.query(HoneypotEvent).order_by(HoneypotEvent.last_seen_at.desc()).limit(200).all()
    reputations = {}
    for ip in {event.source_ip for event in events if event.source_ip}:
        reputations[ip] = get_ip_reputation(db, ip)
    output = []
    for event in events:
        item = HoneypotEventOut.model_validate(event).model_dump()
        reputation = reputations.get(event.source_ip)
        item["reputation"] = IpReputationOut.model_validate(reputation).model_dump() if reputation else None
        output.append(item)
    return output

@router.get("/blocked-ips", response_model=list[BlockedIpWatchlistOut])
def blocked_ips(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(BlockedIpWatchlist).filter_by(active=True).order_by(BlockedIpWatchlist.last_seen_at.desc()).limit(200).all()

@router.post("/cleanup-expired")
def cleanup_expired(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return cleanup_expired_sessions(db, actor="admin", admin_user_id=admin.id)
