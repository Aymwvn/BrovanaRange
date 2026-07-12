from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AntiCheatEvent, AuditLog, Lab, LabSession, Submission, Subscription, User
from app.core.security import require_admin
from app.schemas import AntiCheatOut, AuditOut, LabCreate, LabOut, LabUpdate, SubscriptionOut, SubscriptionUpdate, UserAdminOut, UserAdminUpdate
from app.services.docker_manager import docker_manager

router = APIRouter(prefix="/admin", tags=["admin"])

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

@router.post("/cleanup-expired")
def cleanup_expired(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    expired = db.query(LabSession).filter(LabSession.status == "running", LabSession.expires_at < datetime.utcnow()).all()
    count = docker_manager.cleanup_expired(expired)
    for s in expired:
        s.status = "expired"
        s.stopped_at = datetime.utcnow()
    db.commit()
    orphaned = docker_manager.cleanup_orphaned_labs()
    db.add(AuditLog(user_id=admin.id, action="ADMIN_CLEANUP_EXPIRED", detail=f"sessions={count}, orphaned={orphaned}"))
    db.commit()
    return {"cleaned": count, "orphaned": orphaned}
