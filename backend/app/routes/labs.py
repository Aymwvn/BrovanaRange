from datetime import datetime
import asyncio
import threading
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Request
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.database import get_db, SessionLocal
from app.models import Lab, LabSession, Submission, Subscription, User, AuditLog
from app.schemas import LabOut, SessionOut, FlagIn, FlagOut
from app.core.config import settings
from app.core.security import current_user, decode_token, verify_password, hash_password
from app.services.docker_manager import docker_manager
from app.services.anti_cheat import evaluate_submission, record_event

router = APIRouter(prefix="/labs", tags=["labs"])
limiter = Limiter(key_func=get_remote_address)

def log(db: Session, user_id: int | None, action: str, target: str = "", detail: str = "", ip: str = ""):
    db.add(AuditLog(user_id=user_id, action=action, target=target, detail=detail, ip=ip))
    db.commit()

@router.get("", response_model=list[LabOut])
def list_labs(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.query(Lab).filter(Lab.is_active == True).order_by(Lab.id.asc()).all()

@router.post("/{lab_id}/start", response_model=SessionOut)
@limiter.limit("8/minute")
def start_lab(request: Request, lab_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    lab = db.query(Lab).filter(Lab.id == lab_id, Lab.is_active == True).first()
    if not lab:
        raise HTTPException(404, "Lab not found")
    active = db.query(LabSession).filter_by(user_id=user.id, lab_id=lab.id, status="running").order_by(LabSession.id.desc()).first()
    if active and active.expires_at > datetime.utcnow():
        if docker_manager.is_running(active.container_id):
            return active
        active.status = "crashed"; active.stopped_at = datetime.utcnow(); db.commit()
    active_count = db.query(LabSession).filter(LabSession.user_id == user.id, LabSession.status == "running", LabSession.expires_at > datetime.utcnow()).count()
    subscription = db.query(Subscription).filter_by(user_id=user.id, status="active").first()
    max_active = subscription.max_active_labs if subscription else 1
    if active_count >= max_active:
        raise HTTPException(429, "Active lab limit reached")
    flag = docker_manager.generate_flag(lab_slug=lab.slug, user_id=user.id)
    try:
        info = docker_manager.start_lab(user_id=user.id, lab_slug=lab.slug, image=lab.docker_image, flag=flag, sandbox_runtime=lab.sandbox_runtime)
    except Exception as e:
        log(db, user.id, "LAB_START_FAILED", lab.slug, str(e)[:500], request.client.host if request.client else "")
        raise HTTPException(500, "Failed to start lab")
    session = LabSession(user_id=user.id, lab_id=lab.id, session_flag_hash=hash_password(flag), **info)
    db.add(session); db.commit(); db.refresh(session)
    log(db, user.id, "LAB_STARTED", lab.slug, session.container_name, request.client.host if request.client else "")
    return session

@router.post("/{lab_id}/stop")
def stop_lab(lab_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = db.query(LabSession).filter_by(user_id=user.id, lab_id=lab_id, status="running").first()
    if not session:
        raise HTTPException(404, "Running session not found")
    docker_manager.stop_lab(session.container_id)
    session.status = "stopped"; session.stopped_at = datetime.utcnow()
    log(db, user.id, "LAB_STOPPED", str(lab_id), session.container_name, request.client.host if request.client else "")
    db.commit()
    return {"message": "Lab stopped"}

@router.post("/{lab_id}/submit-flag", response_model=FlagOut)
@limiter.limit("20/minute")
def submit_flag(request: Request, lab_id: int, payload: FlagIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    lab = db.query(Lab).filter_by(id=lab_id).first()
    if not lab:
        raise HTTPException(404, "Lab not found")
    session = db.query(LabSession).filter_by(user_id=user.id, lab_id=lab_id, status="running").order_by(LabSession.id.desc()).first()
    if session and session.expires_at < datetime.utcnow():
        docker_manager.stop_lab(session.container_id)
        session.status = "expired"
        session.stopped_at = datetime.utcnow()
        log(db, user.id, "LAB_EXPIRED", lab.slug, session.container_name, request.client.host if request.client else "")
        db.commit()
        raise HTTPException(410, "Lab session expired")
    correct = bool(session and session.session_flag_hash and verify_password(payload.flag.strip(), session.session_flag_hash))
    already = db.query(Submission).filter_by(user_id=user.id, lab_id=lab_id, correct=True).first()
    ip = request.client.host if request.client else ""
    for other in db.query(LabSession).filter(LabSession.user_id != user.id, LabSession.lab_id == lab_id, LabSession.session_flag_hash != "").limit(200).all():
        if verify_password(payload.flag.strip(), other.session_flag_hash):
            record_event(db, user_id=user.id, lab_id=lab_id, ip=ip, reason="same_flag_across_users", detail=f"Submitted another user's lab flag from session {other.id}.", severity="critical")
            break
    flagged, reason = evaluate_submission(db, user_id=user.id, lab_id=lab_id, ip=ip, submitted_flag=payload.flag.strip(), correct=correct, session_started_at=session.started_at if session else None)
    db.add(Submission(user_id=user.id, lab_id=lab_id, submitted_flag="[redacted]", correct=correct, ip=ip, flagged=flagged, anomaly_reason=reason))
    if correct and not already:
        user.score += lab.points
    log(db, user.id, "FLAG_SUBMITTED", lab.slug, "correct" if correct else "wrong", ip)
    db.commit()
    return FlagOut(correct=correct, message="Correct flag" if correct else "Wrong flag", score=user.score)

async def user_from_token(token: str) -> User | None:
    try:
        payload = decode_token(token, "access")
        user_id = int(payload.get("sub"))
    except (HTTPException, JWTError, TypeError, ValueError):
        return None
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == user_id, User.is_active == True).first()
    finally:
        db.close()

@router.websocket("/sessions/{session_id}/ws")
async def terminal_ws(websocket: WebSocket, session_id: int, token: str = Query(default="")):
    await websocket.accept()
    user = await user_from_token(token)
    if not user:
        await websocket.send_text("\r\nAuthentication failed.\r\n"); await websocket.close(); return
    db = SessionLocal(); sock = None; stop_event = threading.Event()
    try:
        session = db.query(LabSession).filter_by(id=session_id, user_id=user.id, status="running").first()
        if not session or session.expires_at < datetime.utcnow():
            await websocket.send_text("\r\nNo active session or session expired.\r\n"); await websocket.close(); return
        try:
            sock = docker_manager.open_tty_socket(session.container_id)
        except Exception as e:
            log(db, user.id, "TERMINAL_FAILED", str(session_id), str(e)[:500])
            await websocket.send_text("\r\nTerminal failed. Click Stop Lab, then Start Lab again.\r\n"); await websocket.close(); return
        loop = asyncio.get_event_loop()
        def reader():
            while not stop_event.is_set():
                try:
                    data = sock.recv(4096)
                    if data:
                        asyncio.run_coroutine_threadsafe(websocket.send_bytes(data), loop)
                except TimeoutError:
                    continue
                except Exception:
                    if not stop_event.is_set():
                        asyncio.run_coroutine_threadsafe(websocket.send_text("\r\n[terminal stream closed]\r\n"), loop)
                    break
        threading.Thread(target=reader, daemon=True).start()
        await websocket.send_text("Connected to RedRange isolated lab as student. Try: whoami && sudo -l\r\n")
        while True:
            message = await websocket.receive()
            data = message.get("text") if message.get("text") is not None else message.get("bytes")
            if data is None: continue
            if isinstance(data, str):
                sock.sendall(data.encode())
            else:
                sock.sendall(data)
    except WebSocketDisconnect:
        pass
    finally:
        stop_event.set()
        try:
            if sock: sock.close()
        except Exception: pass
        db.close()
