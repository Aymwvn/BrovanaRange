from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from app.core.config import settings
from app.core.security import hash_password
from app.database import Base, engine, SessionLocal
from app.migrations import ensure_runtime_schema
from app.models import Lab, Subscription, User
from app.routes import admin, auth, labs, metrics, scoreboard, subscriptions

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="RedRange Hardened Secure Cyber Range API", version="4.0.0")
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

SEED_LABS = [
    dict(slug="linux-privilege-escalation", title="Linux Privilege Escalation", category="Linux Privilege Escalation", difficulty="Basic", description="Abuse a sudo misconfiguration to escalate privileges and capture a dynamic root flag inside an isolated Linux container.", docker_image="redrange/linux-privilege-escalation:latest", sandbox_runtime="runc", points=60),
    dict(slug="web-injection", title="Red Injection", category="Web Exploitation", difficulty="Basic", description="Exploit a vulnerable local web service with command injection and recover the dynamic flag from the container.", docker_image="redrange/web-injection:latest", sandbox_runtime=settings.LAB_CONTAINER_RUNTIME, points=80),
    dict(slug="forensic-skeleton", title="Skeleton DFIR", category="Digital Forensics", difficulty="Basic", description="Investigate suspicious files and recover evidence from a compromised Linux container.", docker_image="redrange/forensic-skeleton:latest", sandbox_runtime=settings.LAB_CONTAINER_RUNTIME, points=70),
]

@app.on_event("startup")
def startup():
    if settings.JWT_SECRET in {"CHANGE_THIS_TO_A_LONG_RANDOM_SECRET", "change-me", "secret"} or len(settings.JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET is weak. Set a long random secret in .env before running.")
    Base.metadata.create_all(bind=engine)
    ensure_runtime_schema(engine)
    db = SessionLocal()
    try:
        old_lab = db.query(Lab).filter_by(slug="ssh-ninja").first()
        new_lab = db.query(Lab).filter_by(slug="linux-privilege-escalation").first()
        if old_lab and not new_lab:
            old_lab.slug = "linux-privilege-escalation"
        for item in SEED_LABS:
            lab = db.query(Lab).filter_by(slug=item["slug"]).first()
            if not lab:
                db.add(Lab(flag_hash="", **item))
            else:
                for k, v in item.items():
                    setattr(lab, k, v)
        admin_user = db.query(User).filter_by(username=settings.DEFAULT_ADMIN_USERNAME).first()
        if not admin_user:
            admin_user = User(username=settings.DEFAULT_ADMIN_USERNAME, email=settings.DEFAULT_ADMIN_EMAIL.lower(), password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD), role="admin", email_verified=True)
            db.add(admin_user)
            db.flush()
        else:
            admin_user.email = settings.DEFAULT_ADMIN_EMAIL.lower()
            admin_user.password_hash = hash_password(settings.DEFAULT_ADMIN_PASSWORD)
            admin_user.role = "admin"
            admin_user.is_active = True
            admin_user.email_verified = True
            admin_user.mfa_totp_enabled = False
            admin_user.mfa_totp_secret = None
            admin_user.mfa_email_enabled = False
            admin_user.failed_login_count = 0
            admin_user.locked_until = None
            admin_user.token_version += 1
        if admin_user and not db.query(Subscription).filter_by(user_id=admin_user.id).first():
            db.add(Subscription(user_id=admin_user.id, plan="admin", status="active", max_active_labs=10))
        db.commit()
    finally:
        db.close()

app.include_router(auth.router)
app.include_router(labs.router)
app.include_router(scoreboard.router)
app.include_router(admin.router)
app.include_router(subscriptions.router)
app.include_router(metrics.router)

@app.get("/health")
def health():
    return {"status": "ok", "version": "4.0.0"}
