from datetime import datetime, timedelta
import secrets
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.database import get_db
from app.core.config import settings
from app.models import EmailOtp, OneTimeToken, RefreshToken, Subscription, User, AuditLog
from app.schemas import (
    EmailTokenIn,
    LoginIn,
    MessageOut,
    MfaEmailEnableIn,
    MfaTotpSetupOut,
    MfaTotpVerifyIn,
    PasswordResetConfirmIn,
    PasswordResetRequestIn,
    RefreshIn,
    TokenOut,
    UserCreate,
    UserOut,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    current_user,
    decode_token,
    generate_numeric_otp,
    generate_url_token,
    hash_password,
    hash_token,
    password_is_strong,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

def audit(db: Session, user_id: int | None, request: Request, action: str, detail: str = ""):
    db.add(AuditLog(user_id=user_id, action=action, ip=request.client.host if request.client else "", detail=detail))
    db.commit()

def issue_tokens(db: Session, user: User, request: Request) -> TokenOut:
    jti = secrets.token_hex(16)
    refresh = create_refresh_token(str(user.id), jti)
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hash_token(refresh),
        jti=jti,
        ip=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", "")[:255],
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    db.commit()
    return TokenOut(access_token=create_access_token(str(user.id), user.token_version), refresh_token=refresh)

def create_one_time_token(db: Session, user: User, purpose: str, minutes: int) -> str:
    token = generate_url_token()
    db.add(OneTimeToken(user_id=user.id, purpose=purpose, token_hash=hash_token(token), expires_at=datetime.utcnow() + timedelta(minutes=minutes)))
    db.commit()
    return token

def consume_one_time_token(db: Session, token: str, purpose: str) -> User | None:
    record = db.query(OneTimeToken).filter_by(token_hash=hash_token(token), purpose=purpose, consumed=False).first()
    if not record or record.expires_at < datetime.utcnow():
        return None
    record.consumed = True
    user = db.query(User).filter_by(id=record.user_id, is_active=True).first()
    db.commit()
    return user

def create_email_otp(db: Session, user: User) -> str:
    otp = generate_numeric_otp()
    db.add(EmailOtp(user_id=user.id, otp_hash=hash_password(otp), expires_at=datetime.utcnow() + timedelta(minutes=settings.EMAIL_OTP_EXPIRE_MINUTES)))
    db.commit()
    return otp

def verify_email_otp(db: Session, user: User, otp: str | None) -> bool:
    if not otp:
        return False
    records = db.query(EmailOtp).filter_by(user_id=user.id, consumed=False).order_by(EmailOtp.created_at.desc()).limit(5).all()
    for record in records:
        if record.expires_at >= datetime.utcnow() and verify_password(otp, record.otp_hash):
            record.consumed = True
            db.commit()
            return True
    return False

@router.post("/register", response_model=UserOut)
@limiter.limit("5/minute")
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)):
    if not password_is_strong(payload.password):
        raise HTTPException(status_code=400, detail="Password must be 10+ chars and include at least 3 of: uppercase, lowercase, number, symbol")
    username = payload.username.strip()
    email = payload.email.lower().strip()
    exists = db.query(User).filter(or_(func.lower(User.email) == email, func.lower(User.username) == username.lower())).first()
    if exists:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    user = User(username=username, email=email, password_hash=hash_password(payload.password), email_verified=not settings.REQUIRE_EMAIL_VERIFICATION)
    db.add(user); db.flush()
    db.add(Subscription(user_id=user.id, plan="free", status="active", max_active_labs=1))
    db.commit(); db.refresh(user)
    token = create_one_time_token(db, user, "email_verify", settings.EMAIL_TOKEN_EXPIRE_MINUTES)
    audit(db, user.id, request, "USER_REGISTERED", username)
    audit(db, user.id, request, "EMAIL_VERIFICATION_ISSUED", token if settings.ENVIRONMENT == "development" else "")
    return user

@router.post("/login", response_model=TokenOut)
@limiter.limit("10/minute")
def login(request: Request, payload: LoginIn, db: Session = Depends(get_db)):
    identifier = payload.identifier.lower().strip()
    user = db.query(User).filter(or_(func.lower(User.email) == identifier, func.lower(User.username) == identifier)).first()
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        audit(db, user.id, request, "LOGIN_BLOCKED_LOCKED", user.username)
        raise HTTPException(status_code=423, detail="Account temporarily locked after failed attempts")
    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            db.commit()
            audit(db, user.id, request, "LOGIN_FAILED", user.username)
        raise HTTPException(status_code=401, detail="Invalid username/email or password")
    if settings.REQUIRE_EMAIL_VERIFICATION and not user.email_verified:
        audit(db, user.id, request, "LOGIN_BLOCKED_EMAIL_UNVERIFIED", user.username)
        raise HTTPException(status_code=403, detail="Email verification required")
    if user.mfa_totp_enabled and (not user.mfa_totp_secret or not pyotp.TOTP(user.mfa_totp_secret).verify(payload.totp_code or "", valid_window=1)):
        audit(db, user.id, request, "LOGIN_MFA_REQUIRED", "totp")
        raise HTTPException(status_code=401, detail="MFA required")
    if (settings.REQUIRE_MFA or user.mfa_email_enabled) and not verify_email_otp(db, user, payload.email_otp):
        otp = create_email_otp(db, user)
        audit(db, user.id, request, "EMAIL_OTP_ISSUED", otp if settings.ENVIRONMENT == "development" else "")
        raise HTTPException(status_code=401, detail="Email OTP required")
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.commit()
    audit(db, user.id, request, "LOGIN_SUCCESS", user.username)
    return issue_tokens(db, user, request)

@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user

@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, payload: RefreshIn, db: Session = Depends(get_db)):
    decoded = decode_token(payload.refresh_token, "refresh")
    record = db.query(RefreshToken).filter_by(token_hash=hash_token(payload.refresh_token), jti=decoded.get("jti"), revoked=False).first()
    if not record or record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = db.query(User).filter_by(id=int(decoded["sub"]), is_active=True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    record.revoked = True
    record.revoked_at = datetime.utcnow()
    audit(db, user.id, request, "SESSION_REFRESHED", record.jti)
    return issue_tokens(db, user, request)

@router.post("/logout", response_model=MessageOut)
def logout(request: Request, payload: RefreshIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    record = db.query(RefreshToken).filter_by(token_hash=hash_token(payload.refresh_token), user_id=user.id, revoked=False).first()
    if record:
        record.revoked = True
        record.revoked_at = datetime.utcnow()
        db.commit()
    audit(db, user.id, request, "SESSION_REVOKED", "single")
    return MessageOut(message="Session revoked")

@router.post("/logout-all", response_model=MessageOut)
def logout_all(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    db.query(RefreshToken).filter_by(user_id=user.id, revoked=False).update({"revoked": True, "revoked_at": datetime.utcnow()})
    user.token_version += 1
    db.commit()
    audit(db, user.id, request, "SESSION_REVOKED", "all")
    return MessageOut(message="All sessions revoked")

@router.post("/verify-email", response_model=MessageOut)
def verify_email(request: Request, payload: EmailTokenIn, db: Session = Depends(get_db)):
    user = consume_one_time_token(db, payload.token, "email_verify")
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user.email_verified = True
    db.commit()
    audit(db, user.id, request, "EMAIL_VERIFIED", user.email)
    return MessageOut(message="Email verified")

@router.post("/resend-verification", response_model=MessageOut)
@limiter.limit("3/minute")
def resend_verification(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    token = create_one_time_token(db, user, "email_verify", settings.EMAIL_TOKEN_EXPIRE_MINUTES)
    audit(db, user.id, request, "EMAIL_VERIFICATION_ISSUED", token if settings.ENVIRONMENT == "development" else "")
    return MessageOut(message="Verification email queued")

@router.post("/password-reset/request", response_model=MessageOut)
@limiter.limit("3/minute")
def password_reset_request(request: Request, payload: PasswordResetRequestIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(func.lower(User.email) == payload.email.lower(), User.is_active == True).first()
    if user:
        token = create_one_time_token(db, user, "password_reset", settings.PASSWORD_RESET_EXPIRE_MINUTES)
        audit(db, user.id, request, "PASSWORD_RESET_ISSUED", token if settings.ENVIRONMENT == "development" else "")
    return MessageOut(message="If the account exists, password reset instructions were queued")

@router.post("/password-reset/confirm", response_model=MessageOut)
def password_reset_confirm(request: Request, payload: PasswordResetConfirmIn, db: Session = Depends(get_db)):
    if not password_is_strong(payload.password):
        raise HTTPException(status_code=400, detail="Password must be 10+ chars and include at least 3 of: uppercase, lowercase, number, symbol")
    user = consume_one_time_token(db, payload.token, "password_reset")
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user.password_hash = hash_password(payload.password)
    user.token_version += 1
    db.query(RefreshToken).filter_by(user_id=user.id, revoked=False).update({"revoked": True, "revoked_at": datetime.utcnow()})
    db.commit()
    audit(db, user.id, request, "PASSWORD_RESET_COMPLETED", "")
    return MessageOut(message="Password changed")

@router.post("/mfa/totp/setup", response_model=MfaTotpSetupOut)
def setup_totp(db: Session = Depends(get_db), user: User = Depends(current_user)):
    secret = pyotp.random_base32()
    user.mfa_totp_secret = secret
    user.mfa_totp_enabled = False
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="RedRange")
    return MfaTotpSetupOut(secret=secret, provisioning_uri=uri)

@router.post("/mfa/totp/verify", response_model=MessageOut)
def verify_totp(request: Request, payload: MfaTotpVerifyIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not user.mfa_totp_secret or not pyotp.TOTP(user.mfa_totp_secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    user.mfa_totp_enabled = True
    db.commit()
    audit(db, user.id, request, "MFA_TOTP_ENABLED", "")
    return MessageOut(message="TOTP MFA enabled")

@router.post("/mfa/email", response_model=MessageOut)
def set_email_mfa(request: Request, payload: MfaEmailEnableIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.mfa_email_enabled = payload.enabled
    db.commit()
    audit(db, user.id, request, "MFA_EMAIL_UPDATED", str(payload.enabled))
    return MessageOut(message="Email MFA updated")
