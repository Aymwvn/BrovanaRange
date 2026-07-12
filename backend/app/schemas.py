from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=20, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class LoginIn(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)
    totp_code: str | None = Field(default=None, min_length=6, max_length=8)
    email_otp: str | None = Field(default=None, min_length=6, max_length=6)

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=40, max_length=1200)

class MessageOut(BaseModel):
    message: str

class EmailTokenIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)

class PasswordResetRequestIn(BaseModel):
    email: EmailStr

class PasswordResetConfirmIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=10, max_length=128)

class MfaTotpSetupOut(BaseModel):
    secret: str
    provisioning_uri: str

class MfaTotpVerifyIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)

class MfaEmailEnableIn(BaseModel):
    enabled: bool

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    score: int
    email_verified: bool
    mfa_totp_enabled: bool
    mfa_email_enabled: bool
    model_config = {"from_attributes": True}

class LabOut(BaseModel):
    id: int
    slug: str
    title: str
    category: str
    difficulty: str
    description: str
    docker_image: str | None = None
    sandbox_runtime: str
    points: int
    is_active: bool
    model_config = {"from_attributes": True}

class LabCreate(BaseModel):
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    title: str = Field(min_length=2, max_length=120)
    category: str = Field(min_length=2, max_length=80)
    difficulty: str = Field(default="Basic", min_length=2, max_length=40)
    description: str = Field(min_length=3, max_length=2000)
    docker_image: str = Field(min_length=3, max_length=150, pattern=r"^[A-Za-z0-9_./:@-]+$")
    sandbox_runtime: str = Field(default="runsc", pattern=r"^(runsc|runc)$")
    points: int = Field(default=60, ge=1, le=10000)
    is_active: bool = True

class LabUpdate(BaseModel):
    slug: str | None = Field(default=None, min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    title: str | None = Field(default=None, min_length=2, max_length=120)
    category: str | None = Field(default=None, min_length=2, max_length=80)
    difficulty: str | None = Field(default=None, min_length=2, max_length=40)
    description: str | None = Field(default=None, min_length=3, max_length=2000)
    docker_image: str | None = Field(default=None, min_length=3, max_length=150, pattern=r"^[A-Za-z0-9_./:@-]+$")
    sandbox_runtime: str | None = Field(default=None, pattern=r"^(runsc|runc)$")
    points: int | None = Field(default=None, ge=1, le=10000)
    is_active: bool | None = None

class SessionOut(BaseModel):
    id: int
    lab_id: int
    status: str
    connection_info: str
    started_at: datetime
    expires_at: datetime
    model_config = {"from_attributes": True}

class FlagIn(BaseModel):
    flag: str = Field(min_length=4, max_length=160, pattern=r"^[A-Za-z0-9_{}\-]+$")

class FlagOut(BaseModel):
    correct: bool
    message: str
    score: int

class AuditOut(BaseModel):
    id: int
    user_id: int | None
    action: str
    target: str
    detail: str
    created_at: datetime
    model_config = {"from_attributes": True}

class UserAdminOut(UserOut):
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime

class UserAdminUpdate(BaseModel):
    role: str | None = Field(default=None, pattern=r"^(admin|student)$")
    is_active: bool | None = None
    email_verified: bool | None = None

class SubscriptionOut(BaseModel):
    id: int
    user_id: int
    plan: str
    status: str
    max_active_labs: int
    expires_at: datetime | None
    model_config = {"from_attributes": True}

class SubscriptionUpdate(BaseModel):
    plan: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$")
    status: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$")
    max_active_labs: int = Field(ge=1, le=10)
    expires_at: datetime | None = None

class AntiCheatOut(BaseModel):
    id: int
    user_id: int | None
    lab_id: int | None
    severity: str
    reason: str
    detail: str
    ip: str
    created_at: datetime
    model_config = {"from_attributes": True}
