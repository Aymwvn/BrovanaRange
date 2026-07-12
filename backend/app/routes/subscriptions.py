from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Subscription, User
from app.core.security import current_user
from app.schemas import SubscriptionOut

router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])

@router.get("/me", response_model=SubscriptionOut)
def my_subscription(db: Session = Depends(get_db), user: User = Depends(current_user)):
    sub = db.query(Subscription).filter_by(user_id=user.id).first()
    if not sub:
        sub = Subscription(user_id=user.id, plan="free", status="active", max_active_labs=1)
        db.add(sub); db.commit(); db.refresh(sub)
    return sub
