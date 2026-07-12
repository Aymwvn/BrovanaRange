from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.core.security import current_user

router = APIRouter(prefix="/scoreboard", tags=["scoreboard"])

@router.get("")
def scoreboard(db: Session = Depends(get_db), _=Depends(current_user)):
    users = db.query(User).filter(User.is_active == True).order_by(User.score.desc()).limit(50).all()
    return [{"rank": i+1, "username": u.username, "score": u.score} for i, u in enumerate(users)]
