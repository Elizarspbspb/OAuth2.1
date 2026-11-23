from sqlalchemy import Column, Integer, String, Float
from database import Base

class Account(Base):
    __tablename__ = "accounts"
    user_id = Column(Integer, primary_key=True)
    owner_name = Column(String(50))
    balance = Column(Float, default=0.0)