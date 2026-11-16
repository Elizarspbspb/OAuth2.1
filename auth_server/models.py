from sqlalchemy import Column, Integer, String, Float
from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)


class OAuth2Client(Base):
    __tablename__ = "oauth2_clients"
    client_id = Column(String(50), primary_key=True)
    redirect_uri = Column(String(200), nullable=False)
    allowed_scopes = Column(String(100), default="read write")


class AuthCode(Base):
    __tablename__ = "oauth2_codes"
    code = Column(String(100), primary_key=True)
    client_id = Column(String(50), nullable=False)
    redirect_uri = Column(String(200), nullable=False)
    user_id = Column(Integer, nullable=False)
    scope = Column(String(100), default="read")
    code_challenge = Column(String(200), nullable=True)
