from sqlalchemy import Column, Integer, String
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)


class OAuth2Client(Base, OAuth2ClientMixin):
    __tablename__ = "oauth2_clients"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)

    # УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ (Open Redirect через слабую проверку redirect_uri):
    # Разработчик разрешил любые пути, начинающиеся с базового URL, вместо строгого сравнения.
    def check_redirect_uri(self, redirect_uri):
        allowed = self.get_default_redirect_uri()
        return redirect_uri.startswith(allowed)


class OAuth2AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)


class OAuth2Token(Base, OAuth2TokenMixin):
    __tablename__ = "oauth2_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
