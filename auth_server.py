import time
import hashlib
from fastapi import FastAPI, Request, Response, Form
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

from authlib.oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)

# 1. ПОДКЛЮЧЕНИЕ К SQL БАЗЕ (Для Docker меняем на postgresql://user:pass@db:5432/bank_auth)
DATABASE_URL = "sqlite:///./bank_oauth.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# 2. МОДЕЛИ БАЗЫ ДАННЫХ
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)


class OAuth2Client(Base, OAuth2ClientMixin):
    __tablename__ = "oauth2_clients"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)

    # УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ №1 (Небезопасная валидация redirect_uri):
    # В банке часто бывают разные поддомены или пути для возврата. Разработчик
    # переопределил строгую проверку Authlib на проверку через startswith().
    # Это позволяет провести Open Redirect атаку (например: http://localhost:8002/://evil.com)
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


Base.metadata.create_all(bind=engine)


# 3. НАСТРОЙКА ГРАНТА OAUTH 2.1
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        db = SessionLocal()
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=request.data.get("code_challenge"),
            code_challenge_method=request.data.get("code_challenge_method"),
        )
        db.add(auth_code)
        db.commit()
        db.close()

    def query_authorization_code(self, code, client):
        db = SessionLocal()
        item = db.query(OAuth2AuthorizationCode).filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item
        return None

    def delete_authorization_code(self, authorization_code):
        db = SessionLocal()
        # В SQLAlchemy нужно заново привязать объект к текущей сессии перед удалением
        obj = db.merge(authorization_code)
        db.delete(obj)
        db.commit()
        db.close()

    def authenticate_user(self, authorization_code):
        db = SessionLocal()
        return db.query(User).filter_by(id=authorization_code.user_id).first()


# 4. АДАПТЕР AUTHLIB ДЛЯ FASTAPI
class FastAPIAuthorizationServer(AuthorizationServer):
    def query_client(self, client_id):
        db = SessionLocal()
        return db.query(OAuth2Client).filter_by(client_id=client_id).first()

    def save_token(self, token_data, request):
        db = SessionLocal()
        token = OAuth2Token(
            client_id=request.client.client_id,
            user_id=request.user.id,
            **token_data
        )
        db.add(token)
        db.commit()
        db.close()

    def create_oauth2_request(self, request: Request):
        return self._create_oauth2_request_from_data(
            method=request.method,
            uri=str(request.url),
            headers=dict(request.headers),
            body=getattr(request.state, "body_dict", {})
        )

    def handle_response(self, status_code, body, headers):
        return Response(content=body, status_code=status_code, headers=dict(headers))


server = FastAPIAuthorizationServer()

# УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ №2 (Ослабление стандарта OAuth 2.1):
# Включена поддержка PKCE, но флаг required=False позволяет клиентам
# обходить защиту PKCE, если они просто не передадут code_challenge.
server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])

app = FastAPI(title="Bank OAuth 2.1 Server (Authlib)")
templates = Jinja2Templates(directory="templates")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.on_event("startup")
def init_db():
    """Заполняем базу тестовыми пользователями и клиентом при первом запуске."""
    db = SessionLocal()
    if not db.query(User).filter_by(username="alice").first():
        db.add(User(id=42, username="alice", password_hash=hash_password("123")))
        db.add(User(id=99, username="bob", password_hash=hash_password("456")))

    if not db.query(OAuth2Client).filter_by(client_id="my_client_app").first():
        client = OAuth2Client(
            client_id="my_client_app",
            client_id_issued_at=int(time.time()),
            user_id=42,
        )
        client.set_client_metadata({
            "client_name": "Mobile Bank Client",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "read write",
            "redirect_uris": ["http://localhost:8002/callback"],
            "token_endpoint_auth_method": "none"
        })
        db.add(client)
    db.commit()
    db.close()


@app.middleware("http")
async def parse_form_body(request: Request, call_next):
    if request.method == "POST":
        form = await request.form()
        request.state.body_dict = dict(form)
    else:
        request.state.body_dict = {}
    return await call_next(request)


@app.get("/authorize")
def authorize_get(request: Request):
    """
    Шаг 1: Пользователь приходит с клиента.
    Authlib сам проверяет client_id, response_type и redirect_uri ДО показа формы!
    """
    try:
        grant = server.get_consent_grant(request, end_user=None)
    except Exception as error:
        return Response(content=str(error), status_code=400)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "client_id": grant.client.client_id,
            "scope": request.query_params.get("scope", "read"),
            "error": None
        }
    )


@app.post("/authorize")
def authorize_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """
    Шаг 2: Пользователь отправил логин и пароль.
    Проверяем их по SQL-базе и просим Authlib выдать authorization_code.
    """
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()

    if not user or user.password_hash != hash_password(password):
        db.close()
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            status_code=401,
            context={
                "client_id": request.query_params.get("client_id", ""),
                "scope": request.query_params.get("scope", "read"),
                "error": "Неверный логин или пароль"
            }
        )

    # Передаем найденного пользователя в Authlib — библиотека сама сгенерирует code
    # и сделает безопасный редирект на redirect_uri
    response = server.create_authorization_response(request, grant_user=user)
    db.close()
    return response


@app.post("/token")
def issue_token(request: Request):
    """Шаг 3: Обмен code на access_token через движок Authlib."""
    return server.create_token_response(request)
