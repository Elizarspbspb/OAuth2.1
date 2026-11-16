import time
import hashlib
from fastapi import FastAPI, Request, Response, Form
from fastapi.templating import Jinja2Templates
from authlib.oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc6749 import OAuth2Request
from urllib.parse import parse_qsl

from database import engine, SessionLocal, Base
from models import User, OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc6750 import BearerTokenGenerator
import jwt  # Убедитесь, что установлен pyjwt или используем authlib.jose

# Создаем таблицы в контейнере PostgreSQL, если их еще нет
Base.metadata.create_all(bind=engine)

# Генерируем пару ключей RSA (Приватный для подписи, Публичный для Сервера ресурсов)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
PUBLIC_PEM = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Формируем стандартный JWKS (JSON Web Key Set) для публикации
jwk = JsonWebKey.import_key(PUBLIC_PEM, {"kty": "RSA", "use": "sig", "kid": "bank-key-1", "alg": "RS256"})
JWKS_DATA = {"keys": [jwk.as_dict()]}

# Учим Authlib выдавать подписанный JWT вместо случайной строки
class JWTBearerTokenGenerator(BearerTokenGenerator):
    def __init__(self, secret_key):
        super().__init__(self._generate_jwt)
        self.secret_key = secret_key

    def _generate_jwt(self, client, grant_type, user, scope):
        from authlib.jose import jwt as authlib_jwt
        header = {"alg": "RS256", "kid": "bank-key-1"}
        payload = {
            "iss": "http://auth_server:8000",
            "sub": str(user.id),
            "username": user.username,
            "scope": scope,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        return authlib_jwt.encode(header, payload, self.secret_key).decode("utf-8")

# Переопределение методов в базовых классах AUTHLIB
# AuthorizationCodeGrant - работа с одноразовыми кодами
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
    # Сохранение кода в PostgreSQL
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

    # Поиск кода
    def query_authorization_code(self, code, client):
        db = SessionLocal()
        item = db.query(OAuth2AuthorizationCode).filter_by(
            code=code, client_id=client.client_id
        ).first()
        return item if (item and not item.is_expired()) else None

    # Удаление кода
    def delete_authorization_code(self, authorization_code):
        db = SessionLocal()
        obj = db.merge(authorization_code)
        db.delete(obj)
        db.commit()
        db.close()

    # Привязка к пользователю
    def authenticate_user(self, authorization_code):
        db = SessionLocal()
        return db.query(User).filter_by(id=authorization_code.user_id).first()

# FastAPIAuthorizationServer - главный движок сервера авторизации
class FastAPIAuthorizationServer(AuthorizationServer):
    # Проверка приложения
    def query_client(self, client_id):
        db = SessionLocal()
        return db.query(OAuth2Client).filter_by(client_id=client_id).first()
        
    # Сохранение боевого токена
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
        
    # Переводчик «Вход»
    def create_oauth2_request(self, request: Request) -> OAuth2Request:
        query_dict = dict(request.query_params)
        form_dict = getattr(request.state, "form_dict", {})
        combined_data = {**query_dict, **form_dict}

        oauth_req = OAuth2Request(
            method=request.method,
            uri=str(request.url),
            headers=dict(request.headers)
        )
        if hasattr(oauth_req, "payload") and oauth_req.payload is None:
            from authlib.oauth2.rfc6749 import OAuth2Payload
            payload = OAuth2Payload()
            # Записываем данные напрямую во внутренний словарь объекта (без вызова сеттера .data)
            payload.dict.update(combined_data)
            oauth_req.payload = payload
        return oauth_req
        
    # Переводчик «Выход»
    def handle_response(self, status_code, body, headers):
        return Response(content=body, status_code=status_code, headers=dict(headers))


server = FastAPIAuthorizationServer()
print("AUTH_SERVER: FastAPIAuthorizationServer()")
server.register_token_generator("default", JWTBearerTokenGenerator(PRIVATE_PEM))
# УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ: PKCE сделан необязательным (required=False)
server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])
    
app = FastAPI(title="Bank OAuth 2.1 Auth Server")
templates = Jinja2Templates(directory="templates")
print("AUTH_SERVER: FastAPI start")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Публикуем публичный ключ по стандарту OAuth / OIDC
@app.get("/.well-known/jwks.json")
def get_jwks():
    """Сервер ресурсов будет забирать отсюда публичный ключ для проверки JWT."""
    return JWKS_DATA
    
# --- ИНИЦИАЛИЗАЦИЯ ТЕСТОВЫХ ДАННЫХ В POSTGRESQL ---
@app.on_event("startup")
def seed_database():
    print("AUTH_SERVER: startup and seed_database()")
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


# --- МАРШРУТЫ (ENDPOINTS) ---
@app.middleware("http")
async def security_and_body_middleware(request: Request, call_next):
    raw_body = await request.body()
    # Превращаем тело POST-запроса (например, "grant_type=authorization_code&code=123") в словарь
    body_str = raw_body.decode("utf-8") if raw_body else ""
    request.state.form_dict = dict(parse_qsl(body_str))

    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/authorize")
def authorize_get(request: Request):
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
def authorize_post(request: Request, username: str = Form(...), password: str = Form(...)):
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

    response = server.create_authorization_response(request, grant_user=user)
    db.close()
    return response


@app.post("/token")
def issue_token(request: Request):
    return server.create_token_response(request)
