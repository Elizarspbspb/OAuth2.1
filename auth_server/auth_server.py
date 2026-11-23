import time
import hashlib
import base64
import secrets
from typing import Optional
from fastapi import FastAPI, Request, Form, Query, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

from database import engine, SessionLocal, Base
from models import User, OAuth2Client, AuthCode

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Clean OAuth 2.1 Auth Server")
templates = Jinja2Templates(directory="templates")

# Генерируем пару RSA-ключей (Приватный для подписи JWT, Публичный отдаем Серверу ресурсов)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)
PUBLIC_PEM = private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

# Формируем стандартный JWKS для проверки токенов на Сервере ресурсов
pub_numbers = private_key.public_key().public_numbers()
def int_to_base64(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

JWKS_DATA = {
    "keys": [{
        "kty": "RSA", "use": "sig", "kid": "bank-key-1", "alg": "RS256",
        "n": int_to_base64(pub_numbers.n), "e": int_to_base64(pub_numbers.e)
    }]
}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return secrets.compare_digest(encoded, challenge)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8003"], # Разрешаем запросы ТОЛЬКО с нашего SPA! (Никогда не "*")
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.on_event("startup")
def seed_db():
    db = SessionLocal()
    if not db.query(User).filter_by(username="alice").first():
        db.add(User(id=42, username="alice", password_hash=hash_password("123")))
        db.add(User(id=99, username="bob", password_hash=hash_password("456")))
    if not db.query(OAuth2Client).filter_by(client_id="my_client_app").first():
        db.add(OAuth2Client(client_id="my_client_app", redirect_uri="http://localhost:8002/callback"))
    if not db.query(OAuth2Client).filter_by(client_id="my_spa_client_app").first():
        db.add(OAuth2Client(client_id="my_spa_client_app", redirect_uri="http://localhost:8003/callback"))
    db.commit()
    db.close()


@app.get("/.well-known/jwks.json")
def get_jwks():
    return JWKS_DATA


@app.get("/authorize")
def authorize_get(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read")
):
    db = SessionLocal()
    client = db.query(OAuth2Client).filter_by(client_id=client_id).first()
    db.close()

    # УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ №1: проверка через startswith() вместо строгого равенства (Open Redirect)
    if not client or not redirect_uri.startswith(client.redirect_uri) or response_type != "code":
        raise HTTPException(status_code=400, detail="Неверный client_id или redirect_uri")

    return templates.TemplateResponse(
        request=request, name="login.html",
        context={"client_id": client_id, "scope": scope, "error": None}
    )


@app.post("/authorize")
def authorize_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read"),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None)
):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    print("user = ", user)
    if not user or user.password_hash != hash_password(password):
        db.close()
        return templates.TemplateResponse(
            request=request, name="login.html", status_code=401,
            context={"client_id": client_id, "scope": scope, "error": "Неверный логин или пароль"}
        )
        
    # УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ №2: PKCE (code_challenge) не обязателен, а scope не проверяется
    authorization_code = secrets.token_urlsafe(16)
    print("authorization_code = ", authorization_code)
    db.add(AuthCode(
        authorization_code=authorization_code, client_id=client_id, redirect_uri=redirect_uri,
        user_id=user.id, scope=scope, code_challenge=code_challenge
    ))
    db.commit()
    db.close()

    #target = f"{redirect_uri}?code={code}" + (f"&state={state}" if state else "")
    target = (f"{redirect_uri}?state={state}" if state else "") + f"&authorization_code={authorization_code}"
    return RedirectResponse(url=target, status_code=303)


@app.post("/token")
def issue_token(
    grant_type: str = Form(...),
    authorization_code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: Optional[str] = Form(None)
):
    print("ISSUE_TOKEN")
    if grant_type != "authorization_code":
        print("Неверный grant_type")
        raise HTTPException(status_code=400, detail="Неверный grant_type")
    print("authorization_code = ", authorization_code)
    print("client_id = ", client_id)
    db = SessionLocal()
    auth_code = db.query(AuthCode).filter_by(authorization_code=authorization_code, client_id=client_id).first()
    print("auth_code = ", auth_code)
    print("auth_code.redirect_uri = ", auth_code.redirect_uri)
    print("redirect_uri = ", redirect_uri)
    if not auth_code or auth_code.redirect_uri != redirect_uri:
        print("Недействительный код авторизации")
        db.close()
        raise HTTPException(status_code=400, detail="Недействительный код авторизации")

    if auth_code.code_challenge:
        if not code_verifier or not verify_pkce(code_verifier, auth_code.code_challenge):
            print("Ошибка проверки PKCE")
            db.close()
            raise HTTPException(status_code=400, detail="Ошибка проверки PKCE")

    # Удаляем одноразовый код из PostgreSQL
    user_id = auth_code.user_id
    scope = auth_code.scope
    db.delete(auth_code)
    db.commit()
    db.close()

    # Выписываем боевой RS256 JWT-токен
    payload = {
        "iss": "http://auth_server:8000",
        "sub": str(user_id),
        "scope": scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    token = jwt.encode(payload, PRIVATE_PEM, algorithm="RS256", headers={"kid": "bank-key-1"})

    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": scope}
