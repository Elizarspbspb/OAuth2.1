# pip install fastapi uvicorn pyjwt
# uvicorn auth_server:app --host 0.0.0.0 --port 8000 --reload

import hashlib
import base64
import secrets
import time
from typing import Optional
from fastapi import FastAPI, HTTPException, Form, Query, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import jwt

app = FastAPI(title="Vulnerable OAuth 2.1 Auth Server")

# Подключаем папку с HTML-шаблонами (автоматическое экранирование XSS включено по умолчанию)
templates = Jinja2Templates(directory="templates")

# Секретный ключ для подписи JWT (в реальности хранится в переменных окружения)
JWT_SECRET = "super_secret_educational_key"
JWT_ALGORITHM = "HS256"

# Имитация базы данных (для простоты старта храним в памяти)
CLIENTS_DB = {
    "my_client_app": {
        "client_secret": "client_secret_123",
        #"redirect_uris": ["http://localhost:8002/callback"],
        "redirect_uris": ["http://localhost:8000/docs"],
        "allowed_scopes": ["read", "write"]
    },
    "admin": {
        "client_secret": "admin_secret_123",
        "redirect_uris": ["http://localhost:8000/docs"],
        "allowed_scopes": ["read", "write", "exe"]
    }
}

USERS_DB = {
    "alice": {"password": "123", "user_id": "user_42"},
    "bob": {"password": "456", "user_id": "user_99"},
}

# Временное хранилище кодов авторизации
AUTH_CODES_DB = {}


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Проверка PKCE по методу S256 (обязательно в OAuth 2.1)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return secrets.compare_digest(encoded, code_challenge)

# http://localhost:8000/authorize?response_type=code&client_id=my_client_app&redirect_uri=http://localhost:8000/docs
# http://localhost:8000/authorize?response_type=code&client_id=admin&redirect_uri=http://localhost:8000/docs
@app.get("/authorize")
def authorize(
    request: Request,
    response_type: str = Query(...),               # ОБЯЗАТЕЛЬНЫЙ (стоит многоточие ...)
    client_id: str = Query(...),                   # ОБЯЗАТЕЛЬНЫЙ
    redirect_uri: str = Query(...),                # ОБЯЗАТЕЛЬНЫЙ
    scope: str = Query("read"),                    # необязательный (по умолчанию "read")
    state: Optional[str] = Query(None),            # необязательный (по умолчанию пусто)
    code_challenge: Optional[str] = Query(None),   # необязательный (дыра в PKCE!)
    code_challenge_method: Optional[str] = Query("S256") # необязательный (по умолчанию "S256")
):

    """
    Шаг 1: Пользователь заходит сюда, логинится (здесь пропустили форму логина для краткости)
    и получает редирект обратно в клиентское приложение с одноразовым code.
    """
    if response_type != "code":
        raise HTTPException(status_code=400, detail="OAuth 2.1 поддерживает только response_type=code")

    client = CLIENTS_DB.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Неверный client_id или redirect_uri")

    # УЯЗВИМОСТЬ №1 (Логика OAuth 2.1):
    # По стандарту OAuth 2.1 параметр code_challenge (PKCE) ОБЯЗАТЕЛЕН.
    # Но разработчик сделал его необязательным (Optional) для обратной совместимости.
    # Это позволяет провести атаку перехвата кода (Authorization Code Interception).

    # УЯЗВИМОСТЬ №2 (Бизнес-логика прав доступа):
    # Сервер не проверяет, разрешен ли запрошенный scope клиенту (client["allowed_scopes"]).
    # Если злоумышленник передаст scope=admin, сервер молча его одобрит.

    # Безопасно рендерим отдельный HTML-файл и передаем туда переменные
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "error": None
        }
    )

@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("read"),
    state: Optional[str] = Form(""),
    code_challenge: Optional[str] = Form(""),
    code_challenge_method: Optional[str] = Form("S256")
):
    client = CLIENTS_DB.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Неверный client_id или redirect_uri")

    user = USERS_DB.get(username)
    if not user or user["password"] != password:
        # При ошибке логина заново рендерим ту же форму с сообщением об ошибке (без XSS)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            status_code=401,
            context={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "error": "Неверный логин или пароль!"
            }
        )

    # УЯЗВИМОСТЬ БИЗНЕС-ЛОГИКИ: подмена hidden-поля scope в DevTools или Burp Suite
    # позволит получить права admin, так как сервер не сверяет scope с client["allowed_scopes"]
    auth_code = secrets.token_urlsafe(16)
    AUTH_CODES_DB[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge if code_challenge else None,
        "user_id": user["user_id"]
    }

    redirect_target = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_target += f"&state={state}"

    return RedirectResponse(url=redirect_target, status_code=303)


@app.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: Optional[str] = Form(None)
):
    """
    Шаг 2: Клиентское приложение обменивает полученный code на боевой JWT access_token.
    """
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Неверный grant_type")

    code_data = AUTH_CODES_DB.get(code)
    if not code_data:
        raise HTTPException(status_code=400, detail="Код недействителен или уже использован")

    if code_data["client_id"] != client_id or code_data["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="Данные клиента не совпадают")

    # Проверяем PKCE, только если на первом шаге был передан code_challenge
    if code_data["code_challenge"]:
        if not code_verifier or not verify_pkce(code_verifier, code_data["code_challenge"]):
            raise HTTPException(status_code=400, detail="Ошибка проверки PKCE")

    # УЯЗВИМОСТЬ №3 (Гонка состояний / Повторное использование):
    # В идеале код удаляется из базы атомарно ДО выдачи токена.
    # Здесь мы удаляем его в самом конце. При параллельных запросах можно получить 2 токена по 1 коду.
    del AUTH_CODES_DB[code]

    # Генерируем JWT токен доступа
    payload = {
        "sub": code_data["user_id"],
        "scope": code_data["scope"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600  # Живет 1 час
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": code_data["scope"]
    }
