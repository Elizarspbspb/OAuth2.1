import os
import secrets
import hashlib
import base64
from urllib.parse import urlencode
import httpx
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Bank Client App")
# Подключаем папку static, где будут лежать JS-скрипты и CSS
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Адрес сервера авторизации для браузера (снаружи Docker)
AUTH_PUBLIC_URL = os.getenv("AUTH_PUBLIC_URL", "http://localhost:8000")
# Адрес сервера авторизации для обмена кодом (внутри сети Docker)
AUTH_INTERNAL_URL = os.getenv("AUTH_INTERNAL_URL", "http://auth_server:8000")
RESOURCE_INTERNAL_URL = os.getenv("RESOURCE_INTERNAL_URL", "http://resource_server:8001")

CLIENT_ID = "my_client_app"
REDIRECT_URI = "http://localhost:8002/callback"

# Хранилище временных данных PKCE (привязано к state)
OAUTH_FLOWS = {}
# Хранилище сессий авторизованных пользователей (в реальном проекте — Redis)
USER_SESSIONS = {}


def generate_pkce():
    """Генерируем пару code_verifier и code_challenge (S256) по стандарту OAuth 2.1."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge

# Middleware - перехватчик. Для добавления базовых заголовков безопасности (AppSec Best Practice)
# Чтобы не писать заголовки каждому маршруту (@app.) ставим 1 раз фильтр на весь сервер
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Запрещаем встраивание сайта в iframe (защита от Clickjacking)
    response.headers["X-Frame-Options"] = "DENY"
    # Запрещаем браузеру угадывать MIME-тип файлов
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Разрешаем загрузку JS только с нашего собственного домена (защита от XSS)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self';"
    return response

#@app.get("/")
#def home(request: Request):
#    return templates.TemplateResponse(request=request, name="index.html")

# Браузер шлет серверу текстовые HTTP-запросы и передаем в объект класса Request
@app.get("/")
def home(request: Request):
    session_id = request.cookies.get("session_id")
    is_authenticated = session_id in USER_SESSIONS
    # Токены в шаблон НЕ передаем!
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"is_authenticated": is_authenticated}
    )

@app.get("/login")
def start_oauth():
    """Шаг 1: Пользователь нажал кнопку 'Войти'. Готовим PKCE и редиректим в Банк."""
    state = secrets.token_urlsafe(16)
    print("state = ", state)
    nonce = secrets.token_urlsafe(16)
    print("nonce = ", nonce)
    code_verifier, challenge = generate_pkce()
    print("code_verifier = ", code_verifier)
    print("challenge = ", challenge)

    # Запоминаем code_verifier, чтобы потом доказать банку, что это именно мы делали запрос
    #SESSIONS[state] = code_verifier
    OAUTH_FLOWS[state] = code_verifier

    params = urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid read write",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    response = RedirectResponse(url=f"{AUTH_PUBLIC_URL}/authorize?{params}")
    # Привязываем state к конкретному браузеру через HttpOnly куку (защита от Login CSRF)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        max_age=300  # живет 5 минут
    )
    return response


@app.get("/callback")
async def oauth_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Шаг 2: Банк вернул пользователя сюда с одноразовым code."""
    if error:
        return templates.TemplateResponse(request=request, name="index.html", context={"error": error})

   # 1. Проверяем, что state в URL совпадает с кукой браузера (защита от Login CSRF)
    cookie_state = request.cookies.get("oauth_state")
    print("state = ", state)
    print("cookie_state = ", cookie_state)
    if not state or not cookie_state or not secrets.compare_digest(state, cookie_state):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": "Ошибка безопасности: state не совпадает с сессией браузера!"}
        )

    # 2. Достаем code_verifier и удаляем одноразовый state
    code_verifier = OAUTH_FLOWS.pop(state, None)
    if not code_verifier:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": "Неверный или устаревший параметр state!"}
        )

    # httpx и await - Асинхронный аналог, чтобы не блокировать весь сервер в ожидание, а точно завершить операцию
    # 3. Меняем code на токены access_token (сервер-сервер внутри Docker)
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            f"{AUTH_INTERNAL_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": code_verifier,
            }
        )

    if token_resp.status_code != 200:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": f"Ошибка получения токена: {token_resp.text}"}
        )

    #token_data = token_resp.json()
    #return templates.TemplateResponse(request=request,name="index.html",context={"token_data": token_data})

    # 4. Сохраняем токены ТОЛЬКО на сервере, а клиенту отдаем случайный session_id
    session_id = secrets.token_urlsafe(32)
    USER_SESSIONS[session_id] = token_resp.json()
    print("session_id = ", session_id)

    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("oauth_state")
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,    # JS в браузере не сможет прочитать эту куку (защита от кражи при XSS)
        samesite="lax",   # Защита от CSRF при переходе со сторонних сайтов
        secure=False,     # Поставьте True, когда перейдете на HTTPS!
        max_age=3600
    )
    return response

# --- API-эндпоинт, который будет дергать наш JS-скрипт из браузера ---
@app.get("/api/account-data")
async def get_account_data(request: Request):
    session_id = request.cookies.get("session_id")
    session_data = USER_SESSIONS.get(session_id)

    if not session_data:
        raise HTTPException(status_code=401, detail="Не авторизован")

    access_token = session_data["access_token"]

    # Backend сам идет в Сервер ресурсов (контейнер 4), подставляя токен в заголовок
    async with httpx.AsyncClient() as client:
        res = await client.get(
            f"{RESOURCE_INTERNAL_URL}/api/data",  # укажите ваш путь на сервере ресурсов
            headers={"Authorization": f"Bearer {access_token}"}
        )

    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail="Ошибка сервера ресурсов")

    return res.json()


@app.post("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        USER_SESSIONS.pop(session_id, None)
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session_id")
    return response