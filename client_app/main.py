import os
import secrets
import hashlib
import base64
from urllib.parse import urlencode
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Bank Client App")
templates = Jinja2Templates(directory="templates")

# Адрес сервера авторизации для браузера (снаружи Docker)
AUTH_PUBLIC_URL = os.getenv("AUTH_PUBLIC_URL", "http://localhost:8000")
# Адрес сервера авторизации для обмена кодом (внутри сети Docker)
AUTH_INTERNAL_URL = os.getenv("AUTH_INTERNAL_URL", "http://auth_server:8000")

CLIENT_ID = "my_client_app"
REDIRECT_URI = "http://localhost:8002/callback"

# Временное хранилище сессий (PKCE code_verifier и state)
SESSIONS = {}


def generate_pkce():
    """Генерируем пару code_verifier и code_challenge (S256) по стандарту OAuth 2.1."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/login")
def start_oauth():
    """Шаг 1: Пользователь нажал кнопку 'Войти'. Готовим PKCE и редиректим в Банк."""
    state = secrets.token_urlsafe(16)
    print("state = ", state)
    code_verifier, challenge = generate_pkce()
    print("code_verifier = ", code_verifier)
    print("challenge = ", challenge)

    # Запоминаем code_verifier, чтобы потом доказать банку, что это именно мы делали запрос
    SESSIONS[state] = code_verifier

    params = urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid read write",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return RedirectResponse(url=f"{AUTH_PUBLIC_URL}/authorize?{params}")


@app.get("/callback")
async def oauth_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Шаг 2: Банк вернул пользователя сюда с одноразовым code."""
    if error:
        return templates.TemplateResponse(request=request, name="index.html", context={"error": error})

    # Проверяем state (защита от CSRF) и достаем наш секретный code_verifier
    code_verifier = SESSIONS.pop(state, None)
    if not code_verifier:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": "Неверный или устаревший параметр state!"}
        )

    # Шаг 3: Идем сервер-сервер (внутри Docker) на /token и меняем code на access_token
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{AUTH_INTERNAL_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": code_verifier,
            }
        )

    if response.status_code != 200:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": f"Ошибка получения токена: {response.text}"}
        )

    token_data = response.json()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"token_data": token_data}
    )
