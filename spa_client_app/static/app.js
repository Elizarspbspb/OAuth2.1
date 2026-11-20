const CONFIG = {
    authUrl: "http://localhost:8000",
    resourceUrl: "http://localhost:8001",
    clientId: "my_spa_client_app", // Убедись, что клиент в БД разрешен без client_secret (Public Client)!
    redirectUri: "http://localhost:8003/callback",
    scope: "openid read write"
};

// В SPA токен приходится хранить в памяти JS (самый безопасный вариант для SPA)
// или в sessionStorage/localStorage (уязвимо для XSS!)
let inMemoryAccessToken = null;

// --- 1. Криптография PKCE на чистом браузерном JS (Web Crypto API) ---
function base64UrlEncode(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

async function generatePKCE() {
    // Генерируем 32 криптостойких случайных байта (аналог secrets.token_urlsafe(32))
    const randomBytes = new Uint8Array(32);
    window.crypto.getRandomValues(randomBytes);
    const verifier = base64UrlEncode(randomBytes);

    // Считаем SHA-256 хеш (аналог hashlib.sha256)
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await window.crypto.subtle.digest("SHA-256", data);
    const challenge = base64UrlEncode(digest);

    return { verifier, challenge };
}

function generateState() {
    const randomBytes = new Uint8Array(16);
    window.crypto.getRandomValues(randomBytes);
    return base64UrlEncode(randomBytes);
}

// --- 2. Логика OAuth 2.1 ---
async function startLogin() {
    const state = generateState();
    const { verifier, challenge } = await generatePKCE();

    // Сохраняем временные данные во вкладке браузера (sessionStorage очистится при закрытии вкладки)
    sessionStorage.setItem("pkce_state", state);
    sessionStorage.setItem("pkce_verifier", verifier);

    const params = new URLSearchParams({
        response_type: "code",
        client_id: CONFIG.clientId,
        redirect_uri: CONFIG.redirectUri,
        scope: CONFIG.scope,
        state: state,
        code_challenge: challenge,
        code_challenge_method: "S256"
    });

    // Редиректим браузер на сервер авторизации
    window.location.href = `${CONFIG.authUrl}/authorize?${params.toString()}`;
}

async function handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const returnedState = urlParams.get("state");
    const error = urlParams.get("error");

    if (error) {
        renderError(`Ошибка авторизации: ${error}`);
        return;
    }

    const savedState = sessionStorage.getItem("pkce_state");
    const verifier = sessionStorage.getItem("pkce_verifier");

    // Очищаем одноразовые значения
    sessionStorage.removeItem("pkce_state");
    sessionStorage.removeItem("pkce_verifier");

    if (!returnedState || returnedState !== savedState) {
        renderError("Ошибка безопасности: state не совпадает!");
        return;
    }

    // Убираем ?code=...&state=... из адресной строки браузера, чтобы токен/код не утек в историю или Referer
    window.history.replaceState({}, document.title, "/");

    // Браузер НАПРЯМУЮ идет на /token (потребует настройки CORS на Сервере авторизации!)
    const body = new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: CONFIG.redirectUri,
        client_id: CONFIG.clientId,
        code_verifier: verifier
    });

    const response = await fetch(`${CONFIG.authUrl}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString()
    });

    if (!response.ok) {
        renderError(`Не удалось обменять код на токен: HTTP ${response.status}`);
        return;
    }

    const tokenData = await response.json();
    // Сохраняем access_token ТОЛЬКО в оперативной памяти JS-переменной (не в localStorage!)
    inMemoryAccessToken = tokenData.access_token;
    renderDashboard();
}

async function loadAccountData() {
    const output = document.getElementById("api-output");
    output.textContent = "Запрос напрямую в Сервер ресурсов...";

    try {
        // Браузер НАПРЯМУЮ отправляет Bearer-токен в 4-й контейнер (потребует CORS на Сервере ресурсов!)
        const response = await fetch(`${CONFIG.resourceUrl}/api/data`, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${inMemoryAccessToken}`,
                "Accept": "application/json"
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        output.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        output.textContent = `Ошибка запроса: ${err.message}`;
    }
}

// --- 3. Отрисовка интерфейса (DOM) ---
function renderLogin() {
    const app = document.getElementById("app");
    app.innerHTML = `
        <p>Вы не авторизованы. Весь код работает только в браузере (SPA).</p>
        <button id="login-btn">Войти через Банк (OAuth 2.1 + PKCE)</button>
    `;
    document.getElementById("login-btn").addEventListener("click", startLogin);
}

function renderDashboard() {
    const app = document.getElementById("app");
    // МБ уязвимость inner ?
    app.innerHTML = `
        <p>Авторизация успешна! Access Token хранится в переменной памяти JS.</p>
        <button id="fetch-btn">Загрузить баланс напрямую из Resource Server</button>
        <button id="logout-btn">Выйти</button>
        <pre id="api-output"></pre>
    `;
    document.getElementById("fetch-btn").addEventListener("click", loadAccountData);
    document.getElementById("logout-btn").addEventListener("click", () => {
        inMemoryAccessToken = null;
        renderLogin();
    });
}

function renderError(msg) {
    const app = document.getElementById("app");
    app.innerHTML = `<p style="color: red;" id="err-box"></p><button id="retry-btn">На главную</button>`;
    // Защита от XSS: вставляем текст ошибки через textContent, а не innerHTML
    document.getElementById("err-box").textContent = msg;
    document.getElementById("retry-btn").addEventListener("click", renderLogin);
}

// --- Точка входа при загрузке страницы ---
document.addEventListener("DOMContentLoaded", () => {
    if (window.location.pathname === "/callback" && window.location.search.includes("code=")) {
        handleCallback();
    } else if (inMemoryAccessToken) {
        renderDashboard();
    } else {
        renderLogin();
    }
});