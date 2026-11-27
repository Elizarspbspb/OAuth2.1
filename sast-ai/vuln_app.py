import hashlib
import html
import os
import pickle
import re
import sqlite3
import subprocess
import jwt
import requests
import yaml
from flask import Flask, request, render_template_string

app = Flask(name)

# =====================================================================
# ГЛОБАЛЬНЫЕ КОНСТАНТЫ (Проверка межпроцедурного слайсинга Jedi)
# =====================================================================
HARDCODED_JWT_SECRET = "super_secret_prod_key_998877"
ENV_JWT_SECRET = os.getenv("JWT_SECRET", "")
ALLOWED_HOSTS = {"api.internal.bank", "auth.internal.bank"}


# =====================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (Санитайзеры: слабые и надежные)
# =====================================================================
def weak_xss_filter(data: str) -> str:
    """Слабая защита: удаляет только тег <script>, обходится через <img onerror=...>."""
    return data.replace("<script>", "").replace("</script>", "")


def strong_xss_filter(data: str) -> str:
    """Надежная защита: полное HTML-экранирование."""
    return html.escape(data, quote=True)


def strict_alphanumeric(val: str) -> str:
    """Надежная защита: оставляет только буквы и цифры."""
    return re.sub(r"[^a-zA-Z0-9]", "", val)


# =====================================================================
# КЕЙС 1: Реальный баг (TP) — Хардкод секрета из глобальной области
# =====================================================================
@app.route("/api/token_vuln")
def generate_token_vuln():
    user = request.args.get("user", "guest")
    # Semgrep сработает на использование захардкоженного секрета
    token = jwt.encode({"sub": user}, HARDCODED_JWT_SECRET, algorithm="HS256")
    return {"token": token}


# =====================================================================
# КЕЙС 2: Ложная тревога (FP) — Секрет берется из os.getenv
# =====================================================================
@app.route("/api/token_safe")
def generate_token_safe():
    user = request.args.get("user", "guest")
    # Semgrep может ругнуться на переменную секрета, но Jedi подтянет os.getenv
    token = jwt.encode({"sub": user}, ENV_JWT_SECRET, algorithm="HS256")
    return {"token": token}


# =====================================================================
# КЕЙС 3: Реальный баг (TP) — Обход XSS-защиты через ветку ELSE
# (Ловушка для LLM: модель видит strong_xss_filter в IF и может ошибиться)
# =====================================================================
@app.route("/profile/bypass")
def xss_branch_bypass():
    username = request.args.get("username", "")
    is_vip = request.args.get("vip") == "1"

    if is_vip:
        clean_name = strong_xss_filter(username)
        page = f"<h1>VIP Profile: {clean_name}</h1>"
    else:
        # В ветке else забыли вызвать strong_xss_filter!
        page = f"<h1>User Profile: {username}</h1>"

    return page


# =====================================================================
# КЕЙС 4: Ложная тревога (FP) — Защита стоит ДО ветвления (строгий доминатор)
# =====================================================================
@app.route("/profile/safe")
def xss_dominated_safe():
    username = request.args.get("username", "")
    # Санитайзер стоит в стволе функции до ветвлений -> 100% путей защищены
    clean_name = strong_xss_filter(username)

    if request.args.get("vip") == "1":
        page = f"<h1>VIP Profile: {clean_name}</h1>"
    else:
        page = f"<h1>User Profile: {clean_name}</h1>"

    return page


# =====================================================================
# КЕЙС 5: Реальный баг (TP) — Использование слабого самописного фильтра
# (Проверка того, что Jedi подтянет weak_xss_filter, а LLM поймет её слабость)
# =====================================================================
@app.route("/search")
def xss_weak_sanitizer():
    query = request.args.get("q", "")
    filtered_query = weak_xss_filter(query)
    return f"<div>Search results for: {filtered_query}</div>"
# =====================================================================
# КЕЙС 6: Реальный баг (TP) — SQL-инъекция через f-строку
# =====================================================================
@app.route("/users/find")
def sql_injection_vuln():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Прямая подстановка пользовательского ввода в SQL-запрос
    cursor.execute(f"SELECT name, email FROM users WHERE id = '{user_id}'")
    return {"data": cursor.fetchall()}


# =====================================================================
# КЕЙС 7: Ложная тревога (FP) — Строгая валидация регуляркой до SQL-запроса
# =====================================================================
@app.route("/users/safe_find")
def sql_injection_safe():
    raw_id = request.args.get("id", "")
    safe_id = strict_alphanumeric(raw_id)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Semgrep все равно ругнется на f-строку, но strict_alphanumeric убрал все спецсимволы
    cursor.execute(f"SELECT name, email FROM users WHERE id = '{safe_id}'")
    return {"data": cursor.fetchall()}


# =====================================================================
# КЕЙС 8: Реальный баг (TP) — Command Injection (инъекция команд ОС)
# =====================================================================
@app.route("/network/ping")
def command_injection_vuln():
    host = request.args.get("host", "127.0.0.1")
    # Опасный вызов shell=True с непроверенным аргументом
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return {"output": output}


# =====================================================================
# КЕЙС 9: Реальный баг (TP) — Path Traversal (чтение произвольных файлов)
# =====================================================================
@app.route("/files/download")
def path_traversal_vuln():
    filename = request.args.get("file", "report.txt")
    # Злоумышленник может передать ../../etc/passwd
    base_dir = "/var/app/reports/"
    full_path = os.path.join(base_dir, filename)
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()


# =====================================================================
# КЕЙС 10: Реальный баг (TP) — Небезопасная десериализация (Pickle / YAML)
# =====================================================================
@app.route("/config/import", methods=["POST"])
def insecure_deserialization_vuln():
    raw_yaml = request.data.decode("utf-8")
    # yaml.load без SafeLoader позволяет выполнить произвольный код (RCE)
    config_data = yaml.load(raw_yaml, Loader=yaml.Loader)
    return {"loaded": str(config_data)}


@app.route("/session/restore", methods=["POST"])
def insecure_pickle_vuln():
    raw_bytes = request.data
    # Десериализация недоверенных байтов через pickle -> мгновенный RCE
    session_obj = pickle.loads(raw_bytes)
    return {"user": str(session_obj)}


# =====================================================================
# КЕЙС 11: Реальный баг (TP) — SSRF (Server-Side Request Forgery)
# =====================================================================
@app.route("/proxy/fetch")
def ssrf_vuln():
    target_url = request.args.get("url", "")
    # Запрос на произвольный внутренний адрес без проверки белого списка ALLOWED_HOSTS
    resp = requests.get(target_url, timeout=3)
    return {"status": resp.status_code, "body": resp.text[:200]}


# =====================================================================
# КЕЙС 12: Реальный баг (TP) — Слабое хеширование паролей (MD5) и SSTI
# =====================================================================
@app.route("/auth/register", methods=["POST"])
def weak_hash_and_ssti():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Использование криптографически сломанного MD5 для пароля
    pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    # Server-Side Template Injection (SSTI): рендеринг пользовательского ввода как шаблона
    template = f"<h3>Welcome, {username}! Your hash: {pwd_hash}</h3>"
    return render_template_string(template)