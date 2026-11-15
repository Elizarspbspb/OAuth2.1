# 1. Сервер авторизации my_auth_server.py написан на FastAPI 
## 1.1. Установка зависимостей
```
pip install fastapi uvicorn pyjwt
```
1. `fastapi` — это сам веб-фреймворк (каркас приложения). Он берет на себя всю рутину работы с HTTP
2. `uvicorn` — это веб-сервер (ASGI-сервер), который открывает порт 8000, принимает сетевой трафик, передает его в приложение на FastAPI, а ответ отправляет обратно пользователю.
3. `pyjwt` — библиотека для работы с JWT (JSON Web Tokens). PyJWT берет данные пользователя (ID, права scope, время жизни), упаковывает их в JSON и подписывает секретным ключом (JWT_SECRET).
4. Установка шаблонизатора jinja:
```
pip install jinja2
```

## 1.2 Запустить сервер
```
uvicorn my_auth_server:app --host 0.0.0.0 --port 8000 --reload
```
## 1.2 Автоматическая документация Swagger
1. Перейдите в браузере по адресу http://localhost:8000/docs. Вы увидите интерактивный интерфейс для всех эндпоинтов. Внутри `FastAPI` уже встроена готовая веб-страница с графическим интерфейсом `Swagger UI`.
2. По адресу http://localhost:8000/openapi.json будет лежать готовая схема для фаззера `Schemathesis`. `FastAPI` собирает технический паспорт вашего API по международному стандарту OpenAPI и публикует его по адресу

Эти два адреса появляются полностью автоматически благодаря фреймворку `FastAPI`.

## 1.3 Запрос
Сделайте запрос на получение токена:
```
http://localhost:8000/authorize?response_type=code&client_id=admin&redirect_uri=http://localhost:8000/docs
```

# 2. Сервер авторизации auth_server.py написан на FastAPI и библиотекой Authlib
В продакшене используют либо готовые Identity Provider (например, Keycloak), либо проверенные криптографические библиотеки уровня Authlib.
## 2.1. Установка зависимостей
```
pip install fastapi uvicorn authlib sqlalchemy jinja2 python-multipart
```