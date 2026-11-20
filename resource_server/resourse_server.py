import os
import httpx
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, Float, String
from sqlalchemy.orm import declarative_base, sessionmaker
from authlib.jose import jwt, JsonWebKey

# Подключаемся ко второй базе данных в том же контейнере Postgres (resource_db)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://bank_admin:secret_pass@auth_db:5432/resource_db")
JWKS_URL = os.getenv("JWKS_URL", "http://auth_server:8000/.well-known/jwks.json")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Таблица счетов пользователей (Ресурсы)
class Account(Base):
    __tablename__ = "accounts"
    user_id = Column(Integer, primary_key=True)
    owner_name = Column(String(50))
    balance = Column(Float, default=0.0)


Base.metadata.create_all(bind=engine)
app = FastAPI(title="Bank Resource Server (Vulnerable Business Logic)")

# Кэш публичного ключа от Сервера Авторизации
CACHED_JWKS = None


async def get_current_user(authorization: str = Header(...)) -> dict:
    """
    Проверяем JWT-токен с помощью ПУБЛИЧНОГО ключа, скачанного с auth_server.
    """
    global CACHED_JWKS
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Неверный формат заголовка Authorization")

    token_str = authorization.split(" ")[1]

    # Скачиваем публичный ключ (JWKS) с сервера авторизации, если еще не скачали
    if not CACHED_JWKS:
        async with httpx.AsyncClient() as client:
            resp = await client.get(JWKS_URL)
            CACHED_JWKS = JsonWebKey.import_key_set(resp.json())

    try:
        # Проверяем криптографическую подпись RS256 публичным ключом!
        claims = jwt.decode(token_str, CACHED_JWKS)
        claims.validate()  # Проверяем срок действия (exp)
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Невалидный токен: {str(e)}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8003"], # Разрешаем запросы ТОЛЬКО с SPA! (Никогда не "*")
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.on_event("startup")
def seed_accounts():
    """Создаем счета для Алисы (1000 руб.) и Боба (5000 руб.)."""
    db = SessionLocal()
    if not db.query(Account).filter_by(user_id=42).first():
        db.add(Account(user_id=42, owner_name="alice", balance=1000.0))
        db.add(Account(user_id=99, owner_name="bob", balance=5000.0))
        db.commit()
    db.close()


class TransferRequest(BaseModel):
    to_user_id: int
    amount: float


# --- УЯЗВИМЫЕ ЭНДПОИНТЫ БИЗНЕС-ЛОГИКИ (Идеально для фаззера!) ---

@app.get("/accounts/{target_user_id}")
def get_balance(target_user_id: int, user: dict = Depends(get_current_user)):
    """
    УЯЗВИМОСТЬ №1 (IDOR): Токен проверен публичным ключом, мы знаем user['sub'],
    но забыли проверить, что target_user_id == int(user['sub']).
    Алиса (ID 42) может посмотреть баланс Боба (ID 99).
    """
    db = SessionLocal()
    acc = db.query(Account).filter_by(user_id=target_user_id).first()
    db.close()
    if not acc:
        raise HTTPException(status_code=404, detail="Счет не найден")
    return {"user_id": acc.user_id, "owner": acc.owner_name, "balance": acc.balance}


@app.post("/transfer")
def transfer_money(data: TransferRequest, user: dict = Depends(get_current_user)):
    """
    УЯЗВИМОСТЬ №2 (Отрицательная сумма): Нет проверки data.amount > 0.
    Если Алиса переведет Бобу -500 рублей, деньги спишутся у Боба и начислятся Алисе!
    УЯЗВИМОСТЬ №3 (Race Condition): Нет блокировки строки (with_for_update) при проверке баланса.
    """
    sender_id = int(user["sub"])
    db = SessionLocal()

    sender = db.query(Account).filter_by(user_id=sender_id).first()
    receiver = db.query(Account).filter_by(user_id=data.to_user_id).first()

    if not sender or not receiver:
        db.close()
        raise HTTPException(status_code=404, detail="Счет отправителя или получателя не найден")

    # Проверка достаточности средств (легко обходится отрицательным amount или гонкой запросов!)
    if sender.balance < data.amount:
        db.close()
        raise HTTPException(status_code=400, detail="Недостаточно средств")

    sender.balance -= data.amount
    receiver.balance += data.amount

    # Предохранитель для фаззера (Invariant Check):
    # Если фаззер с помощью гонки запросов загонит баланс в минус, сервер упадет с 500,
    # и фаззер сразу подсветит этот баг в отчете!
    assert sender.balance >= 0, "CRITICAL BUSINESS LOGIC BUG: Negative balance!"

    db.commit()
    new_balance = sender.balance
    db.close()

    return {"status": "success", "new_balance": new_balance}
