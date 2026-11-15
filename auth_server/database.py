import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Берем адрес БД из настроек контейнера. Если не задан — подключаемся к локальному Postgres
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql+psycopg://bank_admin:secret_pass@auth_db:5432/auth_db"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
