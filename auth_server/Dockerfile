# Берем легкий официальный образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Сначала копируем только зависимости и ставим их (это ускорит повторные сборки)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь остальной код (main.py, models.py, database.py и папку templates)
COPY . .

# Открываем порт 8000
EXPOSE 8000

# Команда запуска сервера
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
