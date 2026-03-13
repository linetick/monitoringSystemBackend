#!/bin/bash

echo ">>> Starting initialization..."

echo ">>> Running database migrations..."
alembic upgrade head

# Создаем начального администратора при наличии env-переменных
python crad.py

echo ">>> Starting application..."

# Запускаем основное приложение
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
