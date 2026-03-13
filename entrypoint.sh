#!/bin/bash

echo ">>> Starting initialization..."

# Запускаем инициализацию БД
python crad.py

echo ">>> Starting application..."

# Запускаем основное приложение
exec uvicorn app.main:app --host 0.0.0.0 --port 8000