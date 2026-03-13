FROM python:3.9-slim

WORKDIR /code

# Системные зависимости
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app ./app
COPY ./crad.py ./crad.py
COPY ./entrypoint.sh ./entrypoint.sh

# Делаем скрипт исполняемым
RUN chmod +x ./entrypoint.sh

# Точка входа (выполняется при запуске контейнера, а не при сборке)
ENTRYPOINT ["./entrypoint.sh"]