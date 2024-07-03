# Используем базовый образ Alpine Linux с Python 3.12
FROM python:3.12-alpine3.19

# Копируем файлы в контейнер
COPY . /usr/src/app

# Обновляем систему и устанавливаем необходимые пакеты
RUN python -m pip install --upgrade pip && \
    python -m pip install --no-cache-dir -r /usr/src/app/requirements.txt

# Делаем скрипт исполняемым
RUN chmod +x /usr/src/app/traceme.py

# Указываем рабочую директорию
WORKDIR /usr/src/app

# Запускаем скрипт
CMD ["python3", "traceme.py", "--host", "8.8.8.8", "--output", "result.json"]
