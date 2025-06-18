FROM python:3.13-alpine3.21 AS builder

WORKDIR /install
COPY requirements.txt .
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install/deps -r requirements.txt

FROM python:3.13-alpine3.21

WORKDIR /app
COPY --from=builder /install/deps /usr/local
COPY traceme.py traceme.py

ENTRYPOINT ["python3", "traceme.py"]
CMD ["--host", "8.8.8.8", "--output", "result.json"]
