
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.lock .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
       --no-cache-dir \
       --require-hashes \
       -r requirements.lock

FROM python:3.12-slim AS runtime

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app.py .

ENV PATH="/opt/venv/bin:$PATH"

RUN rm -rf /opt/venv/lib/python3.12/site-packages/pip \
    /opt/venv/lib/python3.12/site-packages/pip-*.dist-info \
    /usr/local/lib/python3.12/site-packages/pip \
    /usr/local/lib/python3.12/site-packages/pip-*.dist-info

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
