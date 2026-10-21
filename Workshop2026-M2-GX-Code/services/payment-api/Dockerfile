FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
# Réseau qui intercepte TLS (proxy, antivirus) : PIP_EXTRA_ARGS dans .env, voir README. Vide par défaut.
ARG PIP_EXTRA_ARGS=""
RUN pip install --no-cache-dir ${PIP_EXTRA_ARGS} -r requirements.txt
COPY app.py .
RUN useradd -r -u 10001 svc
USER 10001
EXPOSE 8000
# Un seul worker : la saturation reste observable et la reprise (restart) déterministe.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
