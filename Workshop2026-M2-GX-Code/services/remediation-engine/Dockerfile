FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org $(grep -v -E '^pytest' requirements.txt)
COPY engine.py adapters.py main.py ./
RUN useradd -r -u 10001 svc
USER 10001
EXPOSE 8000
CMD ["uvicorn", "main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
