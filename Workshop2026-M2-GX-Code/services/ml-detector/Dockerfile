FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
COPY features.py gate.py model.py detector.py ./
# Utilisateur non privilégié ; le modèle est monté en lecture seule sur /models.
RUN useradd -r -u 10001 detector
USER 10001
EXPOSE 9101
CMD ["python", "detector.py"]
