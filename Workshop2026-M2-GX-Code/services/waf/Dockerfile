FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
COPY rules.py bans.py main.py ./
RUN useradd -r -u 10001 waf && mkdir -p /var/lib/waf && chown waf /var/lib/waf
USER 10001
EXPOSE 8080 8081 8082
CMD ["python", "main.py"]
