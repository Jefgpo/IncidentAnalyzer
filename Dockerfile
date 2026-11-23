# Imagen única: compila el frontend y lo sirve desde FastAPI (un solo contenedor, un solo puerto).
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPLCONFIGDIR=/tmp/mpl
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY sample_data /app/sample_data
COPY --from=web /web/dist ./static
RUN useradd --create-home --uid 10001 soc && mkdir -p /data/sessions && chown -R soc /app /data
ENV SESSION_DIR=/data/sessions
USER soc
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/api/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
