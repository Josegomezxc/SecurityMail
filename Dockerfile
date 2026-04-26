# Dockerfile (aplicación principal Django)
FROM python:3.12-slim

WORKDIR /app

# Dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código fuente
COPY . .

# Crear carpeta de adjuntos
RUN mkdir -p /app/media/attachments

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]