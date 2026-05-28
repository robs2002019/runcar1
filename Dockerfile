# ── Imagen base ligera de Python ────────────────────────────────────────────
FROM python:3.11-slim

# Evita que Python genere archivos .pyc y activa logs en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar e instalar dependencias primero (aprovecha cache de Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY runcar_backend.py .

# Si tienes el archivo de credenciales Firebase, cópialo también
# COPY serviceAccountKey.json .

# Puerto que expone la app
EXPOSE 8000

# Comando de arranque
CMD ["uvicorn", "runcar_backend:app", "--host", "0.0.0.0", "--port", "8000"]
