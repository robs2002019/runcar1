"""
RUN CAR PRO MAX — Servidor Web Simple
======================================
Sirve el archivo index.html con FastAPI.
Firebase se maneja directo desde el navegador (como en el original).

Instalacion:
    pip install fastapi uvicorn

Ejecucion:
    uvicorn server:app --host 0.0.0.0 --port 8000
"""

import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
