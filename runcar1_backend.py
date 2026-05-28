"""
RUN CAR PRO MAX — Backend FastAPI
==================================
Equivalente Python del frontend Firebase original.

Requisitos:
    pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] firebase-admin

Ejecucion:
    uvicorn runcar_backend:app --reload --port 8000

Variables de entorno requeridas:
    FIREBASE_CREDENTIALS_JSON  → ruta al archivo serviceAccountKey.json de Firebase
    SECRET_KEY                 → clave secreta para JWT (cambia esto en produccion)

Endpoints principales:
    POST /auth/register        → Registrar usuario (cliente o driver)
    POST /auth/login           → Login, devuelve JWT
    GET  /viajes               → Listar viajes disponibles (buscando/contraoferta)
    POST /viajes               → Publicar nuevo viaje (cliente)
    PATCH /viajes/{id}         → Actualizar estado de viaje
    POST /viajes/{id}/ofertas  → Driver envia oferta
    PATCH /viajes/{id}/ofertas/{oferta_id} → Cliente acepta/rechaza oferta
    GET  /viajes/{id}/mensajes → Historial de chat
    POST /viajes/{id}/mensajes → Enviar mensaje de chat
    GET  /ganancias/me         → Ganancias del driver autenticado
    POST /mensajes-generales   → Admin envia mensaje global
    GET  /admin/usuarios       → Admin lista usuarios
    PATCH /admin/usuarios/{uid} → Admin activa/desactiva usuario
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List

# ── FastAPI & HTTP ───────────────────────────────────────────────────────────
from fastapi import (
    FastAPI, Depends, HTTPException, status, Body
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# ── Auth / JWT ───────────────────────────────────────────────────────────────
from jose import JWTError, jwt
from passlib.context import CryptContext

# ── Firebase Admin ───────────────────────────────────────────────────────────
import firebase_admin
from firebase_admin import credentials, firestore

# ── Pydantic ─────────────────────────────────────────────────────────────────
from pydantic import BaseModel
# ════════════════════════════════════════════════════════════════════════════
# CONFIGURACION
# ════════════════════════════════════════════════════════════════════════════

SECRET_KEY = os.getenv("SECRET_KEY", "CAMBIA_ESTA_CLAVE_EN_PRODUCCION_12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7   # 7 días

FIREBASE_CRED_PATH = os.getenv(
    "FIREBASE_CREDENTIALS_JSON", "serviceAccountKey.json"
)

# Comisión de la app
APP_COMMISSION_RATE = 0.08   # 8 %

# Duración máxima de publicación de un viaje (segundos)
VIAJE_EXPIRY_SECONDS = 200

# ════════════════════════════════════════════════════════════════════════════
# INICIO FIREBASE
# ════════════════════════════════════════════════════════════════════════════

def init_firebase():
    cred_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
    print(f"[DEBUG] CRED_JSON length: {len(cred_json)}")
    print(f"[DEBUG] CRED_JSON starts with: {cred_json[:30] if cred_json else 'VACIO'}")
    
    if not firebase_admin._apps:
        if cred_json:
            try:
                cred_dict = json.loads(cred_json)
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
                print("[Firebase] Inicializado desde variable de entorno JSON ✓")
            except Exception as e:
                print(f"[Firebase] ERROR: {e}")
                return None
        elif os.path.exists(FIREBASE_CRED_PATH):
            cred = credentials.Certificate(FIREBASE_CRED_PATH)
            firebase_admin.initialize_app(cred)
            print(f"[Firebase] Inicializado desde archivo ✓")
        else:
            print("[ADVERTENCIA] No se encontró serviceAccountKey.json.")
            return None
    return firestore.client()

# ════════════════════════════════════════════════════════════════════════════
# SEGURIDAD / JWT
# ════════════════════════════════════════════════════════════════════════════

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Valida JWT y devuelve los datos del usuario desde Firestore."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado o token inválido",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid: str = payload.get("sub")
        if uid is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    if db is None:
        # Modo mock: devolver usuario ficticio para pruebas
        return {"uid": uid, "rol": "cliente", "nombre": "Usuario Mock", "estado": "activo"}

    snap = db.collection("usuarios").document(uid).get()
    if not snap.exists:
        raise credentials_exc
    user = snap.to_dict()
    if user.get("estado") == "inactivo":
        raise HTTPException(status_code=403, detail="Cuenta inactiva")
    return user


def require_role(*roles):
    """Dependencia: exige que el usuario tenga uno de los roles indicados."""
    async def _check(current_user: dict = Depends(get_current_user)):
        if current_user.get("rol") not in roles:
            raise HTTPException(status_code=403, detail="Acceso denegado")
        return current_user
    return _check


# ════════════════════════════════════════════════════════════════════════════
# MODELOS PYDANTIC
# ════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    email: str
    password: str
    nombre: str
    telefono: Optional[str] = ""
    rol: str = "cliente"               # "cliente" | "driver"
    # Campos driver
    placa: Optional[str] = ""
    marca: Optional[str] = ""
    modelo: Optional[str] = ""
    anio: Optional[str] = ""
    # Fotos en Base64 (opcional)
    foto_perfil: Optional[str] = ""
    licencia: Optional[str] = ""
    penales: Optional[str] = ""
    solvencia: Optional[str] = ""
    foto_placa: Optional[str] = ""
    foto_carro1: Optional[str] = ""
    foto_carro2: Optional[str] = ""
    foto_carro3: Optional[str] = ""


class PublicarViajeRequest(BaseModel):
    origen: str
    destino: str
    origen_lat: Optional[float] = None
    origen_lng: Optional[float] = None
    destino_lat: Optional[float] = None
    destino_lng: Optional[float] = None
    cliente_lat: Optional[float] = None
    cliente_lng: Optional[float] = None
    personas: int = 1
    bebes: int = 0
    mascotas: int = 0
    carga: float = 0
    notas: Optional[str] = ""
    distancia: Optional[str] = ""
    tiempo: Optional[str] = ""
    precio_app: Optional[str] = ""
    oferta_original: float


class ActualizarViajeRequest(BaseModel):
    estado: Optional[str] = None
    driver_lat: Optional[float] = None
    driver_lng: Optional[float] = None
    motivo_cancelacion: Optional[str] = None


class EnviarOfertaRequest(BaseModel):
    monto: float


class ResponderOfertaRequest(BaseModel):
    accion: str   # "aceptar" | "rechazar"


class EnviarMensajeRequest(BaseModel):
    msg: str


class MensajeGeneralRequest(BaseModel):
    msg: str


class ActualizarUsuarioRequest(BaseModel):
    estado: str   # "activo" | "inactivo"


# ════════════════════════════════════════════════════════════════════════════
# APLICACION
# ════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="RUN CAR PRO MAX — API",
    description="Backend equivalente al frontend Firebase de RUN CAR PRO MAX",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Cambia a tu dominio en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ════════════════════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════════════════════

@app.post("/auth/register", summary="Registrar nuevo usuario")
async def register(body: RegisterRequest):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")
    if body.rol == "admin":
        raise HTTPException(400, "No es posible registrarse como administrador")

    # Verificar email único
    existing = (
        db.collection("usuarios")
        .where("email", "==", body.email)
        .limit(1)
        .get()
    )
    if existing:
        raise HTTPException(400, "El correo ya está registrado")

    uid = hashlib.sha256(
        f"{body.email}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:28]

    hashed_pw = hash_password(body.password)

    user_doc = {
        "uid": uid,
        "email": body.email,
        "password_hash": hashed_pw,
        "nombre": body.nombre,
        "telefono": body.telefono,
        "rol": body.rol,
        "estado": "activo",
        "foto_perfil": body.foto_perfil,
        "timestamp": datetime.utcnow().isoformat(),
    }

    if body.rol == "driver":
        user_doc.update({
            "placa": body.placa,
            "marca": body.marca,
            "modelo": body.modelo,
            "anio": body.anio,
            "licencia": body.licencia,
            "penales": body.penales,
            "solvencia": body.solvencia,
            "foto_placa": body.foto_placa,
            "foto_carro1": body.foto_carro1,
            "foto_carro2": body.foto_carro2,
            "foto_carro3": body.foto_carro3,
        })

    db.collection("usuarios").document(uid).set(user_doc)

    token = create_access_token({"sub": uid, "rol": body.rol})
    return {"access_token": token, "token_type": "bearer", "uid": uid, "rol": body.rol}


@app.post("/auth/login", summary="Iniciar sesión")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    results = (
        db.collection("usuarios")
        .where("email", "==", form_data.username)
        .limit(1)
        .get()
    )
    if not results:
        raise HTTPException(401, "Correo o contraseña incorrecta")

    user = results[0].to_dict()
    if not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(401, "Correo o contraseña incorrecta")
    if user.get("estado") == "inactivo":
        raise HTTPException(403, "Cuenta inactiva")

    token = create_access_token({"sub": user["uid"], "rol": user["rol"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "uid": user["uid"],
        "rol": user["rol"],
        "nombre": user["nombre"],
        "foto_perfil": user.get("foto_perfil", ""),
    }


@app.get("/auth/me", summary="Perfil del usuario autenticado")
async def me(current_user: dict = Depends(get_current_user)):
    # No exponer password_hash
    return {k: v for k, v in current_user.items() if k != "password_hash"}


# ════════════════════════════════════════════════════════════════════════════
# VIAJES
# ════════════════════════════════════════════════════════════════════════════

@app.get("/viajes", summary="Listar viajes disponibles (driver)")
async def listar_viajes(current_user: dict = Depends(require_role("driver", "admin"))):
    if db is None:
        return []

    docs = db.collection("viajes").get()
    viajes = []
    now = datetime.utcnow()

    for d in docs:
        v = d.to_dict()
        v["id"] = d.id

        # Calcular segundos restantes
        ts = v.get("timestamp")
        if ts:
            pub_dt = datetime.fromisoformat(ts.replace("Z", ""))
            elapsed = (now - pub_dt).total_seconds()
            v["segundos_restantes"] = max(0, VIAJE_EXPIRY_SECONDS - int(elapsed))
        else:
            v["segundos_restantes"] = 0

        if v.get("estado") in ("buscando", "contraoferta"):
            viajes.append(v)

    viajes.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return viajes


@app.post("/viajes", summary="Publicar nuevo viaje (cliente)")
async def publicar_viaje(
    body: PublicarViajeRequest,
    current_user: dict = Depends(require_role("cliente")),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    # Verificar que el cliente no tenga ya un viaje activo
    activos = (
        db.collection("viajes")
        .where("clienteId", "==", current_user["uid"])
        .where("estado", "in", ["buscando", "contraoferta", "aceptado"])
        .limit(1)
        .get()
    )
    if activos:
        raise HTTPException(400, "Ya tienes un viaje activo. Cancélalo primero.")

    viaje = {
        "clienteId": current_user["uid"],
        "clienteNombre": current_user["nombre"],
        "clienteFoto": current_user.get("foto_perfil", ""),
        "clienteLat": body.cliente_lat,
        "clienteLng": body.cliente_lng,
        "origenLat": body.origen_lat,
        "origenLng": body.origen_lng,
        "destinoLat": body.destino_lat,
        "destinoLng": body.destino_lng,
        "origen": body.origen,
        "destino": body.destino,
        "personas": body.personas,
        "bebes": body.bebes,
        "mascotas": body.mascotas,
        "carga": body.carga,
        "notas": body.notas,
        "distancia": body.distancia,
        "tiempo": body.tiempo,
        "precioApp": body.precio_app,
        "ofertaOriginal": body.oferta_original,
        "ofertaActual": body.oferta_original,
        "estado": "buscando",
        "timestamp": datetime.utcnow().isoformat(),
    }

    ref = db.collection("viajes").add(viaje)
    viaje_id = ref[1].id
    return {"id": viaje_id, **viaje}


@app.get("/viajes/{viaje_id}", summary="Obtener detalle de un viaje")
async def obtener_viaje(
    viaje_id: str,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    snap = db.collection("viajes").document(viaje_id).get()
    if not snap.exists:
        raise HTTPException(404, "Viaje no encontrado")

    v = snap.to_dict()
    v["id"] = viaje_id

    # Sólo el cliente dueño, el driver asignado o admin pueden ver detalles
    uid = current_user["uid"]
    rol = current_user["rol"]
    if rol not in ("admin",) and v.get("clienteId") != uid and v.get("driverId") != uid:
        raise HTTPException(403, "Sin acceso a este viaje")

    return v


@app.patch("/viajes/{viaje_id}", summary="Actualizar estado / posición del viaje")
async def actualizar_viaje(
    viaje_id: str,
    body: ActualizarViajeRequest,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    snap = db.collection("viajes").document(viaje_id).get()
    if not snap.exists:
        raise HTTPException(404, "Viaje no encontrado")

    v = snap.to_dict()
    uid = current_user["uid"]
    rol = current_user["rol"]

    updates = {}

    # Posición GPS del driver
    if body.driver_lat is not None:
        if v.get("driverId") != uid and rol != "admin":
            raise HTTPException(403, "Solo el driver asignado puede actualizar posición")
        updates["driverLat"] = body.driver_lat
        updates["driverLng"] = body.driver_lng

    # Cambio de estado
    if body.estado:
        estado_actual = v.get("estado")

        # Cancelar — cliente o driver asignado o admin
        if body.estado == "cancelado":
            if uid not in (v.get("clienteId"), v.get("driverId")) and rol != "admin":
                raise HTTPException(403, "Sin permiso para cancelar")
            updates["estado"] = "cancelado"
            updates["fechaCancelacion"] = datetime.utcnow().isoformat()
            updates["motivoCancelacion"] = body.motivo_cancelacion or "usuario_cancelo"

        # Finalizar — cliente o driver asignado
        elif body.estado == "finalizado":
            if uid not in (v.get("clienteId"), v.get("driverId")) and rol != "admin":
                raise HTTPException(403, "Sin permiso para finalizar")
            updates["estado"] = "finalizado"
            updates["fechaFin"] = datetime.utcnow().isoformat()

            # Registrar ganancia
            monto = v.get("ofertaActual", 0)
            db.collection("ganancias").add({
                "driverId": v.get("driverId", ""),
                "driverNombre": v.get("driverNombre", ""),
                "clienteNombre": v.get("clienteNombre", ""),
                "monto": float(monto),
                "comision": round(float(monto) * APP_COMMISSION_RATE, 2),
                "fecha": datetime.utcnow().strftime("%d/%m/%Y"),
                "viajeId": viaje_id,
                "timestamp": datetime.utcnow().isoformat(),
            })

            # Mensaje sistema
            db.collection("viajes").document(viaje_id).collection("mensajes").add({
                "uid": "sistema",
                "nombre": "Sistema",
                "msg": f"Viaje finalizado. Monto: ${float(monto):.2f}",
                "timestamp": datetime.utcnow().isoformat(),
            })

        else:
            raise HTTPException(400, f"Estado '{body.estado}' no permitido por este endpoint")

    if not updates:
        raise HTTPException(400, "No se enviaron cambios")

    db.collection("viajes").document(viaje_id).update(updates)
    return {"ok": True, "updates": updates}


# ════════════════════════════════════════════════════════════════════════════
# OFERTAS
# ════════════════════════════════════════════════════════════════════════════

@app.get("/viajes/{viaje_id}/ofertas", summary="Listar ofertas de un viaje")
async def listar_ofertas(
    viaje_id: str,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        return []

    snap = db.collection("viajes").document(viaje_id).get()
    if not snap.exists:
        raise HTTPException(404, "Viaje no encontrado")

    v = snap.to_dict()
    uid = current_user["uid"]
    rol = current_user["rol"]
    if rol not in ("admin",) and v.get("clienteId") != uid and v.get("driverId") != uid and rol != "driver":
        raise HTTPException(403, "Sin acceso")

    docs = (
        db.collection("viajes")
        .document(viaje_id)
        .collection("ofertas")
        .order_by("timestamp")
        .get()
    )
    return [{"id": d.id, **d.to_dict()} for d in docs]


@app.post("/viajes/{viaje_id}/ofertas", summary="Driver envía oferta al cliente")
async def enviar_oferta(
    viaje_id: str,
    body: EnviarOfertaRequest,
    current_user: dict = Depends(require_role("driver")),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    if body.monto <= 0:
        raise HTTPException(400, "El monto debe ser mayor a 0")

    snap = db.collection("viajes").document(viaje_id).get()
    if not snap.exists:
        raise HTTPException(404, "Viaje no encontrado")

    v = snap.to_dict()
    if v.get("estado") not in ("buscando", "contraoferta"):
        raise HTTPException(400, "El viaje ya no acepta ofertas")

    # Verificar límite de 3 ofertas por driver
    ofertas_driver = (
        db.collection("viajes")
        .document(viaje_id)
        .collection("ofertas")
        .where("driverId", "==", current_user["uid"])
        .get()
    )
    if len(ofertas_driver) >= 3:
        raise HTTPException(400, "Máximo 3 ofertas por viaje")

    uid = current_user["uid"]
    drv = current_user

    oferta = {
        "driverId": uid,
        "driverNombre": drv.get("nombre", ""),
        "driverFoto": drv.get("foto_perfil", ""),
        "placa": drv.get("placa", ""),
        "marca": drv.get("marca", ""),
        "modelo": drv.get("modelo", ""),
        "monto": body.monto,
        "estado": "pendiente",
        "timestamp": datetime.utcnow().isoformat(),
    }

    ref = (
        db.collection("viajes")
        .document(viaje_id)
        .collection("ofertas")
        .add(oferta)
    )
    oferta_id = ref[1].id

    # Actualizar estado del viaje a "contraoferta"
    db.collection("viajes").document(viaje_id).update({
        "estado": "contraoferta",
        "ultimaOfertaTs": datetime.utcnow().isoformat(),
    })

    return {"id": oferta_id, **oferta}


@app.patch(
    "/viajes/{viaje_id}/ofertas/{oferta_id}",
    summary="Cliente acepta o rechaza una oferta",
)
async def responder_oferta(
    viaje_id: str,
    oferta_id: str,
    body: ResponderOfertaRequest,
    current_user: dict = Depends(require_role("cliente")),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    snap = db.collection("viajes").document(viaje_id).get()
    if not snap.exists:
        raise HTTPException(404, "Viaje no encontrado")

    v = snap.to_dict()
    if v.get("clienteId") != current_user["uid"]:
        raise HTTPException(403, "Este viaje no es tuyo")

    oferta_snap = (
        db.collection("viajes")
        .document(viaje_id)
        .collection("ofertas")
        .document(oferta_id)
        .get()
    )
    if not oferta_snap.exists:
        raise HTTPException(404, "Oferta no encontrada")

    oferta = oferta_snap.to_dict()

    if body.accion == "aceptar":
        # Aceptar oferta
        db.collection("viajes").document(viaje_id).collection("ofertas").document(
            oferta_id
        ).update({"estado": "aceptada"})

        db.collection("viajes").document(viaje_id).update({
            "estado": "aceptado",
            "ofertaActual": oferta["monto"],
            "driverId": oferta["driverId"],
            "driverNombre": oferta["driverNombre"],
            "driverFoto": oferta["driverFoto"],
            "placa": oferta["placa"],
            "marca": oferta["marca"],
            "modelo": oferta["modelo"],
        })
        return {"ok": True, "mensaje": "Oferta aceptada. Driver asignado."}

    elif body.accion == "rechazar":
        db.collection("viajes").document(viaje_id).collection("ofertas").document(
            oferta_id
        ).update({"estado": "rechazada"})

        db.collection("viajes").document(viaje_id).update({
            "ultimaOfertaRechazadaDriver": oferta["driverId"]
        })
        return {"ok": True, "mensaje": "Oferta rechazada."}

    else:
        raise HTTPException(400, "Acción inválida. Usa 'aceptar' o 'rechazar'")


# ════════════════════════════════════════════════════════════════════════════
# MENSAJES DE CHAT
# ════════════════════════════════════════════════════════════════════════════

@app.get("/viajes/{viaje_id}/mensajes", summary="Historial de chat del viaje")
async def obtener_mensajes(
    viaje_id: str,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        return []

    docs = (
        db.collection("viajes")
        .document(viaje_id)
        .collection("mensajes")
        .order_by("timestamp")
        .get()
    )
    return [{"id": d.id, **d.to_dict()} for d in docs]


@app.post("/viajes/{viaje_id}/mensajes", summary="Enviar mensaje de chat")
async def enviar_mensaje(
    viaje_id: str,
    body: EnviarMensajeRequest,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")

    if not body.msg.strip():
        raise HTTPException(400, "El mensaje no puede estar vacío")

    msg = {
        "uid": current_user["uid"],
        "nombre": current_user["nombre"],
        "foto": current_user.get("foto_perfil", ""),
        "msg": body.msg.strip(),
        "timestamp": datetime.utcnow().isoformat(),
    }
    db.collection("viajes").document(viaje_id).collection("mensajes").add(msg)
    return {"ok": True}


# ════════════════════════════════════════════════════════════════════════════
# MENSAJES PRIVADOS (driver ↔ cliente antes de aceptar)
# ════════════════════════════════════════════════════════════════════════════

@app.get("/viajes/{viaje_id}/chat-privado", summary="Chat privado pre-viaje")
async def chat_privado_get(
    viaje_id: str,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        return []
    docs = (
        db.collection("viajes")
        .document(viaje_id)
        .collection("chatPrivado")
        .order_by("timestamp")
        .get()
    )
    return [{"id": d.id, **d.to_dict()} for d in docs]


@app.post("/viajes/{viaje_id}/chat-privado", summary="Enviar mensaje privado pre-viaje")
async def chat_privado_post(
    viaje_id: str,
    body: EnviarMensajeRequest,
    current_user: dict = Depends(get_current_user),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")
    msg = {
        "uid": current_user["uid"],
        "nombre": current_user["nombre"],
        "msg": body.msg.strip(),
        "timestamp": datetime.utcnow().isoformat(),
    }
    db.collection("viajes").document(viaje_id).collection("chatPrivado").add(msg)
    return {"ok": True}


# ════════════════════════════════════════════════════════════════════════════
# GANANCIAS
# ════════════════════════════════════════════════════════════════════════════

@app.get("/ganancias/me", summary="Ganancias del driver autenticado (últimos 5 días)")
async def mis_ganancias(current_user: dict = Depends(require_role("driver"))):
    if db is None:
        return {"registros": [], "bruto": 0, "comision": 0, "neto": 0}

    docs = (
        db.collection("ganancias")
        .where("driverId", "==", current_user["uid"])
        .order_by("timestamp", direction=firestore.Query.DESCENDING)
        .limit(50)
        .get()
    )

    registros = [{"id": d.id, **d.to_dict()} for d in docs]
    total_bruto = sum(float(r.get("monto", 0)) for r in registros)
    comision = round(total_bruto * APP_COMMISSION_RATE, 2)
    neto = round(total_bruto - comision, 2)

    # Agrupar por día (máx 5 días)
    dias: dict = {}
    for r in registros:
        fecha = r.get("fecha", "Sin fecha")
        dias.setdefault(fecha, 0)
        dias[fecha] += float(r.get("monto", 0))

    dias_lista = [
        {"fecha": f, "monto": round(m, 2), "comision": round(m * APP_COMMISSION_RATE, 2)}
        for f, m in list(dias.items())[:5]
    ]

    return {
        "registros": registros,
        "dias": dias_lista,
        "bruto": round(total_bruto, 2),
        "comision": comision,
        "neto": neto,
        "tasa_comision": APP_COMMISSION_RATE,
    }


# ════════════════════════════════════════════════════════════════════════════
# MENSAJES GENERALES (Admin → Drivers)
# ════════════════════════════════════════════════════════════════════════════

@app.get("/mensajes-generales", summary="Listar mensajes generales")
async def listar_mensajes_generales(current_user: dict = Depends(get_current_user)):
    if db is None:
        return []
    docs = (
        db.collection("mensajesGenerales")
        .order_by("timestamp", direction=firestore.Query.DESCENDING)
        .limit(20)
        .get()
    )
    return [{"id": d.id, **d.to_dict()} for d in docs]


@app.post("/mensajes-generales", summary="Admin envía mensaje global a drivers")
async def enviar_mensaje_general(
    body: MensajeGeneralRequest,
    current_user: dict = Depends(require_role("admin")),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")
    if not body.msg.strip():
        raise HTTPException(400, "El mensaje no puede estar vacío")

    doc = {
        "msg": body.msg.strip(),
        "de": current_user["nombre"],
        "uid": current_user["uid"],
        "timestamp": datetime.utcnow().isoformat(),
    }
    db.collection("mensajesGenerales").add(doc)
    return {"ok": True, "mensaje": "Mensaje enviado a todos los drivers"}


# ════════════════════════════════════════════════════════════════════════════
# ADMINISTRACIÓN
# ════════════════════════════════════════════════════════════════════════════

@app.get("/admin/usuarios", summary="Admin: listar todos los usuarios")
async def admin_listar_usuarios(
    current_user: dict = Depends(require_role("admin"))
):
    if db is None:
        return []
    docs = db.collection("usuarios").get()
    users = []
    for d in docs:
        u = d.to_dict()
        u.pop("password_hash", None)   # No exponer contraseña
        users.append(u)
    return users


@app.patch("/admin/usuarios/{uid}", summary="Admin: activar o desactivar usuario")
async def admin_actualizar_usuario(
    uid: str,
    body: ActualizarUsuarioRequest,
    current_user: dict = Depends(require_role("admin")),
):
    if db is None:
        raise HTTPException(503, "Firebase no disponible")
    if body.estado not in ("activo", "inactivo"):
        raise HTTPException(400, "Estado inválido. Usa 'activo' o 'inactivo'")

    snap = db.collection("usuarios").document(uid).get()
    if not snap.exists:
        raise HTTPException(404, "Usuario no encontrado")

    db.collection("usuarios").document(uid).update({"estado": body.estado})
    return {"ok": True, "uid": uid, "estado": body.estado}


@app.get("/admin/ganancias", summary="Admin: ganancias globales")
async def admin_ganancias(current_user: dict = Depends(require_role("admin"))):
    if db is None:
        return {"registros": [], "bruto": 0, "comision": 0}
    docs = db.collection("ganancias").get()
    registros = [{"id": d.id, **d.to_dict()} for d in docs]
    total = sum(float(r.get("monto", 0)) for r in registros)
    return {
        "registros": registros,
        "bruto": round(total, 2),
        "comision": round(total * APP_COMMISSION_RATE, 2),
    }


# ════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ════════════════════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
async def root():
    return {
        "app": "RUN CAR PRO MAX API",
        "version": "1.0.0",
        "status": "ok",
        "firebase": "conectado" if db is not None else "no conectado (modo mock)",
        "docs": "/docs",
    }


# ════════════════════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA DIRECTO
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("runcar_backend:app", host="0.0.0.0", port=8000, reload=True)
