"""
Almacén SQLite: usuarios del panel, sesiones, intentos de login y auditoría.

Se abre una conexión por operación en vez de compartir una global: los
endpoints son síncronos y FastAPI los ejecuta en un pool de hilos, y sqlite3
no permite reusar una conexión entre hilos.

Nota sobre los tokens de sesión: en la base se guarda solo su SHA-256. Si
alguien se lleva el .db no obtiene sesiones válidas, igual que con las
contraseñas.
"""

import hashlib
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

ROLES = ("admin", "lector")

_hasher = PasswordHasher()

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario       TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    rol           TEXT    NOT NULL CHECK (rol IN ('admin', 'lector')),
    activo        INTEGER NOT NULL DEFAULT 1,
    creado        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sesiones (
    token_hash TEXT    PRIMARY KEY,
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    csrf       TEXT    NOT NULL,
    creada     TEXT    NOT NULL,
    expira     TEXT    NOT NULL,
    ip         TEXT
);

CREATE TABLE IF NOT EXISTS intentos (
    clave           TEXT PRIMARY KEY,
    fallos          INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta TEXT
);

CREATE TABLE IF NOT EXISTS auditoria (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    usuario   TEXT,
    accion    TEXT NOT NULL,
    objetivo  TEXT,
    resultado TEXT NOT NULL,
    detalle   TEXT,
    ip        TEXT
);

CREATE INDEX IF NOT EXISTS idx_auditoria_ts ON auditoria(ts DESC);
CREATE INDEX IF NOT EXISTS idx_sesiones_expira ON sesiones(expira);
"""


def _ahora():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def conexion(ruta):
    """Conexión con claves foráneas activas y commit/rollback automático"""
    con = sqlite3.connect(ruta, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")

    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db(ruta):
    """Crea el esquema si no existe y asegura permisos restrictivos"""
    directorio = os.path.dirname(os.path.abspath(ruta))
    if directorio:
        os.makedirs(directorio, exist_ok=True)

    nueva = not os.path.exists(ruta)

    with conexion(ruta) as con:
        con.executescript(ESQUEMA)

    if nueva:
        try:
            os.chmod(ruta, 0o600)
        except OSError:
            pass


# ------------------------------------------------------------------ usuarios

def hash_password(password):
    return _hasher.hash(password)


def crear_usuario(ruta, usuario, password, rol="lector"):
    if rol not in ROLES:
        raise ValueError("Rol no válido: %s" % rol)

    usuario = usuario.strip()
    if not usuario:
        raise ValueError("El nombre de usuario no puede estar vacío")
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")

    with conexion(ruta) as con:
        try:
            cur = con.execute(
                "INSERT INTO usuarios (usuario, password_hash, rol, activo, creado)"
                " VALUES (?, ?, ?, 1, ?)",
                (usuario, hash_password(password), rol, _iso(_ahora())),
            )
        except sqlite3.IntegrityError:
            raise ValueError("El usuario '%s' ya existe" % usuario)

        return cur.lastrowid


def obtener_usuario(ruta, usuario):
    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT * FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()
    return dict(fila) if fila else None


def listar_usuarios(ruta):
    with conexion(ruta) as con:
        filas = con.execute(
            "SELECT id, usuario, rol, activo, creado FROM usuarios ORDER BY usuario"
        ).fetchall()
    return [dict(f) for f in filas]


def contar_admins_activos(ruta):
    with conexion(ruta) as con:
        return con.execute(
            "SELECT COUNT(*) FROM usuarios WHERE rol = 'admin' AND activo = 1"
        ).fetchone()[0]


def verificar_password(ruta, usuario, password):
    """
    Devuelve el usuario si las credenciales son correctas, si no None.

    Se calcula el hash incluso cuando el usuario no existe, para que el
    tiempo de respuesta no revele qué nombres están dados de alta.
    """
    registro = obtener_usuario(ruta, usuario)
    almacenado = registro["password_hash"] if registro else _hasher.hash("inexistente")

    try:
        _hasher.verify(almacenado, password)
    except (VerifyMismatchError, InvalidHashError):
        return None

    if not registro or not registro["activo"]:
        return None

    if _hasher.check_needs_rehash(almacenado):
        cambiar_password(ruta, registro["usuario"], password)

    return registro


def cambiar_password(ruta, usuario, password):
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")

    with conexion(ruta) as con:
        cur = con.execute(
            "UPDATE usuarios SET password_hash = ? WHERE usuario = ?",
            (hash_password(password), usuario),
        )
        if cur.rowcount == 0:
            raise ValueError("No existe el usuario '%s'" % usuario)


def cambiar_rol(ruta, usuario, rol):
    if rol not in ROLES:
        raise ValueError("Rol no válido: %s" % rol)

    with conexion(ruta) as con:
        con.execute("UPDATE usuarios SET rol = ? WHERE usuario = ?", (rol, usuario))


def activar_usuario(ruta, usuario, activo):
    with conexion(ruta) as con:
        con.execute(
            "UPDATE usuarios SET activo = ? WHERE usuario = ?",
            (1 if activo else 0, usuario),
        )


def borrar_usuario(ruta, usuario):
    with conexion(ruta) as con:
        con.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))


# ------------------------------------------------------------------ sesiones

def crear_sesion(ruta, usuario_id, duracion_min, ip=None):
    """Devuelve (token, csrf). El token solo existe aquí y en la cookie."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    ahora = _ahora()

    with conexion(ruta) as con:
        con.execute(
            "INSERT INTO sesiones (token_hash, usuario_id, csrf, creada, expira, ip)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                _hash_token(token),
                usuario_id,
                csrf,
                _iso(ahora),
                _iso(ahora + timedelta(minutes=duracion_min)),
                ip,
            ),
        )

    return token, csrf


def obtener_sesion(ruta, token):
    """Devuelve la sesión con los datos del usuario, o None si no vale"""
    if not token:
        return None

    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT s.token_hash, s.csrf, s.expira, u.id AS usuario_id,"
            "       u.usuario, u.rol, u.activo"
            "  FROM sesiones s JOIN usuarios u ON u.id = s.usuario_id"
            " WHERE s.token_hash = ?",
            (_hash_token(token),),
        ).fetchone()

    if not fila:
        return None

    if datetime.fromisoformat(fila["expira"]) <= _ahora():
        borrar_sesion(ruta, token)
        return None

    if not fila["activo"]:
        borrar_sesion(ruta, token)
        return None

    return dict(fila)


def renovar_sesion(ruta, token, duracion_min):
    with conexion(ruta) as con:
        con.execute(
            "UPDATE sesiones SET expira = ? WHERE token_hash = ?",
            (_iso(_ahora() + timedelta(minutes=duracion_min)), _hash_token(token)),
        )


def borrar_sesion(ruta, token):
    with conexion(ruta) as con:
        con.execute("DELETE FROM sesiones WHERE token_hash = ?", (_hash_token(token),))


def borrar_sesiones_de(ruta, usuario_id):
    """Cierra todas las sesiones de un usuario (al desactivarlo o cambiar rol)"""
    with conexion(ruta) as con:
        con.execute("DELETE FROM sesiones WHERE usuario_id = ?", (usuario_id,))


def purgar_sesiones(ruta):
    with conexion(ruta) as con:
        con.execute("DELETE FROM sesiones WHERE expira <= ?", (_iso(_ahora()),))


# ------------------------------------------------------- intentos de acceso

def esta_bloqueado(ruta, clave):
    """Segundos que quedan de bloqueo para esa clave (usuario|ip), 0 si ninguno"""
    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT bloqueado_hasta FROM intentos WHERE clave = ?", (clave,)
        ).fetchone()

    if not fila or not fila["bloqueado_hasta"]:
        return 0

    restante = (datetime.fromisoformat(fila["bloqueado_hasta"]) - _ahora()).total_seconds()
    return int(restante) if restante > 0 else 0


def registrar_fallo(ruta, clave, maximo, bloqueo_min):
    """Suma un fallo y bloquea la clave si se alcanza el máximo"""
    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT fallos FROM intentos WHERE clave = ?", (clave,)
        ).fetchone()

        fallos = (fila["fallos"] if fila else 0) + 1
        bloqueo = _iso(_ahora() + timedelta(minutes=bloqueo_min)) if fallos >= maximo else None

        con.execute(
            "INSERT INTO intentos (clave, fallos, bloqueado_hasta) VALUES (?, ?, ?)"
            " ON CONFLICT(clave) DO UPDATE SET fallos = ?, bloqueado_hasta = ?",
            (clave, fallos, bloqueo, fallos, bloqueo),
        )

    return fallos


def limpiar_intentos(ruta, clave):
    with conexion(ruta) as con:
        con.execute("DELETE FROM intentos WHERE clave = ?", (clave,))


# ----------------------------------------------------------------- auditoría

def registrar(ruta, usuario, accion, objetivo=None, resultado="ok", detalle=None, ip=None):
    """Deja constancia de una acción. Toda mutación del servidor pasa por aquí."""
    with conexion(ruta) as con:
        con.execute(
            "INSERT INTO auditoria (ts, usuario, accion, objetivo, resultado, detalle, ip)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_iso(_ahora()), usuario, accion, objetivo, resultado, detalle, ip),
        )


def listar_auditoria(ruta, limite=200):
    with conexion(ruta) as con:
        filas = con.execute(
            "SELECT * FROM auditoria ORDER BY id DESC LIMIT ?", (int(limite),)
        ).fetchall()
    return [dict(f) for f in filas]
