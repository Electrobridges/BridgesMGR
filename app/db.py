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

# Jerarquía de tres escalones, de más a menos:
#
#   superusuario  el primero que se dio de alta. Manda igual que un admin, pero
#                 además es intocable: nadie puede cambiarle el rol, ni
#                 desactivarlo, ni borrarlo, ni tocarle la contraseña o el
#                 segundo factor. Solo él mismo, y desde el servidor la CLI.
#   admin         muta el servidor y gestiona cuentas, incluidas las de otros
#                 admins. No alcanza al superusuario.
#   supervisor    solo consulta.
ROL_SUPER = "superusuario"
ROL_ADMIN = "admin"
ROL_SUPERVISOR = "supervisor"

ROLES = (ROL_SUPER, ROL_ADMIN, ROL_SUPERVISOR)

# Los que se pueden otorgar. El de superusuario no se concede: lo tiene quien
# creó la instalación, y solo se hereda reconstruyendo la base.
ROLES_ASIGNABLES = (ROL_ADMIN, ROL_SUPERVISOR)

# Los que pueden mutar el servidor. Es la lista que mira auth.solo_admin.
ROLES_MANDO = (ROL_SUPER, ROL_ADMIN)

# Clave del ajuste que decide si las cuentas de rol 'supervisor' están
# obligadas a usar segundo factor. Vive en la base y no en config.yaml a
# propósito: el panel corre como 'ovpnweb' y config.yaml es root:ovpnweb 0640,
# así que no puede escribirlo. Además es una decisión de operación, no de
# despliegue.
AJUSTE_EXIGIR_TOTP_SUPERVISOR = "exigir_totp_supervisor"

# Cómo se llamaban las cosas antes de la jerarquía de tres roles. Solo lo usa
# la migración; el resto del código no debe mirar aquí.
_ROL_VIEJO_LECTOR = "lector"
_AJUSTE_VIEJO_TOTP = "exigir_totp_lector"

# Cuánto dura el permiso a medio autenticar entre la contraseña y el código.
# Corto adrede: es una credencial parcial.
MINUTOS_LOGIN_PENDIENTE = 5

_hasher = PasswordHasher()

# La tabla de usuarios se define aparte del resto del esquema porque la
# migración de roles tiene que reconstruirla entera —SQLite no sabe alterar un
# CHECK— y escribir sus columnas dos veces es justo cómo acaban divergiendo.
# Lleva el nombre de tabla por parámetro para poder crearla con otro nombre
# durante esa reconstrucción.
DDL_USUARIOS = """
CREATE TABLE IF NOT EXISTS %s (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario          TEXT    NOT NULL UNIQUE,
    password_hash    TEXT    NOT NULL,
    rol              TEXT    NOT NULL CHECK (rol IN ('superusuario', 'admin', 'supervisor')),
    activo           INTEGER NOT NULL DEFAULT 1,
    creado           TEXT    NOT NULL,
    totp_secret      TEXT,
    totp_activado    INTEGER NOT NULL DEFAULT 0,
    totp_ultimo_paso INTEGER
);
"""

# Como mucho un superusuario, y lo garantiza la base. El código ya se encarga
# —solo se concede a la primera cuenta y cambiar_rol no lo ofrece—, pero esto
# es lo que sigue siendo cierto si alguien se salta el código.
INDICES_USUARIOS = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_un_super ON %s(rol)
    WHERE rol = 'superusuario';
"""

ESQUEMA = (DDL_USUARIOS % "usuarios") + (INDICES_USUARIOS % "usuarios") + """
CREATE TABLE IF NOT EXISTS ajustes (
    clave TEXT PRIMARY KEY,
    valor TEXT NOT NULL
);

-- Estado intermedio del login en dos pasos: la contraseña ya es correcta pero
-- todavía no hay sesión. Se guarda el SHA-256 del token, igual que en sesiones.
CREATE TABLE IF NOT EXISTS logins_pendientes (
    token_hash TEXT    PRIMARY KEY,
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    creado     TEXT    NOT NULL,
    expira     TEXT    NOT NULL,
    ip         TEXT
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
CREATE INDEX IF NOT EXISTS idx_pendientes_expira ON logins_pendientes(expira);
"""

# Columnas añadidas después de la primera versión. CREATE TABLE IF NOT EXISTS
# no toca una tabla que ya existe, así que las bases ya instaladas hay que
# ampliarlas a mano al arrancar.
COLUMNAS_NUEVAS = {
    "usuarios": [
        ("totp_secret", "TEXT"),
        ("totp_activado", "INTEGER NOT NULL DEFAULT 0"),
        ("totp_ultimo_paso", "INTEGER"),
    ],
}

# Todo lo que se copia tal cual al reconstruir la tabla de usuarios. El rol va
# aparte porque es lo único que se traduce.
COLUMNAS_USUARIOS = (
    "id", "usuario", "password_hash", "activo", "creado",
    "totp_secret", "totp_activado", "totp_ultimo_paso",
)


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


def _migrar(con):
    """
    Añade a las tablas existentes las columnas que se incorporaron después.

    Se hace comprobando qué hay en vez de capturando el error del ALTER: así
    un fallo de verdad no se confunde con "esa columna ya estaba".
    """
    for tabla, columnas in COLUMNAS_NUEVAS.items():
        existentes = {f["name"] for f in con.execute("PRAGMA table_info(%s)" % tabla)}
        for nombre, definicion in columnas:
            if nombre not in existentes:
                con.execute("ALTER TABLE %s ADD COLUMN %s %s" % (tabla, nombre, definicion))


def _hay_que_migrar_roles(con):
    """
    Si la tabla de usuarios sigue siendo la de dos roles.

    Se mira el CHECK que quedó escrito en sqlite_master en vez de los datos:
    una base con solo admins tiene el esquema viejo aunque no haya ni un
    'lector' al que traducir. ('supervisor' no aparece dentro de
    'superusuario', así que la comprobación no se engaña sola.)
    """
    fila = con.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'usuarios'"
    ).fetchone()
    return bool(fila) and ROL_SUPERVISOR not in fila[0]


def _migrar_roles(ruta):
    """
    Lleva una base de dos roles ('admin'/'lector') a la jerarquía de tres.

    Hay que reconstruir la tabla entera: el rol lleva un CHECK y SQLite no sabe
    alterarlo. Se sigue el procedimiento de la documentación —claves foráneas
    fuera, tabla nueva, copia, intercambio, claves foráneas dentro— con una
    conexión propia, porque conexion() las deja siempre activas y renombrar con
    ellas puestas reescribiría las referencias de sesiones y logins_pendientes
    para que apuntaran a la tabla equivocada.

    Dos traducciones, y ninguna más:

      - 'lector' pasa a 'supervisor'. Es el mismo permiso con otro nombre.
      - el admin más antiguo pasa a 'superusuario'. Se elige entre los admins y
        no entre todas las cuentas: si el id 1 fuera un lector, promoverlo
        sería regalarle el mando de la instalación a quien solo miraba. Una
        base sin ningún admin se queda sin superusuario, que es lo correcto —
        no había a quién ascender— y se arregla con
        `app.cli designar-superusuario`, que es también el remedio si el
        ascenso recae en una cuenta que no era la que se quería.

    La auditoría no se toca. Es el registro de lo que pasó, y lo que pasó se
    llamaba 'lector'.
    """
    # isolation_level=None para llevar la transacción a mano: el PRAGMA de
    # claves foráneas se ignora dentro de una, y aquí hace falta fuera.
    con = sqlite3.connect(ruta, timeout=10, isolation_level=None)

    try:
        if not _hay_que_migrar_roles(con):
            return

        con.execute("PRAGMA foreign_keys = OFF")
        try:
            # execute() y no executescript(): este último hace un COMMIT
            # implícito antes de correr y se llevaría por delante el BEGIN.
            con.execute("BEGIN")
            con.execute(DDL_USUARIOS % "usuarios_nuevo")

            columnas = ", ".join(COLUMNAS_USUARIOS)
            con.execute(
                "INSERT INTO usuarios_nuevo (%s, rol)"
                "     SELECT %s, CASE WHEN rol = ? THEN ? ELSE rol END"
                "       FROM usuarios" % (columnas, columnas),
                (_ROL_VIEJO_LECTOR, ROL_SUPERVISOR),
            )
            con.execute(
                "UPDATE usuarios_nuevo SET rol = ?"
                " WHERE id = (SELECT MIN(id) FROM usuarios_nuevo WHERE rol = ?)",
                (ROL_SUPER, ROL_ADMIN),
            )

            con.execute("DROP TABLE usuarios")
            con.execute("ALTER TABLE usuarios_nuevo RENAME TO usuarios")
            con.execute(INDICES_USUARIOS % "usuarios")

            # OR REPLACE por si conviven la clave vieja y la nueva
            con.execute(
                "UPDATE OR REPLACE ajustes SET clave = ? WHERE clave = ?",
                (AJUSTE_EXIGIR_TOTP_SUPERVISOR, _AJUSTE_VIEJO_TOTP),
            )
            con.execute("COMMIT")
        except Exception:
            try:
                con.execute("ROLLBACK")
            except sqlite3.OperationalError:
                # El fallo fue el propio COMMIT: no hay transacción que deshacer
                # y tapar el error original con este no ayudaría a nadie.
                pass
            raise
        finally:
            con.execute("PRAGMA foreign_keys = ON")

        rotas = con.execute("PRAGMA foreign_key_check").fetchall()
        if rotas:
            raise RuntimeError(
                "La migración de roles dejó referencias rotas: %r" % (rotas,)
            )
    finally:
        con.close()


def init_db(ruta):
    """Crea el esquema si no existe, lo migra si hace falta y cierra permisos"""
    directorio = os.path.dirname(os.path.abspath(ruta))
    if directorio:
        os.makedirs(directorio, exist_ok=True)

    nueva = not os.path.exists(ruta)

    with conexion(ruta) as con:
        con.executescript(ESQUEMA)
        _migrar(con)

    # Después de _migrar: la reconstrucción copia las columnas de TOTP, así que
    # tienen que existir ya cuando le toca el turno.
    _migrar_roles(ruta)

    if nueva:
        try:
            os.chmod(ruta, 0o600)
        except OSError:
            pass


# ------------------------------------------------------------------ usuarios

def hash_password(password):
    return _hasher.hash(password)


def crear_usuario(ruta, usuario, password, rol=ROL_SUPERVISOR):
    """
    Da de alta una cuenta. Devuelve (id, rol_concedido).

    El primero que llega manda: si la tabla está vacía, el rol pedido se ignora
    y la cuenta nace superusuario. Es la única forma de serlo, y por eso
    'superusuario' no aparece en ROLES_ASIGNABLES. Quien llame tiene que usar
    el rol devuelto y no el que pidió, o dirá una cosa distinta de la que pasó.
    """
    if rol not in ROLES_ASIGNABLES:
        raise ValueError("Rol no válido: %s" % rol)

    usuario = usuario.strip()
    if not usuario:
        raise ValueError("El nombre de usuario no puede estar vacío")
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")

    with conexion(ruta) as con:
        if con.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
            rol = ROL_SUPER

        try:
            cur = con.execute(
                "INSERT INTO usuarios (usuario, password_hash, rol, activo, creado)"
                " VALUES (?, ?, ?, 1, ?)",
                (usuario, hash_password(password), rol, _iso(_ahora())),
            )
        except sqlite3.IntegrityError as e:
            # El índice parcial de superusuario y el UNIQUE del nombre dan el
            # mismo tipo de error; decir cuál de los dos fue es la diferencia
            # entre un mensaje útil y uno que despista.
            if "usuarios.rol" in str(e):
                raise ValueError("Ya hay un superusuario en esta instalación")
            raise ValueError("El usuario '%s' ya existe" % usuario)

        return cur.lastrowid, rol


def obtener_usuario(ruta, usuario):
    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT * FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()
    return dict(fila) if fila else None


def listar_usuarios(ruta):
    with conexion(ruta) as con:
        filas = con.execute(
            "SELECT id, usuario, rol, activo, creado, totp_activado"
            "  FROM usuarios ORDER BY usuario"
        ).fetchall()
    return [dict(f) for f in filas]


def contar_mando_activo(ruta):
    """
    Cuentas activas que pueden mutar el servidor: superusuario y admins.

    Es lo que impide dejar el panel sin nadie capaz de administrarlo. Cuenta al
    superusuario porque manda igual que un admin; que además sea intocable ya
    lo garantiza por otra vía, pero esta función responde a "¿quién queda?", no
    a "¿quién es imborrable?".
    """
    marcadores = ", ".join("?" * len(ROLES_MANDO))
    with conexion(ruta) as con:
        return con.execute(
            "SELECT COUNT(*) FROM usuarios WHERE rol IN (%s) AND activo = 1" % marcadores,
            ROLES_MANDO,
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
    """
    Cambia el rol de una cuenta.

    Solo admite los roles asignables, así que por aquí no se concede el de
    superusuario ni se le quita: el WHERE lo excluye para que ni siquiera un
    error de más arriba pueda degradarlo.
    """
    if rol not in ROLES_ASIGNABLES:
        raise ValueError("Rol no válido: %s" % rol)

    with conexion(ruta) as con:
        con.execute(
            "UPDATE usuarios SET rol = ? WHERE usuario = ? AND rol != ?",
            (rol, usuario, ROL_SUPER),
        )


def designar_superusuario(ruta, usuario):
    """
    Traslada el rol de superusuario a esa cuenta. Devuelve (id_nuevo, quien_era).

    El panel no llega hasta aquí y no debe: allí el superusuario es fijo. Esta
    es la vía de reparación desde el servidor, la misma frontera que sostiene
    todo lo demás —quien puede ejecutar esto ya tiene más autoridad que
    cualquier rol del panel—, y hace falta porque hay dos situaciones reales
    que si no dejan una instalación sin arreglo: una base migrada que no tenía
    ningún admin al que ascender, y otra en la que el ascenso recayó en una
    cuenta que no era la que se quería.

    El orden no es cosmético: el índice único parcial solo admite un
    superusuario, así que hay que bajar al que había antes de subir al nuevo.
    """
    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT id, rol FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()

        if not fila:
            raise ValueError("No existe el usuario '%s'" % usuario)
        if fila["rol"] == ROL_SUPER:
            raise ValueError("'%s' ya es el superusuario" % usuario)

        anterior = con.execute(
            "SELECT usuario FROM usuarios WHERE rol = ?", (ROL_SUPER,)
        ).fetchone()

        con.execute("UPDATE usuarios SET rol = ? WHERE rol = ?", (ROL_ADMIN, ROL_SUPER))
        con.execute("UPDATE usuarios SET rol = ? WHERE usuario = ?", (ROL_SUPER, usuario))

        return fila["id"], (anterior["usuario"] if anterior else None)


def activar_usuario(ruta, usuario, activo):
    with conexion(ruta) as con:
        con.execute(
            "UPDATE usuarios SET activo = ? WHERE usuario = ?",
            (1 if activo else 0, usuario),
        )


def borrar_usuario(ruta, usuario):
    with conexion(ruta) as con:
        con.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))


# ------------------------------------------------------------ segundo factor

def guardar_secreto_totp(ruta, usuario, secreto):
    """
    Guarda un secreto recién generado, todavía SIN activar.

    El alta no se da por buena hasta que el usuario teclea un código correcto:
    si no, alguien podría quedarse fuera por haber guardado mal el secreto en
    su móvil.
    """
    with conexion(ruta) as con:
        cur = con.execute(
            "UPDATE usuarios SET totp_secret = ?, totp_activado = 0,"
            "       totp_ultimo_paso = NULL"
            " WHERE usuario = ?",
            (secreto, usuario),
        )
        if cur.rowcount == 0:
            raise ValueError("No existe el usuario '%s'" % usuario)


def activar_totp(ruta, usuario, paso):
    """Confirma el alta. 'paso' es el intervalo del código que lo confirmó."""
    with conexion(ruta) as con:
        con.execute(
            "UPDATE usuarios SET totp_activado = 1, totp_ultimo_paso = ?"
            " WHERE usuario = ? AND totp_secret IS NOT NULL",
            (paso, usuario),
        )


def desactivar_totp(ruta, usuario):
    """Borra el secreto además de la marca: un secreto huérfano no pinta nada"""
    with conexion(ruta) as con:
        con.execute(
            "UPDATE usuarios SET totp_secret = NULL, totp_activado = 0,"
            "       totp_ultimo_paso = NULL"
            " WHERE usuario = ?",
            (usuario,),
        )


def registrar_paso_totp(ruta, usuario_id, paso):
    """
    Anota el último paso aceptado para que ese código no valga dos veces.

    La condición del WHERE evita que dos peticiones simultáneas hagan
    retroceder el contador.
    """
    with conexion(ruta) as con:
        con.execute(
            "UPDATE usuarios SET totp_ultimo_paso = ?"
            " WHERE id = ? AND (totp_ultimo_paso IS NULL OR totp_ultimo_paso < ?)",
            (paso, usuario_id, paso),
        )


# ------------------------------------------------------------------- ajustes

def obtener_ajuste(ruta, clave, por_defecto=None):
    with conexion(ruta) as con:
        fila = con.execute("SELECT valor FROM ajustes WHERE clave = ?", (clave,)).fetchone()
    return fila["valor"] if fila else por_defecto


def guardar_ajuste(ruta, clave, valor):
    with conexion(ruta) as con:
        con.execute(
            "INSERT INTO ajustes (clave, valor) VALUES (?, ?)"
            " ON CONFLICT(clave) DO UPDATE SET valor = ?",
            (clave, str(valor), str(valor)),
        )


def exigir_totp_supervisor(ruta):
    """¿Está el segundo factor impuesto a las cuentas de rol 'supervisor'?"""
    return obtener_ajuste(ruta, AJUSTE_EXIGIR_TOTP_SUPERVISOR, "0") == "1"


def totp_obligatorio(ruta, rol):
    """
    Si el segundo factor es exigible para ese rol.

    A quien manda —superusuario y admins— nunca se le impone: lo decide cada
    uno en su perfil. Imponérselo desde el panel permitiría a un admin dejar
    fuera a otro, y quien manda aquí es quien tiene acceso al servidor.
    """
    return rol == ROL_SUPERVISOR and exigir_totp_supervisor(ruta)


# ------------------------------------------------------- login a medio hacer

def crear_login_pendiente(ruta, usuario_id, ip=None):
    """Permiso temporal entre la contraseña correcta y el código. Devuelve el token."""
    token = secrets.token_urlsafe(32)
    ahora = _ahora()

    with conexion(ruta) as con:
        con.execute(
            "INSERT INTO logins_pendientes (token_hash, usuario_id, creado, expira, ip)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                _hash_token(token),
                usuario_id,
                _iso(ahora),
                _iso(ahora + timedelta(minutes=MINUTOS_LOGIN_PENDIENTE)),
                ip,
            ),
        )

    return token


def obtener_login_pendiente(ruta, token):
    """Devuelve el usuario a medio autenticar, o None si no vale o caducó"""
    if not token:
        return None

    with conexion(ruta) as con:
        fila = con.execute(
            "SELECT p.expira, u.*"
            "  FROM logins_pendientes p JOIN usuarios u ON u.id = p.usuario_id"
            " WHERE p.token_hash = ?",
            (_hash_token(token),),
        ).fetchone()

    if not fila:
        return None

    if datetime.fromisoformat(fila["expira"]) <= _ahora() or not fila["activo"]:
        borrar_login_pendiente(ruta, token)
        return None

    return dict(fila)


def borrar_login_pendiente(ruta, token):
    with conexion(ruta) as con:
        con.execute(
            "DELETE FROM logins_pendientes WHERE token_hash = ?", (_hash_token(token),)
        )


def purgar_logins_pendientes(ruta):
    with conexion(ruta) as con:
        con.execute("DELETE FROM logins_pendientes WHERE expira <= ?", (_iso(_ahora()),))


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
            "       u.usuario, u.rol, u.activo, u.totp_activado"
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
