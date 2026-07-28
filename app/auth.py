"""
Autenticación por sesión, roles y protección CSRF.

Modelo: cookie httpOnly + SameSite=Strict con un token opaco cuyo SHA-256 vive
en la base. Los roles van en jerarquía —'superusuario' y 'admin' pueden mutar
el servidor, 'supervisor' solo consulta— y quien la define es db.ROLES_MANDO.
Cualquier endpoint que cambie algo debe depender de solo_admin.

Cuidado con la diferencia: solo_admin responde "¿puede tocar el servidor?".
Quién puede tocar a QUIÉN es otra cosa, vive en routers/administracion.py y no
se resuelve con una dependencia porque depende de la cuenta de destino.

CSRF: las mutaciones se hacen con HTMX y exigen la cabecera X-CSRF-Token, que
la plantilla base inyecta en todas las peticiones. Una petición cross-site no
puede fijar cabeceras propias, así que la cabecera basta; la cookie SameSite
es la segunda barrera.
"""

import hmac

from fastapi import Depends, Request

from . import db

COOKIE_NOMBRE = "ovpnweb_sesion"
COOKIE_PENDIENTE = "ovpnweb_2fa"
CABECERA_CSRF = "X-CSRF-Token"

MUTANTES = {"POST", "PUT", "PATCH", "DELETE"}

# Lo único que puede tocar quien tiene el segundo factor pendiente de alta:
# darlo de alta, o marcharse.
RUTAS_SIN_TOTP = ("/perfil", "/logout")


class NoAutenticado(Exception):
    """No hay sesión válida: hay que mandar al login"""


class SinPermiso(Exception):
    """Hay sesión pero el rol no alcanza"""

    def __init__(self, mensaje="Tu rol no permite esta acción"):
        self.mensaje = mensaje
        super().__init__(mensaje)


class CSRFInvalido(Exception):
    """Falta la cabecera CSRF o no coincide con la sesión"""


class RequiereAltaTOTP(Exception):
    """
    La política obliga a esta cuenta a tener segundo factor y todavía no lo ha
    dado de alta. Hay sesión, pero solo sirve para ir al perfil y activarlo.
    """


def ip_cliente(request):
    return request.client.host if request.client else None


def _cfg(request):
    return request.app.state.cfg


def cfg_db(request):
    return _cfg(request).seguridad.db_path


def sesion_opcional(request: Request):
    """Devuelve la sesión si la cookie es válida, si no None"""
    token = request.cookies.get(COOKIE_NOMBRE)
    if not token:
        return None

    cfg = _cfg(request)
    sesion = db.obtener_sesion(cfg.seguridad.db_path, token)

    if sesion:
        # Sesión deslizante: cada actividad renueva la ventana
        db.renovar_sesion(cfg.seguridad.db_path, token, cfg.seguridad.duracion_sesion_min)

    return sesion


def debe_dar_de_alta_totp(request, sesion):
    """
    La política exige segundo factor a este rol y la cuenta aún no lo tiene.

    Se consulta en cada petición y no al iniciar sesión: si un admin activa la
    política, las sesiones abiertas quedan restringidas al momento, sin
    esperar a que caduquen.
    """
    return (db.totp_obligatorio(cfg_db(request), sesion["rol"])
            and not sesion["totp_activado"])


def usuario_actual(request: Request):
    """Dependencia para rutas que exigen sesión iniciada"""
    sesion = sesion_opcional(request)
    if not sesion:
        raise NoAutenticado()

    request.state.sesion = sesion

    if debe_dar_de_alta_totp(request, sesion) and not _ruta_exenta(request):
        raise RequiereAltaTOTP()

    return sesion


def _ruta_exenta(request):
    """Rutas que siguen abiertas mientras el segundo factor está pendiente"""
    return request.url.path.startswith(RUTAS_SIN_TOTP)


def solo_admin(sesion=Depends(usuario_actual)):
    """Dependencia para rutas que modifican el servidor"""
    if sesion["rol"] not in db.ROLES_MANDO:
        raise SinPermiso()
    return sesion


def verificar_csrf(request: Request, sesion=Depends(usuario_actual)):
    """
    Comprueba la cabecera CSRF en peticiones que mutan estado.

    Se declara como dependencia aparte para que quede explícito en cada ruta
    que la protege, en vez de esconderlo en un middleware global.
    """
    if request.method not in MUTANTES:
        return sesion

    enviado = request.headers.get(CABECERA_CSRF)
    # compare_digest y no ==: el tiempo de comparación no debe depender de
    # cuántos caracteres se han acertado. Sobre la red es difícil de explotar,
    # pero es un secreto y se compara como tal, igual que en core/totp.py.
    if not enviado or not hmac.compare_digest(enviado, sesion["csrf"]):
        raise CSRFInvalido()

    return sesion


def iniciar_sesion(request, response, usuario):
    """Crea la sesión y planta la cookie. Devuelve el token CSRF."""
    cfg = _cfg(request)
    token, csrf = db.crear_sesion(
        cfg.seguridad.db_path,
        usuario["id"],
        cfg.seguridad.duracion_sesion_min,
        ip_cliente(request),
    )

    response.set_cookie(
        COOKIE_NOMBRE,
        token,
        max_age=cfg.seguridad.duracion_sesion_min * 60,
        httponly=True,
        secure=cfg.seguridad.cookie_segura,
        samesite="strict",
        path="/",
    )

    return csrf


def cerrar_sesion(request, response):
    cfg = _cfg(request)
    token = request.cookies.get(COOKIE_NOMBRE)

    if token:
        db.borrar_sesion(cfg.seguridad.db_path, token)

    response.delete_cookie(COOKIE_NOMBRE, path="/")


# ------------------------------------------------- login a medio autenticar

def iniciar_pendiente(request, response, usuario):
    """
    Planta la cookie del login a medio hacer: contraseña correcta, código no.

    Es una credencial parcial, así que dura poco y se borra en cuanto se usa.
    No lleva token CSRF porque no da acceso a nada: solo permite presentar un
    código en el formulario del segundo paso.
    """
    token = db.crear_login_pendiente(cfg_db(request), usuario["id"], ip_cliente(request))

    response.set_cookie(
        COOKIE_PENDIENTE,
        token,
        max_age=db.MINUTOS_LOGIN_PENDIENTE * 60,
        httponly=True,
        secure=_cfg(request).seguridad.cookie_segura,
        samesite="strict",
        path="/",
    )
    return token


def pendiente_actual(request):
    """Usuario que ya pasó la contraseña y le falta el código, o None"""
    return db.obtener_login_pendiente(
        cfg_db(request), request.cookies.get(COOKIE_PENDIENTE)
    )


def cerrar_pendiente(request, response):
    token = request.cookies.get(COOKIE_PENDIENTE)
    if token:
        db.borrar_login_pendiente(cfg_db(request), token)
    response.delete_cookie(COOKIE_PENDIENTE, path="/")


def comprobar_bloqueo(request, usuario):
    """
    Segundos de bloqueo pendientes para este intento de login.

    Se cuenta por usuario+IP: así un atacante desde otra IP no puede dejar
    fuera al administrador legítimo simplemente fallando adrede.
    """
    cfg = _cfg(request)
    clave = "%s|%s" % (usuario, ip_cliente(request))
    return clave, db.esta_bloqueado(cfg.seguridad.db_path, clave)
