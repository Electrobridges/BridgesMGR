"""
Autenticación por sesión, roles y protección CSRF.

Modelo: cookie httpOnly + SameSite=Strict con un token opaco cuyo SHA-256 vive
en la base. Los roles son 'admin' (puede mutar el servidor) y 'lector' (solo
consulta). Cualquier endpoint que cambie algo debe depender de solo_admin.

CSRF: las mutaciones se hacen con HTMX y exigen la cabecera X-CSRF-Token, que
la plantilla base inyecta en todas las peticiones. Una petición cross-site no
puede fijar cabeceras propias, así que la cabecera basta; la cookie SameSite
es la segunda barrera.
"""

from fastapi import Depends, Request

from . import db

COOKIE_NOMBRE = "ovpnweb_sesion"
CABECERA_CSRF = "X-CSRF-Token"

MUTANTES = {"POST", "PUT", "PATCH", "DELETE"}


class NoAutenticado(Exception):
    """No hay sesión válida: hay que mandar al login"""


class SinPermiso(Exception):
    """Hay sesión pero el rol no alcanza"""

    def __init__(self, mensaje="Tu rol no permite esta acción"):
        self.mensaje = mensaje
        super().__init__(mensaje)


class CSRFInvalido(Exception):
    """Falta la cabecera CSRF o no coincide con la sesión"""


def ip_cliente(request):
    return request.client.host if request.client else None


def _cfg(request):
    return request.app.state.cfg


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


def usuario_actual(request: Request):
    """Dependencia para rutas que exigen sesión iniciada"""
    sesion = sesion_opcional(request)
    if not sesion:
        raise NoAutenticado()

    request.state.sesion = sesion
    return sesion


def solo_admin(sesion=Depends(usuario_actual)):
    """Dependencia para rutas que modifican el servidor"""
    if sesion["rol"] != "admin":
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
    if not enviado or enviado != sesion["csrf"]:
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


def comprobar_bloqueo(request, usuario):
    """
    Segundos de bloqueo pendientes para este intento de login.

    Se cuenta por usuario+IP: así un atacante desde otra IP no puede dejar
    fuera al administrador legítimo simplemente fallando adrede.
    """
    cfg = _cfg(request)
    clave = "%s|%s" % (usuario, ip_cliente(request))
    return clave, db.esta_bloqueado(cfg.seguridad.db_path, clave)
