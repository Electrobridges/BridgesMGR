"""
Cambio de idioma de la interfaz, y el middleware que lo aplica a cada petición.

El idioma elegido va en una cookie, no en la cuenta: también hace falta en la
página de entrada, donde todavía no hay cuenta. No es un secreto ni da acceso a
nada, así que la ruta que lo cambia es un GET sin sesión ni token CSRF: lo peor
que puede hacer una web ajena es cambiarte el idioma.

Orden para decidir el idioma de una petición:
1. la cookie 'idioma', si alguien lo eligió;
2. la cabecera Accept-Language del navegador;
3. servidor.idioma de config.yaml.
"""

from http.cookies import SimpleCookie

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import idiomas
from .comun import cfg

router = APIRouter()

COOKIE = "idioma"
UN_ANO = 365 * 24 * 3600


def _cabecera(scope, nombre):
    for clave, valor in scope.get("headers") or ():
        if clave == nombre:
            return valor.decode("latin-1")
    return ""


def del_navegador(accept_language):
    """El primero de Accept-Language que conocemos, respetando los q=."""
    candidatos = []
    for i, parte in enumerate(accept_language.split(",")):
        trozos = parte.strip().split(";")
        calidad = 1.0
        for extra in trozos[1:]:
            if extra.strip().startswith("q="):
                try:
                    calidad = float(extra.strip()[2:])
                except ValueError:
                    calidad = 0.0
        codigo = idiomas.normalizar(trozos[0])
        if codigo and calidad > 0:
            candidatos.append((-calidad, i, codigo))
    return min(candidatos)[2] if candidatos else None


def idioma_de(scope):
    galleta = SimpleCookie()
    try:
        galleta.load(_cabecera(scope, b"cookie"))
    except Exception:  # una cookie mal formada no puede tumbar la petición
        galleta = SimpleCookie()
    if COOKIE in galleta:
        elegido = idiomas.normalizar(galleta[COOKIE].value)
        if elegido:
            return elegido
    return del_navegador(_cabecera(scope, b"accept-language")) or idiomas.por_defecto()


class MiddlewareIdioma:
    """
    ASGI puro y no @app.middleware("http"): con BaseHTTPMiddleware el endpoint
    corre en otra tarea, y aunque hoy herede el contexto, que el idioma de una
    petición no se filtre a otra no debe depender de ese detalle.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        token = idiomas.fijar(idioma_de(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            idiomas.restaurar(token)


def _destino_seguro(volver):
    """Solo rutas locales: '/clientes' sí; '//otra.web', 'https://…' o '/\\x' no."""
    if not volver or not volver.startswith("/") or volver.startswith(("//", "/\\")):
        return "/"
    if any(c in volver for c in "\r\n"):
        return "/"
    return volver


@router.get("/idioma/{codigo}")
def cambiar_idioma(request: Request, codigo: str, volver: str = "/"):
    respuesta = RedirectResponse(_destino_seguro(volver), status_code=303)
    elegido = idiomas.normalizar(codigo)
    if elegido:
        respuesta.set_cookie(
            COOKIE, elegido, max_age=UN_ANO, httponly=True, samesite="lax",
            secure=cfg(request).seguridad.cookie_segura,
        )
    return respuesta
