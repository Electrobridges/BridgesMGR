"""
Aplicación FastAPI del panel.

Los endpoints se declaran síncronos (def, no async def) a propósito: casi todo
lo que hacen es E/S bloqueante (sqlite, sockets, subprocess al helper) y
FastAPI los ejecuta en un pool de hilos, en vez de congelar el bucle de
eventos.
"""

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db
from .auth import CSRFInvalido, NoAutenticado, SinPermiso, sesion_opcional
from .config import cargar_config
from .core.parsers import format_bytes
from .routers import administracion, clientes, panel, sesion

BASE = os.path.dirname(os.path.abspath(__file__))


def _es_htmx(request):
    return request.headers.get("HX-Request") == "true"


def crear_app(cfg=None):
    cfg = cfg or cargar_config()

    app = FastAPI(
        title="OpenVPN Manager Web",
        docs_url=None,       # no exponemos OpenAPI en un panel de administración
        redoc_url=None,
        openapi_url=None,
    )

    app.state.cfg = cfg
    db.init_db(cfg.seguridad.db_path)
    db.purgar_sesiones(cfg.seguridad.db_path)

    plantillas = Jinja2Templates(directory=os.path.join(BASE, "templates"))
    plantillas.env.globals["format_bytes"] = format_bytes
    app.state.plantillas = plantillas

    app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")

    # ------------------------------------------------------------ cabeceras
    @app.middleware("http")
    async def cabeceras_seguridad(request: Request, call_next):
        respuesta = await call_next(request)
        # Todo es local y sin CDNs: la CSP puede ser estricta de verdad
        respuesta.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'none'"
        )
        respuesta.headers["X-Content-Type-Options"] = "nosniff"
        respuesta.headers["X-Frame-Options"] = "DENY"
        respuesta.headers["Referrer-Policy"] = "same-origin"
        respuesta.headers["Cache-Control"] = "no-store"
        return respuesta

    # ------------------------------------------------------------ errores
    @app.exception_handler(NoAutenticado)
    def _no_autenticado(request: Request, exc):
        if _es_htmx(request):
            # Que HTMX no inyecte la página de login dentro de un fragmento
            respuesta = HTMLResponse("", status_code=401)
            respuesta.headers["HX-Redirect"] = "/login"
            return respuesta
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(SinPermiso)
    def _sin_permiso(request: Request, exc):
        if _es_htmx(request):
            return plantillas.TemplateResponse(
                request,
                "partials/aviso.html",
                {"tipo": "error", "mensaje": exc.mensaje},
                status_code=403,
            )
        return plantillas.TemplateResponse(
            request,
            "error.html",
            {"codigo": 403, "mensaje": exc.mensaje, "sesion": sesion_opcional(request)},
            status_code=403,
        )

    @app.exception_handler(CSRFInvalido)
    def _csrf(request: Request, exc):
        return plantillas.TemplateResponse(
            request,
            "partials/aviso.html",
            {"tipo": "error",
             "mensaje": "Token CSRF no válido. Recarga la página e inténtalo de nuevo."},
            status_code=403,
        )

    app.include_router(sesion.router)
    app.include_router(panel.router)
    app.include_router(clientes.router)
    app.include_router(administracion.router)

    return app


# No se construye ninguna app al importar el módulo: uvicorn arranca con
#     uvicorn --factory app.main:crear_app
# y los tests llaman a crear_app(cfg) con su propia configuración temporal.
