"""Utilidades compartidas por los routers"""

from fastapi.responses import HTMLResponse

from .. import db
from ..auth import ip_cliente, sesion_opcional


def plantillas(request):
    return request.app.state.plantillas


def cfg(request):
    return request.app.state.cfg


def render(request, plantilla, contexto=None, **kwargs):
    """
    Renderiza añadiendo siempre la sesión actual al contexto.

    Además inyecta 'manda': si esta sesión puede mutar el servidor. Es la misma
    pregunta que responde auth.solo_admin y sale de la misma lista, db.ROLES_MANDO.

    Ninguna plantilla debe comparar `sesion.rol` con una cadena. Se hacía, y al
    añadir el rol de superusuario cuatro sitios se quedaron mirando por 'admin':
    la cuenta con más poder del panel perdió el menú de Usuarios, el formulario
    de crear clientes y los botones de la tabla. Un rol nuevo no puede obligar a
    recordar cuatro plantillas; hay una prueba que lo impide.

    Firma moderna de Starlette: TemplateResponse(request, nombre, contexto).
    La antigua (nombre, contexto) ya no funciona: interpreta el nombre como
    request y revienta al buscar la plantilla.
    """
    sesion = getattr(request.state, "sesion", None) or sesion_opcional(request)

    ctx = {
        "sesion": sesion,
        "manda": bool(sesion and sesion["rol"] in db.ROLES_MANDO),
    }
    ctx.update(contexto or {})
    return plantillas(request).TemplateResponse(request, plantilla, ctx, **kwargs)


def aviso(request, mensaje, tipo="ok", refrescar=None, status_code=200):
    """
    Devuelve el fragmento de aviso que HTMX inserta en la barra de mensajes.

    Si se pasa 'refrescar', se emite la cabecera HX-Trigger con ese evento
    para que las listas afectadas se recarguen solas.
    """
    respuesta = render(
        request,
        "partials/aviso.html",
        {"tipo": tipo, "mensaje": mensaje},
        status_code=status_code,
    )
    if refrescar:
        respuesta.headers["HX-Trigger"] = refrescar
    return respuesta


def error_htmx(request, mensaje, refrescar=None):
    return aviso(request, mensaje, tipo="error", refrescar=refrescar, status_code=400)


def auditar(request, sesion, accion, objetivo=None, resultado="ok", detalle=None):
    from .. import db
    db.registrar(
        cfg(request).seguridad.db_path,
        usuario=sesion["usuario"] if sesion else None,
        accion=accion,
        objetivo=objetivo,
        resultado=resultado,
        detalle=detalle,
        ip=ip_cliente(request),
    )


def vacio(status_code=200):
    return HTMLResponse("", status_code=status_code)
